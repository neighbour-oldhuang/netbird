package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/dns"
)

var errHarmonyInterfacesNotReady = errors.New("HarmonyOS interface snapshot is not ready")

type harmonyInterfaceInput struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	Up           bool     `json:"up"`
	Broadcast    bool     `json:"broadcast"`
	Loopback     bool     `json:"loopback"`
	PointToPoint bool     `json:"pointToPoint"`
	Multicast    bool     `json:"multicast"`
	Addresses    []string `json:"addresses"`
}

type harmonyInterfaceSet struct {
	Interfaces []harmonyInterfaceInput `json:"interfaces"`
}

type harmonyPlatformSnapshot struct {
	Revision                      uint64   `json:"revision"`
	InterfaceRevision             uint64   `json:"interfaceRevision"`
	PreparationGeneration         uint64   `json:"preparationGeneration"`
	PreparationState              string   `json:"preparationState"`
	ConfigRevision                uint64   `json:"configRevision"`
	AppliedConfigRevision         uint64   `json:"appliedConfigRevision"`
	ReconfigurationGeneration     uint64   `json:"reconfigurationGeneration"`
	ReconfigurationState          string   `json:"reconfigurationState"`
	ReconfigurationTargetRevision uint64   `json:"reconfigurationTargetRevision"`
	InterfacesReady               bool     `json:"interfacesReady"`
	ConfigReady                   bool     `json:"configReady"`
	Addresses                     []string `json:"addresses"`
	Routes                        []string `json:"routes"`
	DNSAddresses                  []string `json:"dnsAddresses"`
	SearchDomains                 []string `json:"searchDomains"`
	MTU                           int      `json:"mtu"`
}

type harmonyPlatformAdapter struct {
	mu sync.RWMutex

	interfaceRevision uint64
	interfacesReady   bool
	interfacesText    string

	revision         uint64
	configRevision   uint64
	configChangedAt  time.Time
	interfaceIPv4    string
	interfaceIPv6    string
	baseRouteIPv4    string
	baseRouteIPv6    string
	routes           []string
	preDNSAddress    string
	dnsAddresses     []string
	searchDomains    []string
	mtu              int
	preparationState string
	preparationGen   uint64
	fdWait           chan harmonyTunFDResult

	providedConfigRevision uint64
	consumedConfigRevision uint64
	activeFDLease          uint64
	releaseFDLease         uint64
	oldFDReleased          bool

	reconfigurationDebounce time.Duration
	reconfigurationGen      uint64
	reconfigurationState    string
	reconfigurationTarget   uint64
}

type harmonyTunFDResult struct {
	fd    int
	lease uint64
	err   error
}

const defaultHarmonyReconfigurationDebounce = 250 * time.Millisecond

func newHarmonyPlatformAdapter() *harmonyPlatformAdapter {
	return &harmonyPlatformAdapter{
		preparationState:        "idle",
		reconfigurationState:    "idle",
		reconfigurationDebounce: defaultHarmonyReconfigurationDebounce,
	}
}

func (a *harmonyPlatformAdapter) IFaces() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.interfacesReady || strings.TrimSpace(a.interfacesText) == "" {
		return "", errHarmonyInterfacesNotReady
	}
	return a.interfacesText, nil
}

func (a *harmonyPlatformAdapter) setInterfacesJSON(raw string) error {
	var input harmonyInterfaceSet
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return fmt.Errorf("decode HarmonyOS interfaces: %w", err)
	}
	if len(input.Interfaces) == 0 {
		return errors.New("HarmonyOS interface list is empty")
	}

	interfaces := slices.Clone(input.Interfaces)
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})
	seenNames := make(map[string]struct{}, len(interfaces))
	lines := make([]string, 0, len(interfaces))
	for i := range interfaces {
		iface := &interfaces[i]
		iface.Name = strings.TrimSpace(iface.Name)
		if iface.Name == "" || strings.ContainsAny(iface.Name, "|\r\n\t ") {
			return fmt.Errorf("invalid HarmonyOS interface name %q", iface.Name)
		}
		if _, exists := seenNames[iface.Name]; exists {
			return fmt.Errorf("duplicate HarmonyOS interface %q", iface.Name)
		}
		seenNames[iface.Name] = struct{}{}
		if iface.Index <= 0 {
			iface.Index = i + 1
		}
		if iface.MTU <= 0 {
			return fmt.Errorf("invalid MTU for HarmonyOS interface %q: %d", iface.Name, iface.MTU)
		}
		addresses, err := normalizePrefixes(iface.Addresses)
		if err != nil {
			return fmt.Errorf("interface %s: %w", iface.Name, err)
		}
		if len(addresses) == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %d %d %t %t %t %t %t|%s",
			iface.Name, iface.Index, iface.MTU, iface.Up, iface.Broadcast,
			iface.Loopback, iface.PointToPoint, iface.Multicast,
			strings.Join(addresses, " ")))
	}
	if len(lines) == 0 {
		return errors.New("HarmonyOS interface list has no usable addresses")
	}
	text := strings.Join(lines, "\n")

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.interfacesReady && a.interfacesText == text {
		return nil
	}
	a.interfacesText = text
	a.interfacesReady = true
	a.interfaceRevision++
	return nil
}

func (a *harmonyPlatformAdapter) OnNetworkChanged(routes string) {
	var raw []string
	for _, route := range strings.Split(routes, ",") {
		if value := strings.TrimSpace(route); value != "" {
			raw = append(raw, value)
		}
	}
	normalized, err := normalizePrefixes(raw)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.Equal(a.routes, normalized) {
		return
	}
	a.routes = normalized
	a.markConfigChangedLocked(time.Now())
}

func (a *harmonyPlatformAdapter) SetInterfaceIP(ip string) {
	a.setInterfaceAddress(false, ip)
}

func (a *harmonyPlatformAdapter) SetInterfaceIPv6(ip string) {
	a.setInterfaceAddress(true, ip)
}

func (a *harmonyPlatformAdapter) setInterfaceAddress(ipv6 bool, value string) {
	value = strings.TrimSpace(value)
	baseRoute := ""
	if value != "" {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is6() != ipv6 {
			return
		}
		value = prefix.String()
		baseRoute = prefix.Masked().String()
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	current := &a.interfaceIPv4
	currentRoute := &a.baseRouteIPv4
	if ipv6 {
		current = &a.interfaceIPv6
		currentRoute = &a.baseRouteIPv6
	}
	if *current == value && *currentRoute == baseRoute {
		return
	}
	*current = value
	*currentRoute = baseRoute
	a.markConfigChangedLocked(time.Now())
}

func (a *harmonyPlatformAdapter) SetMTU(mtu int) {
	if mtu <= 0 || mtu > 65535 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mtu == mtu {
		return
	}
	a.mtu = mtu
	a.markConfigChangedLocked(time.Now())
}

func (a *harmonyPlatformAdapter) SetDNSAddress(value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return
		}
		value = address.String()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.preDNSAddress == value {
		return
	}
	a.preDNSAddress = value
	a.markConfigChangedLocked(time.Now())
}

func (a *harmonyPlatformAdapter) ApplyDns(raw string) {
	var config dns.HostDNSConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return
	}
	var addresses []string
	if config.ServerIP.IsValid() {
		addresses = []string{config.ServerIP.String()}
	}
	domains := make([]string, 0, len(config.Domains))
	for _, domainConfig := range config.Domains {
		if domainConfig.Disabled {
			continue
		}
		domain := strings.TrimSuffix(strings.TrimSpace(domainConfig.Domain), ".")
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	domains = uniqueSorted(domains)

	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.Equal(a.dnsAddresses, addresses) && slices.Equal(a.searchDomains, domains) {
		return
	}
	a.dnsAddresses = addresses
	a.searchDomains = domains
	a.markConfigChangedLocked(time.Now())
}

func (a *harmonyPlatformAdapter) markConfigChangedLocked(now time.Time) {
	a.configRevision++
	a.configChangedAt = now
	a.revision++
	if a.consumedConfigRevision == 0 || a.configRevision <= a.consumedConfigRevision {
		return
	}
	switch a.reconfigurationState {
	case "idle", "stable":
		if a.activeFDLease != 0 {
			a.reconfigurationState = "debouncing"
		}
	case "pending", "debouncing", "stopping-old-fd", "rebuilding-client", "old-fd-released", "restarting", "awaiting-new-fd":
		a.reconfigurationTarget = a.configRevision
	}
}

func (a *harmonyPlatformAdapter) debugRequestReconfiguration() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.activeFDLease == 0 || a.consumedConfigRevision == 0 ||
		a.reconfigurationState != "stable" || !a.configReadyLocked() {
		return errors.New("HarmonyOS debug reconfiguration requires a stable consumed fd")
	}
	now := time.Now()
	a.markConfigChangedLocked(now.Add(-a.reconfigurationDebounce))
	a.refreshReconfigurationLocked(now)
	if a.reconfigurationState != "pending" || a.reconfigurationTarget != a.configRevision {
		return errors.New("HarmonyOS debug reconfiguration did not become pending")
	}
	return nil
}

func (a *harmonyPlatformAdapter) refreshReconfigurationLocked(now time.Time) {
	if a.reconfigurationState != "debouncing" || a.activeFDLease == 0 ||
		a.configRevision <= a.consumedConfigRevision {
		return
	}
	if now.Sub(a.configChangedAt) < a.reconfigurationDebounce {
		return
	}
	a.reconfigurationGen++
	a.reconfigurationTarget = a.configRevision
	a.reconfigurationState = "pending"
	a.revision++
}

func (a *harmonyPlatformAdapter) snapshot() harmonyPlatformSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshReconfigurationLocked(time.Now())
	return a.snapshotLocked()
}

func (a *harmonyPlatformAdapter) WaitTunFD(ctx context.Context) (int, error) {
	fd, _, err := a.WaitTunFDLease(ctx)
	return fd, err
}

func (a *harmonyPlatformAdapter) WaitTunFDLease(ctx context.Context) (int, uint64, error) {
	a.mu.Lock()
	if a.fdWait != nil {
		a.mu.Unlock()
		return 0, 0, errors.New("HarmonyOS tunnel fd wait is already active")
	}
	a.preparationGen++
	lease := a.preparationGen
	a.preparationState = "awaiting-fd"
	if a.reconfigurationState == "restarting" {
		a.reconfigurationState = "awaiting-new-fd"
	}
	wait := make(chan harmonyTunFDResult, 1)
	a.fdWait = wait
	a.revision++
	a.mu.Unlock()

	select {
	case result := <-wait:
		if result.err != nil {
			return 0, 0, result.err
		}
		a.mu.Lock()
		if a.fdWait != wait || result.lease != lease || a.preparationState == "rolled-back" {
			a.mu.Unlock()
			return 0, 0, errors.New("HarmonyOS tunnel fd lease was invalidated before consumption")
		}
		a.fdWait = nil
		a.preparationState = "fd-received"
		a.revision++
		a.mu.Unlock()
		return result.fd, result.lease, nil
	case <-ctx.Done():
		a.mu.Lock()
		if a.fdWait == wait {
			a.fdWait = nil
			a.preparationState = "cancelled"
			a.revision++
		}
		a.mu.Unlock()
		return 0, 0, ctx.Err()
	}
}

func (a *harmonyPlatformAdapter) provideTunFD(fd int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reconfigurationState == "restarting" || a.reconfigurationState == "awaiting-new-fd" {
		return errors.New("HarmonyOS reconfiguration requires generation-aware tunnel fd provision")
	}
	return a.provideTunFDLocked(fd, a.preparationGen, a.reconfigurationGen, a.configRevision)
}

func (a *harmonyPlatformAdapter) provideTunFDForGeneration(
	fd int,
	preparationGeneration uint64,
	reconfigurationGeneration uint64,
	configRevision uint64,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.provideTunFDLocked(fd, preparationGeneration, reconfigurationGeneration, configRevision)
}

func (a *harmonyPlatformAdapter) provideTunFDLocked(
	fd int,
	preparationGeneration uint64,
	reconfigurationGeneration uint64,
	configRevision uint64,
) error {
	if fd <= 0 {
		return fmt.Errorf("HarmonyOS tunnel fd must be greater than zero: %d", fd)
	}
	if a.fdWait == nil || a.preparationState != "awaiting-fd" {
		return errors.New("HarmonyOS platform is not awaiting a tunnel fd")
	}
	if preparationGeneration != a.preparationGen {
		return fmt.Errorf("stale HarmonyOS preparation generation: got %d want %d", preparationGeneration, a.preparationGen)
	}
	if reconfigurationGeneration != a.reconfigurationGen {
		return fmt.Errorf("stale HarmonyOS reconfiguration generation: got %d want %d", reconfigurationGeneration, a.reconfigurationGen)
	}
	if configRevision != a.configRevision {
		return fmt.Errorf("stale HarmonyOS config revision: got %d want %d", configRevision, a.configRevision)
	}
	if !a.configReadyLocked() {
		return errors.New("HarmonyOS platform configuration is not ready")
	}
	if a.reconfigurationState == "restarting" {
		a.reconfigurationState = "awaiting-new-fd"
	}
	if a.reconfigurationState != "idle" && a.reconfigurationState != "stable" &&
		a.reconfigurationState != "awaiting-new-fd" {
		return fmt.Errorf("HarmonyOS reconfiguration state %q cannot accept a tunnel fd", a.reconfigurationState)
	}
	a.providedConfigRevision = configRevision
	a.preparationState = "fd-provided"
	a.revision++
	a.fdWait <- harmonyTunFDResult{fd: fd, lease: preparationGeneration}
	return nil
}

func (a *harmonyPlatformAdapter) TunFDConsumed() {
	a.mu.Lock()
	lease := a.preparationGen
	a.mu.Unlock()
	a.TunFDConsumedForLease(lease)
}

func (a *harmonyPlatformAdapter) TunFDConsumedForLease(lease uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.preparationState != "fd-received" || lease == 0 || lease != a.preparationGen {
		return
	}
	a.preparationState = "fd-consumed"
	a.activeFDLease = lease
	a.consumedConfigRevision = a.providedConfigRevision
	a.reconfigurationTarget = 0
	if a.configRevision > a.consumedConfigRevision {
		a.reconfigurationState = "debouncing"
		a.configChangedAt = time.Now()
	} else {
		a.reconfigurationState = "stable"
	}
	a.revision++
}

func (a *harmonyPlatformAdapter) TunFDReleasedForLease(lease uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if lease == 0 || lease != a.activeFDLease {
		return
	}
	a.activeFDLease = 0
	a.preparationState = "fd-released"
	if a.reconfigurationState == "stopping-old-fd" && lease == a.releaseFDLease {
		a.releaseFDLease = 0
		a.oldFDReleased = true
		a.reconfigurationState = "rebuilding-client"
	} else if a.reconfigurationState == "stable" {
		a.reconfigurationState = "idle"
	}
	a.revision++
}

func (a *harmonyPlatformAdapter) beginReconfiguration(generation, targetRevision uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshReconfigurationLocked(time.Now())
	if a.reconfigurationState != "pending" {
		return fmt.Errorf("HarmonyOS reconfiguration is not pending: %s", a.reconfigurationState)
	}
	if generation != a.reconfigurationGen {
		return fmt.Errorf("stale HarmonyOS reconfiguration generation: got %d want %d", generation, a.reconfigurationGen)
	}
	if targetRevision != a.reconfigurationTarget || targetRevision != a.configRevision {
		return fmt.Errorf("stale HarmonyOS reconfiguration target: got %d want %d", targetRevision, a.configRevision)
	}
	if time.Since(a.configChangedAt) < a.reconfigurationDebounce {
		return errors.New("HarmonyOS reconfiguration debounce has not elapsed")
	}
	if a.activeFDLease == 0 {
		return errors.New("HarmonyOS reconfiguration has no active fd lease")
	}
	a.releaseFDLease = a.activeFDLease
	a.oldFDReleased = false
	a.reconfigurationState = "stopping-old-fd"
	a.preparationState = "stopping-old-fd"
	a.revision++
	return nil
}

func (a *harmonyPlatformAdapter) oldFDReleaseAcknowledged(generation uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return generation == a.reconfigurationGen && a.oldFDReleased &&
		a.reconfigurationState == "rebuilding-client"
}

func (a *harmonyPlatformAdapter) completeClientRebuild(generation uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.reconfigurationGen || !a.oldFDReleased ||
		a.reconfigurationState != "rebuilding-client" {
		return errors.New("HarmonyOS old fd release acknowledgement is no longer current")
	}
	a.reconfigurationState = "old-fd-released"
	a.revision++
	return nil
}

func (a *harmonyPlatformAdapter) restartReconfiguration(generation uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.reconfigurationGen {
		return fmt.Errorf("stale HarmonyOS reconfiguration generation: got %d want %d", generation, a.reconfigurationGen)
	}
	if a.reconfigurationState != "old-fd-released" {
		return fmt.Errorf("HarmonyOS old fd is not released: %s", a.reconfigurationState)
	}
	a.reconfigurationState = "restarting"
	a.preparationState = "restarting"
	a.providedConfigRevision = 0
	a.revision++
	return nil
}

func (a *harmonyPlatformAdapter) failReconfiguration(generation uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.reconfigurationGen {
		return
	}
	if a.fdWait != nil {
		select {
		case a.fdWait <- harmonyTunFDResult{err: errors.New("HarmonyOS reconfiguration failed")}:
		default:
		}
		a.fdWait = nil
	}
	a.reconfigurationState = "failed"
	a.preparationState = "failed"
	a.activeFDLease = 0
	a.releaseFDLease = 0
	a.oldFDReleased = false
	a.revision++
}

// beginPreparationCycle clears a terminal state left by a previous preparation so
// that an explicit reconnect after rollback or cancellation can start again. Only
// terminal states are cleared; an in-flight preparation is left untouched.
func (a *harmonyPlatformAdapter) beginPreparationCycle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.preparationState == "rolled-back" || a.preparationState == "cancelled" {
		a.preparationState = "idle"
	}
	// The reconfiguration state is part of the same terminal snapshot. Leaving it
	// at "rolled-back" makes the next explicit connect reject a healthy platform.
	if a.reconfigurationState == "rolled-back" || a.reconfigurationState == "cancelled" ||
		a.reconfigurationState == "failed" {
		a.reconfigurationState = "idle"
		a.reconfigurationTarget = 0
	}
}

func (a *harmonyPlatformAdapter) rollbackDesired() harmonyPlatformSnapshot {	a.mu.Lock()
	defer a.mu.Unlock()
	desiredChanged := a.interfaceIPv4 != "" || a.interfaceIPv6 != "" || a.baseRouteIPv4 != "" ||
		a.baseRouteIPv6 != "" || len(a.routes) > 0 || a.preDNSAddress != "" ||
		len(a.dnsAddresses) > 0 || len(a.searchDomains) > 0 || a.mtu != 0
	changed := desiredChanged || (a.preparationState != "idle" && a.preparationState != "rolled-back") ||
		(a.reconfigurationState != "idle" && a.reconfigurationState != "rolled-back")
	if a.fdWait != nil {
		select {
		case a.fdWait <- harmonyTunFDResult{err: errors.New("HarmonyOS platform preparation rolled back")}:
		default:
		}
		a.fdWait = nil
	}
	a.interfaceIPv4 = ""
	a.interfaceIPv6 = ""
	a.baseRouteIPv4 = ""
	a.baseRouteIPv6 = ""
	a.routes = nil
	a.preDNSAddress = ""
	a.dnsAddresses = nil
	a.searchDomains = nil
	a.mtu = 0
	if changed {
		if desiredChanged {
			a.configRevision++
			a.configChangedAt = time.Now()
		}
		a.preparationState = "rolled-back"
		a.providedConfigRevision = 0
		a.consumedConfigRevision = 0
		a.activeFDLease = 0
		a.releaseFDLease = 0
		a.oldFDReleased = false
		a.reconfigurationGen++
		a.reconfigurationState = "rolled-back"
		a.reconfigurationTarget = 0
		a.revision++
	}
	return a.snapshotLocked()
}

func (a *harmonyPlatformAdapter) configReadyLocked() bool {
	return (a.interfaceIPv4 != "" || a.interfaceIPv6 != "") && a.mtu > 0
}

func (a *harmonyPlatformAdapter) snapshotLocked() harmonyPlatformSnapshot {
	addresses := make([]string, 0, 2)
	if a.interfaceIPv4 != "" {
		addresses = append(addresses, a.interfaceIPv4)
	}
	if a.interfaceIPv6 != "" {
		addresses = append(addresses, a.interfaceIPv6)
	}
	routes := make([]string, 0, len(a.routes)+2)
	if a.baseRouteIPv4 != "" {
		routes = append(routes, a.baseRouteIPv4)
	}
	if a.baseRouteIPv6 != "" {
		routes = append(routes, a.baseRouteIPv6)
	}
	routes = append(routes, a.routes...)
	routes = uniqueSorted(routes)
	dnsAddresses := slices.Clone(a.dnsAddresses)
	if a.preDNSAddress != "" {
		dnsAddresses = append(dnsAddresses, a.preDNSAddress)
	}
	dnsAddresses = uniqueSorted(dnsAddresses)
	return harmonyPlatformSnapshot{
		Revision:                      a.revision,
		InterfaceRevision:             a.interfaceRevision,
		PreparationGeneration:         a.preparationGen,
		PreparationState:              a.preparationState,
		ConfigRevision:                a.configRevision,
		AppliedConfigRevision:         a.consumedConfigRevision,
		ReconfigurationGeneration:     a.reconfigurationGen,
		ReconfigurationState:          a.reconfigurationState,
		ReconfigurationTargetRevision: a.reconfigurationTarget,
		InterfacesReady:               a.interfacesReady,
		ConfigReady:                   a.configReadyLocked(),
		Addresses:                     addresses,
		Routes:                        routes,
		DNSAddresses:                  dnsAddresses,
		SearchDomains:                 slices.Clone(a.searchDomains),
		MTU:                           a.mtu,
	}
}

func normalizePrefixes(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", value, err)
		}
		set[prefix.String()] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func runHarmonyPlatformAdapterSelfTest() (harmonyPlatformSnapshot, error) {
	adapter := newHarmonyPlatformAdapter()
	if err := adapter.setInterfacesJSON(`{"interfaces":[{"name":"selftest0","index":1,"mtu":1500,"up":true,"multicast":true,"addresses":["192.0.2.10/24"]}]}`); err != nil {
		return harmonyPlatformSnapshot{}, err
	}
	adapter.SetInterfaceIP("100.64.0.10/16")
	adapter.SetInterfaceIPv6("2001:db8:1::10/64")
	adapter.SetMTU(1280)
	adapter.OnNetworkChanged("192.168.0.0/16,10.0.0.0/8")
	adapter.ApplyDns(`{"domains":[{"domain":"example.test","matchOnly":true}],"routeAll":false,"serverIP":"100.64.0.53","serverPort":53}`)

	snapshot := adapter.snapshot()
	if !snapshot.InterfacesReady || !snapshot.ConfigReady || snapshot.MTU != 1280 ||
		len(snapshot.Addresses) != 2 || len(snapshot.Routes) != 4 || len(snapshot.DNSAddresses) != 1 {
		return harmonyPlatformSnapshot{}, fmt.Errorf("unexpected platform self-test snapshot: %+v", snapshot)
	}

	fdResult := make(chan harmonyTunFDResult, 1)
	go func() {
		fd, err := adapter.WaitTunFD(context.Background())
		fdResult <- harmonyTunFDResult{fd: fd, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for adapter.snapshot().PreparationState != "awaiting-fd" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if adapter.snapshot().PreparationState != "awaiting-fd" {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test did not enter awaiting-fd")
	}
	if err := adapter.provideTunFD(42); err != nil {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test provide fd: %w", err)
	}
	select {
	case result := <-fdResult:
		if result.err != nil || result.fd != 42 {
			return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test fd result: fd=%d err=%v", result.fd, result.err)
		}
	case <-time.After(time.Second):
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test fd wait timed out")
	}
	adapter.TunFDConsumed()
	consumed := adapter.snapshot()
	if consumed.PreparationState != "fd-consumed" || consumed.ReconfigurationState != "stable" ||
		consumed.AppliedConfigRevision != consumed.ConfigRevision {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test fd was not consumed: %+v", consumed)
	}

	adapter.mu.Lock()
	adapter.reconfigurationDebounce = 0
	adapter.mu.Unlock()
	adapter.OnNetworkChanged("192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
	pending := adapter.snapshot()
	if pending.ReconfigurationState != "pending" || pending.ReconfigurationGeneration == 0 ||
		pending.ReconfigurationTargetRevision != pending.ConfigRevision {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test reconfiguration was not coalesced: %+v", pending)
	}
	if err := adapter.beginReconfiguration(pending.ReconfigurationGeneration, pending.ReconfigurationTargetRevision); err != nil {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test begin reconfiguration: %w", err)
	}
	adapter.TunFDReleasedForLease(pending.PreparationGeneration + 1)
	if adapter.snapshot().ReconfigurationState != "stopping-old-fd" {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test accepted a stale release lease")
	}
	adapter.TunFDReleasedForLease(pending.PreparationGeneration)
	if !adapter.oldFDReleaseAcknowledged(pending.ReconfigurationGeneration) {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test did not acknowledge old fd release")
	}
	if err := adapter.completeClientRebuild(pending.ReconfigurationGeneration); err != nil {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test complete rebuild: %w", err)
	}
	if err := adapter.restartReconfiguration(pending.ReconfigurationGeneration); err != nil {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test restart reconfiguration: %w", err)
	}

	beforeRollback := adapter.snapshot().Revision
	rolledBack := adapter.rollbackDesired()
	if rolledBack.ConfigReady || len(rolledBack.Addresses) != 0 || len(rolledBack.Routes) != 0 ||
		len(rolledBack.DNSAddresses) != 0 || !rolledBack.InterfacesReady || rolledBack.Revision <= beforeRollback {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test rollback failed: %+v", rolledBack)
	}
	if repeated := adapter.rollbackDesired(); repeated.Revision != rolledBack.Revision {
		return harmonyPlatformSnapshot{}, fmt.Errorf("platform self-test rollback is not idempotent")
	}
	return snapshot, nil
}
