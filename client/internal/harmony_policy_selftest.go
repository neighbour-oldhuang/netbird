//go:build harmony

package internal

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/route"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type harmonyInitialMapRecorder struct {
	routes string
	dnsRaw string
}

func (r *harmonyInitialMapRecorder) OnNetworkChanged(routes string) { r.routes = routes }
func (r *harmonyInitialMapRecorder) SetInterfaceIP(string)          {}
func (r *harmonyInitialMapRecorder) SetInterfaceIPv6(string)        {}
func (r *harmonyInitialMapRecorder) ApplyDns(raw string)            { r.dnsRaw = raw }

func harmonyInitialMapPreparationSelfTest() error {
	recorder := &harmonyInitialMapRecorder{}
	engine := &Engine{
		config: &EngineConfig{WgAddr: wgaddr.MustParseWGAddress("100.64.10.1/24")},
		mobileDep: MobileDependency{
			Platform:              MobilePlatformHarmony,
			NetworkChangeListener: recorder,
			DnsManager:            recorder,
		},
		routeManager: &routemanager.MockManager{PrepareRouteRangesFunc: func(routes []*route.Route) []string {
			if len(routes) != 1 || routes[0].NetString() != "10.20.0.0/16" {
				return nil
			}
			return []string{"10.20.0.0/16"}
		}},
		dnsServer: &dns.MockServer{},
	}
	networkMap := &mgmProto.NetworkMap{
		Routes: []*mgmProto.Route{{
			ID: "selftest-route", Network: "10.20.0.0/16", NetID: "selftest", Peer: "remote", NetworkType: 1,
		}},
		DNSConfig: &mgmProto.DNSConfig{
			ServiceEnable: true,
			CustomZones:   []*mgmProto.CustomZone{{Domain: "selftest.example.com."}},
		},
	}
	if err := engine.prepareInitialNetworkMap(networkMap); err != nil {
		return err
	}
	if recorder.routes != "10.20.0.0/16" {
		return fmt.Errorf("unexpected prepared route projection")
	}
	var hostConfig dns.HostDNSConfig
	if err := json.Unmarshal([]byte(recorder.dnsRaw), &hostConfig); err != nil {
		return fmt.Errorf("decode prepared DNS projection: %w", err)
	}
	hasSearchDomain := false
	for _, domain := range hostConfig.Domains {
		if domain.Domain == "selftest.example.com." && !domain.Disabled && !domain.MatchOnly {
			hasSearchDomain = true
			break
		}
	}
	if hostConfig.ServerIP != netip.MustParseAddr("100.10.254.255") || !hasSearchDomain {
		return fmt.Errorf("unexpected prepared DNS projection")
	}
	return nil
}

type harmonyPolicyAdapter struct{}

func (harmonyPolicyAdapter) IFaces() (string, error) { return "", nil }
func (harmonyPolicyAdapter) OnNetworkChanged(string) {}
func (harmonyPolicyAdapter) SetInterfaceIP(string)   {}
func (harmonyPolicyAdapter) SetInterfaceIPv6(string) {}
func (harmonyPolicyAdapter) ApplyDns(string)         {}

// HarmonyPolicySelfTest validates fail-closed entry policy without starting
// management login, the engine, or a system VPN.
func HarmonyPolicySelfTest() error {
	if !isHarmonyBuild() {
		return fmt.Errorf("Harmony build marker is false")
	}
	if wgIfaceMonitorSupported() {
		return fmt.Errorf("desktop WireGuard monitor is enabled")
	}

	var client ConnectClient
	if err := client.Run(nil, ""); err == nil || !strings.Contains(err.Error(), "RunOnHarmony") {
		return fmt.Errorf("ordinary Run did not fail closed: %v", err)
	}

	adapter := harmonyPolicyAdapter{}
	if _, err := newHarmonyMobileDependency(0, adapter, adapter, adapter, "state.json", "cache"); err == nil {
		return fmt.Errorf("fd 0 was accepted")
	}
	dep, err := newHarmonyMobileDependency(3, adapter, adapter, adapter, "state.json", "cache")
	if err != nil {
		return fmt.Errorf("construct Harmony dependency: %w", err)
	}
	if dep.Platform != MobilePlatformHarmony || dep.Platform.OSName() != "harmony" || !dep.Platform.IsMobile() {
		return fmt.Errorf("invalid Harmony platform identity: %d", dep.Platform)
	}
	if err := harmonyInitialMapPreparationSelfTest(); err != nil {
		return fmt.Errorf("initial NetworkMap preparation: %w", err)
	}
	return nil
}
