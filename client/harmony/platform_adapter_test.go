package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

var (
	_ stdnet.ExternalIFaceDiscover   = (*harmonyPlatformAdapter)(nil)
	_ listener.NetworkChangeListener = (*harmonyPlatformAdapter)(nil)
	_ dns.MobileDNSManager           = (*harmonyPlatformAdapter)(nil)
)

func TestHarmonyPlatformAdapterInterfacesAndRevision(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	if _, err := a.IFaces(); err == nil {
		t.Fatal("IFaces succeeded before a snapshot was provided")
	}

	raw := `{"interfaces":[` +
		`{"name":"wlan0","index":7,"mtu":1500,"up":true,"broadcast":true,"multicast":true,"addresses":["192.0.2.10/24","2001:db8::10/64"]},` +
		`{"name":"rmnet0","index":8,"mtu":1400,"up":true,"pointToPoint":true,"addresses":["198.51.100.2/30"]}` +
		`]}`
	if err := a.setInterfacesJSON(raw); err != nil {
		t.Fatal(err)
	}
	got, err := a.IFaces()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "wlan0 7 1500 true true false false true|192.0.2.10/24 2001:db8::10/64") ||
		!strings.Contains(got, "rmnet0 8 1400 true false false true false|198.51.100.2/30") {
		t.Fatalf("unexpected interface text: %q", got)
	}
	first := a.snapshot()
	if !first.InterfacesReady || first.InterfaceRevision != 1 {
		t.Fatalf("unexpected first snapshot: %+v", first)
	}
	if err := a.setInterfacesJSON(raw); err != nil {
		t.Fatal(err)
	}
	if got := a.snapshot().InterfaceRevision; got != 1 {
		t.Fatalf("idempotent interface update changed revision to %d", got)
	}
}

func TestHarmonyPlatformAdapterDesiredConfigAndRollback(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	if err := a.setInterfacesJSON(`{"interfaces":[{"name":"wlan0","mtu":1500,"up":true,"addresses":["192.0.2.10/24"]}]}`); err != nil {
		t.Fatal(err)
	}
	a.SetInterfaceIP("100.64.0.10/16")
	a.SetInterfaceIPv6("2001:db8:1::10/64")
	a.SetMTU(1280)
	a.OnNetworkChanged("192.168.0.0/16,10.0.0.0/8,10.0.0.0/8")

	dnsRaw, err := json.Marshal(dns.HostDNSConfig{
		Domains: []dns.DomainConfig{
			{Domain: "example.com."},
			{Domain: "disabled.example", Disabled: true},
			{Domain: "example.com"},
		},
		ServerIP:   netip.MustParseAddr("100.64.0.53"),
		ServerPort: 53,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.ApplyDns(string(dnsRaw))

	snapshot := a.snapshot()
	if !snapshot.ConfigReady || snapshot.MTU != 1280 {
		t.Fatalf("config is not ready: %+v", snapshot)
	}
	if strings.Join(snapshot.Addresses, ",") != "100.64.0.10/16,2001:db8:1::10/64" {
		t.Fatalf("addresses: %v", snapshot.Addresses)
	}
	if strings.Join(snapshot.Routes, ",") != "10.0.0.0/8,100.64.0.0/16,192.168.0.0/16,2001:db8:1::/64" {
		t.Fatalf("routes: %v", snapshot.Routes)
	}
	if strings.Join(snapshot.DNSAddresses, ",") != "100.64.0.53" || strings.Join(snapshot.SearchDomains, ",") != "example.com" {
		t.Fatalf("DNS config: addresses=%v domains=%v", snapshot.DNSAddresses, snapshot.SearchDomains)
	}

	rolledBack := a.rollbackDesired()
	if rolledBack.ConfigReady || rolledBack.MTU != 0 || len(rolledBack.Addresses) != 0 || len(rolledBack.Routes) != 0 || len(rolledBack.DNSAddresses) != 0 {
		t.Fatalf("rollback retained desired config: %+v", rolledBack)
	}
	if !rolledBack.InterfacesReady || rolledBack.InterfaceRevision != 1 {
		t.Fatalf("rollback discarded physical interfaces: %+v", rolledBack)
	}
	if again := a.rollbackDesired(); again.Revision != rolledBack.Revision {
		t.Fatalf("idempotent rollback changed revision: %d -> %d", rolledBack.Revision, again.Revision)
	}
}

func TestHarmonyPlatformAdapterRejectsInvalidInterfaces(t *testing.T) {
	tests := []string{
		`{}`,
		`{"interfaces":[{"name":"bad name","mtu":1500,"addresses":["192.0.2.1/24"]}]}`,
		`{"interfaces":[{"name":"wlan0","mtu":0,"addresses":["192.0.2.1/24"]}]}`,
		`{"interfaces":[{"name":"wlan0","mtu":1500,"addresses":["not-a-prefix"]}]}`,
	}
	for _, raw := range tests {
		if err := newHarmonyPlatformAdapter().setInterfacesJSON(raw); err == nil {
			t.Fatalf("invalid interface payload accepted: %s", raw)
		}
	}
}

func TestHarmonyPlatformAdapterConcurrentSnapshots(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	if err := a.setInterfacesJSON(`{"interfaces":[{"name":"wlan0","mtu":1500,"up":true,"addresses":["192.0.2.10/24"]}]}`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			a.SetInterfaceIP("100.64.0.10/16")
			a.OnNetworkChanged("10.0.0.0/8")
		}()
		go func() {
			defer wg.Done()
			_ = a.snapshot()
			_, _ = a.IFaces()
		}()
	}
	wg.Wait()
	if !a.snapshot().InterfacesReady {
		t.Fatal("adapter lost interface readiness")
	}
}

func TestHarmonyPlatformAdapterSelfTest(t *testing.T) {
	snapshot, err := runHarmonyPlatformAdapterSelfTest()
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.InterfacesReady || !snapshot.ConfigReady {
		t.Fatalf("unexpected self-test snapshot: %+v", snapshot)
	}
}

func TestHarmonyPlatformAdapterLateFDProvide(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	a.SetInterfaceIP("100.64.0.10/16")
	a.SetMTU(1280)
	a.SetDNSAddress("100.64.0.53")

	result := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		fd, err := a.WaitTunFD(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		result <- fd
	}()
	waitForPreparationState(t, a, "awaiting-fd")
	snapshot := a.snapshot()
	if !snapshot.ConfigReady || snapshot.PreparationGeneration != 1 ||
		strings.Join(snapshot.Routes, ",") != "100.64.0.0/16" ||
		strings.Join(snapshot.DNSAddresses, ",") != "100.64.0.53" {
		t.Fatalf("unexpected prepared snapshot: %+v", snapshot)
	}
	if err := a.provideTunFD(42); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case fd := <-result:
		if fd != 42 {
			t.Fatalf("received fd %d, want 42", fd)
		}
	case <-time.After(time.Second):
		t.Fatal("late-fd wait did not complete")
	}
	waitForPreparationState(t, a, "fd-received")
	a.TunFDConsumed()
	waitForPreparationState(t, a, "fd-consumed")
}

func TestHarmonyPlatformAdapterLateFDCancelAndRollback(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		a := newHarmonyPlatformAdapter()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := a.WaitTunFD(ctx)
			done <- err
		}()
		waitForPreparationState(t, a, "awaiting-fd")
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("wait error = %v, want context.Canceled", err)
		}
		waitForPreparationState(t, a, "cancelled")
	})

	t.Run("rollback", func(t *testing.T) {
		a := newHarmonyPlatformAdapter()
		done := make(chan error, 1)
		go func() {
			_, err := a.WaitTunFD(context.Background())
			done <- err
		}()
		waitForPreparationState(t, a, "awaiting-fd")
		rolledBack := a.rollbackDesired()
		if rolledBack.PreparationState != "rolled-back" {
			t.Fatalf("rollback state: %+v", rolledBack)
		}
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("unexpected rollback wait error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("rollback did not unblock late-fd wait")
		}
		if err := a.provideTunFD(42); err == nil {
			t.Fatal("fd accepted after rollback")
		}
	})
}

func waitForPreparationState(t *testing.T, adapter *harmonyPlatformAdapter, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if adapter.snapshot().PreparationState == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("preparation state = %q, want %q", adapter.snapshot().PreparationState, want)
}

func TestHarmonyPlatformAdapterGenerationSafeReconfiguration(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	a.reconfigurationDebounce = 0
	a.SetInterfaceIP("100.64.0.10/16")
	a.SetMTU(1280)

	firstResult := make(chan harmonyTunFDResult, 1)
	go func() {
		fd, lease, err := a.WaitTunFDLease(context.Background())
		firstResult <- harmonyTunFDResult{fd: fd, lease: lease, err: err}
	}()
	waitForPreparationState(t, a, "awaiting-fd")
	first := a.snapshot()
	if err := a.provideTunFDForGeneration(42, first.PreparationGeneration, 0, first.ConfigRevision); err != nil {
		t.Fatal(err)
	}
	result := <-firstResult
	if result.err != nil || result.fd != 42 || result.lease != first.PreparationGeneration {
		t.Fatalf("unexpected first lease result: %+v", result)
	}
	a.TunFDConsumedForLease(result.lease)
	stable := a.snapshot()
	if stable.ReconfigurationState != "stable" || stable.AppliedConfigRevision != stable.ConfigRevision {
		t.Fatalf("first fd was not applied: %+v", stable)
	}

	a.OnNetworkChanged("10.0.0.0/8")
	a.ApplyDns(`{"domains":[{"domain":"example.test"}],"serverIP":"100.64.0.53","serverPort":53}`)
	pending := a.snapshot()
	if pending.ReconfigurationState != "pending" || pending.ReconfigurationGeneration != 1 ||
		pending.ReconfigurationTargetRevision != pending.ConfigRevision {
		t.Fatalf("unexpected pending snapshot: %+v", pending)
	}
	if err := a.beginReconfiguration(pending.ReconfigurationGeneration+1, pending.ReconfigurationTargetRevision); err == nil {
		t.Fatal("stale reconfiguration generation was accepted")
	}
	if err := a.beginReconfiguration(pending.ReconfigurationGeneration, pending.ReconfigurationTargetRevision-1); err == nil {
		t.Fatal("stale reconfiguration target was accepted")
	}
	if err := a.beginReconfiguration(pending.ReconfigurationGeneration, pending.ReconfigurationTargetRevision); err != nil {
		t.Fatal(err)
	}

	a.TunFDReleasedForLease(result.lease + 100)
	if got := a.snapshot().ReconfigurationState; got != "stopping-old-fd" {
		t.Fatalf("stale release changed state to %q", got)
	}
	a.TunFDReleasedForLease(result.lease)
	if got := a.snapshot().ReconfigurationState; got != "rebuilding-client" {
		t.Fatalf("matching release state = %q", got)
	}
	if !a.oldFDReleaseAcknowledged(pending.ReconfigurationGeneration) {
		t.Fatal("matching release was not acknowledged")
	}
	if err := a.completeClientRebuild(pending.ReconfigurationGeneration); err != nil {
		t.Fatal(err)
	}
	if err := a.restartReconfiguration(pending.ReconfigurationGeneration + 1); err == nil {
		t.Fatal("stale restart generation was accepted")
	}
	if err := a.restartReconfiguration(pending.ReconfigurationGeneration); err != nil {
		t.Fatal(err)
	}

	secondResult := make(chan harmonyTunFDResult, 1)
	go func() {
		fd, lease, err := a.WaitTunFDLease(context.Background())
		secondResult <- harmonyTunFDResult{fd: fd, lease: lease, err: err}
	}()
	waitForPreparationState(t, a, "awaiting-fd")
	second := a.snapshot()
	if second.ReconfigurationState != "awaiting-new-fd" {
		t.Fatalf("restart state = %q", second.ReconfigurationState)
	}
	if err := a.provideTunFDForGeneration(43, second.PreparationGeneration-1,
		second.ReconfigurationGeneration, second.ConfigRevision); err == nil {
		t.Fatal("stale preparation generation was accepted")
	}
	if err := a.provideTunFDForGeneration(43, second.PreparationGeneration,
		second.ReconfigurationGeneration, second.ConfigRevision-1); err == nil {
		t.Fatal("stale config revision was accepted")
	}
	if err := a.provideTunFDForGeneration(43, second.PreparationGeneration,
		second.ReconfigurationGeneration, second.ConfigRevision); err != nil {
		t.Fatal(err)
	}
	result = <-secondResult
	if result.err != nil || result.lease != second.PreparationGeneration {
		t.Fatalf("unexpected second lease result: %+v", result)
	}

	// A desired update after provision is intentionally not counted as applied
	// when the exact fd lease is consumed; it schedules the next generation.
	a.OnNetworkChanged("10.0.0.0/8,192.168.0.0/16")
	a.TunFDConsumedForLease(result.lease + 1)
	if got := a.snapshot().PreparationState; got != "fd-received" {
		t.Fatalf("stale consume changed preparation state to %q", got)
	}
	a.TunFDConsumedForLease(result.lease)
	next := a.snapshot()
	if next.ReconfigurationState != "pending" || next.ReconfigurationGeneration != 2 ||
		next.AppliedConfigRevision >= next.ConfigRevision {
		t.Fatalf("post-provide config change was incorrectly applied: %+v", next)
	}
}

func TestHarmonyPlatformAdapterDebounceCoalescesConfigChanges(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	a.reconfigurationDebounce = time.Hour
	a.SetInterfaceIP("100.64.0.10/16")
	a.SetMTU(1280)

	resultCh := make(chan harmonyTunFDResult, 1)
	go func() {
		fd, lease, err := a.WaitTunFDLease(context.Background())
		resultCh <- harmonyTunFDResult{fd: fd, lease: lease, err: err}
	}()
	waitForPreparationState(t, a, "awaiting-fd")
	prepared := a.snapshot()
	if err := a.provideTunFDForGeneration(42, prepared.PreparationGeneration, 0, prepared.ConfigRevision); err != nil {
		t.Fatal(err)
	}
	result := <-resultCh
	a.TunFDConsumedForLease(result.lease)

	a.OnNetworkChanged("10.0.0.0/8")
	a.SetDNSAddress("100.64.0.53")
	debouncing := a.snapshot()
	if debouncing.ReconfigurationState != "debouncing" || debouncing.ReconfigurationGeneration != 0 {
		t.Fatalf("changes escaped debounce: %+v", debouncing)
	}

	a.mu.Lock()
	a.reconfigurationDebounce = 0
	a.mu.Unlock()
	pending := a.snapshot()
	if pending.ReconfigurationState != "pending" || pending.ReconfigurationGeneration != 1 ||
		pending.ReconfigurationTargetRevision != pending.ConfigRevision {
		t.Fatalf("coalesced revision was not published: %+v", pending)
	}
	a.OnNetworkChanged("10.0.0.0/8,192.168.0.0/16")
	coalesced := a.snapshot()
	if coalesced.ReconfigurationGeneration != pending.ReconfigurationGeneration ||
		coalesced.ReconfigurationTargetRevision != coalesced.ConfigRevision {
		t.Fatalf("pending update did not coalesce: before=%+v after=%+v", pending, coalesced)
	}
}

func TestHarmonyPlatformAdapterDebugRequestReconfiguration(t *testing.T) {
	a := newHarmonyPlatformAdapter()
	a.SetInterfaceIP("100.64.0.10/16")
	a.SetMTU(1280)

	resultCh := make(chan harmonyTunFDResult, 1)
	go func() {
		fd, lease, err := a.WaitTunFDLease(context.Background())
		resultCh <- harmonyTunFDResult{fd: fd, lease: lease, err: err}
	}()
	waitForPreparationState(t, a, "awaiting-fd")
	prepared := a.snapshot()
	if err := a.provideTunFDForGeneration(42, prepared.PreparationGeneration, 0, prepared.ConfigRevision); err != nil {
		t.Fatal(err)
	}
	result := <-resultCh
	if result.err != nil {
		t.Fatal(result.err)
	}
	a.TunFDConsumedForLease(result.lease)
	stable := a.snapshot()
	if err := a.debugRequestReconfiguration(); err != nil {
		t.Fatal(err)
	}
	pending := a.snapshot()
	if pending.ReconfigurationState != "pending" || pending.ReconfigurationGeneration != 1 ||
		pending.ConfigRevision != stable.ConfigRevision+1 ||
		pending.ReconfigurationTargetRevision != pending.ConfigRevision {
		t.Fatalf("unexpected debug pending snapshot: %+v", pending)
	}
	if err := a.debugRequestReconfiguration(); err == nil {
		t.Fatal("second debug reconfiguration request was accepted while pending")
	}
}
