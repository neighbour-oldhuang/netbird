package internal

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type harmonyTestPlatformAdapter struct{}

func (harmonyTestPlatformAdapter) IFaces() (string, error) { return "", nil }
func (harmonyTestPlatformAdapter) OnNetworkChanged(string) {}
func (harmonyTestPlatformAdapter) SetInterfaceIP(string)   {}
func (harmonyTestPlatformAdapter) SetInterfaceIPv6(string) {}
func (harmonyTestPlatformAdapter) ApplyDns(string)         {}

type harmonyTestTunFDProvider struct{}

func (harmonyTestTunFDProvider) WaitTunFD(context.Context) (int, error) {
	return 42, nil
}

func TestNewHarmonyMobileDependencyRejectsMissingRequirements(t *testing.T) {
	adapter := harmonyTestPlatformAdapter{}
	tests := []struct {
		name      string
		fd        int32
		discover  bool
		listener  bool
		dns       bool
		statePath string
		cacheDir  string
		want      string
	}{
		{name: "zero fd", fd: 0, discover: true, listener: true, dns: true, statePath: "state.json", cacheDir: "cache", want: "greater than zero"},
		{name: "negative fd", fd: -1, discover: true, listener: true, dns: true, statePath: "state.json", cacheDir: "cache", want: "greater than zero"},
		{name: "discoverer", fd: 3, listener: true, dns: true, statePath: "state.json", cacheDir: "cache", want: "interface discoverer"},
		{name: "network listener", fd: 3, discover: true, dns: true, statePath: "state.json", cacheDir: "cache", want: "network change listener"},
		{name: "dns manager", fd: 3, discover: true, listener: true, statePath: "state.json", cacheDir: "cache", want: "DNS manager"},
		{name: "state path", fd: 3, discover: true, listener: true, dns: true, statePath: " ", cacheDir: "cache", want: "state file path"},
		{name: "cache dir", fd: 3, discover: true, listener: true, dns: true, statePath: "state.json", cacheDir: " ", want: "cache directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var discover interface{ IFaces() (string, error) }
			var listener interface {
				OnNetworkChanged(string)
				SetInterfaceIP(string)
				SetInterfaceIPv6(string)
			}
			var dnsManager interface{ ApplyDns(string) }
			if tt.discover {
				discover = adapter
			}
			if tt.listener {
				listener = adapter
			}
			if tt.dns {
				dnsManager = adapter
			}

			_, err := newHarmonyMobileDependency(tt.fd, discover, listener, dnsManager, tt.statePath, tt.cacheDir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestNewHarmonyMobileDependencySetsExplicitPlatformAndPaths(t *testing.T) {
	adapter := harmonyTestPlatformAdapter{}
	dep, err := newHarmonyMobileDependency(7, adapter, adapter, adapter, "private/state.json", "private/cache")
	if err != nil {
		t.Fatal(err)
	}
	if dep.Platform != MobilePlatformHarmony || dep.Platform.OSName() != "harmony" || !dep.Platform.IsMobile() {
		t.Fatalf("unexpected platform identity: %v", dep.Platform)
	}
	if dep.FileDescriptor != 7 || dep.StateFilePath != "private/state.json" || dep.TempDir != "private/cache" {
		t.Fatalf("unexpected Harmony dependency: %+v", dep)
	}
	if dep.IFaceDiscover == nil || dep.NetworkChangeListener == nil || dep.DnsManager == nil {
		t.Fatal(errors.New("Harmony platform adapters were not retained"))
	}
}

func TestNewHarmonyMobileDependencyWithFDProvider(t *testing.T) {
	adapter := harmonyTestPlatformAdapter{}
	if _, err := newHarmonyMobileDependencyWithFDProvider(nil, adapter, adapter, adapter, "state.json", "cache"); err == nil || !strings.Contains(err.Error(), "fd provider") {
		t.Fatalf("missing provider error = %v", err)
	}
	provider := harmonyTestTunFDProvider{}
	dependency, err := newHarmonyMobileDependencyWithFDProvider(provider, adapter, adapter, adapter, "state.json", "cache")
	if err != nil {
		t.Fatal(err)
	}
	if dependency.Platform != MobilePlatformHarmony || dependency.FileDescriptor != 0 || dependency.TunFDProvider == nil {
		t.Fatalf("unexpected late-fd dependency: %+v", dependency)
	}
}
