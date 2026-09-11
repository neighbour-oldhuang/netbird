//go:build harmony

package internal

import (
	"strings"
	"testing"
)

func TestHarmonyBuildPolicy(t *testing.T) {
	if !isHarmonyBuild() {
		t.Fatal("Harmony build marker is false")
	}
	if wgIfaceMonitorSupported() {
		t.Fatal("Harmony must not use the desktop WireGuard interface monitor")
	}

	var client ConnectClient
	err := client.Run(nil, "")
	if err == nil || !strings.Contains(err.Error(), "RunOnHarmony") {
		t.Fatalf("ordinary Run must fail closed on Harmony, got %v", err)
	}
}
