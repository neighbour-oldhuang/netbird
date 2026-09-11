//go:build harmony

package configurer

import "testing"

func TestHarmonyDisablesLinuxConfigurerOps(t *testing.T) {
	if supportsLinuxConfigurerOps() {
		t.Fatal("Harmony must not use Linux UAPI cleanup or fwmark operations")
	}
	if mark := getFwmark(); mark != 0 {
		t.Fatalf("Harmony fwmark = %d, want 0", mark)
	}
}
