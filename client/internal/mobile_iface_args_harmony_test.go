//go:build harmony

package internal

import (
	"testing"

	"github.com/netbirdio/netbird/client/iface"
)

func TestConfigureMobileIFaceArgsHarmony(t *testing.T) {
	opts := iface.WGIFaceOpts{}
	configureMobileIFaceArgs(&opts, MobileDependency{})
	if opts.MobileArgs != nil {
		t.Fatal("zero MobileDependency must not configure stdin as a tunnel")
	}

	configureMobileIFaceArgs(&opts, MobileDependency{FileDescriptor: 42})
	if opts.MobileArgs == nil {
		t.Fatal("MobileArgs was not configured")
	}
	if opts.MobileArgs.TunFd != 42 {
		t.Fatalf("TunFd = %d, want 42", opts.MobileArgs.TunFd)
	}
	if opts.MobileArgs.TunAdapter != nil {
		t.Fatal("HarmonyOS must not configure an Android TunAdapter")
	}
}
