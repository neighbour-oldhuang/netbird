//go:build harmony

package iface

import (
	"context"
	"errors"
	"testing"

	"github.com/netbirdio/netbird/client/iface/device"
)

type harmonyFactoryFDProvider struct{}

func (harmonyFactoryFDProvider) WaitTunFD(context.Context) (int, error) {
	return 42, nil
}

func TestHarmonyNewWGIFaceRequiresPlatformFD(t *testing.T) {
	if _, err := NewWGIFace(WGIFaceOpts{}); !errors.Is(err, ErrHarmonyTunFDRequired) {
		t.Fatalf("missing MobileArgs error = %v", err)
	}

	for _, invalidFD := range []int{0, -1} {
		if _, err := NewWGIFace(WGIFaceOpts{
			MobileArgs: &device.MobileIFaceArguments{TunFd: invalidFD},
		}); !errors.Is(err, ErrHarmonyTunFDRequired) {
			t.Fatalf("invalid fd %d error = %v", invalidFD, err)
		}
	}
}

func TestHarmonyNewWGIFaceAcceptsLateFDProvider(t *testing.T) {
	wgInterface, err := NewWGIFace(WGIFaceOpts{
		Context: context.Background(),
		MobileArgs: &device.MobileIFaceArguments{
			TunFDProvider: harmonyFactoryFDProvider{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wgInterface == nil {
		t.Fatal("late-fd provider did not create WGIFace model")
	}
}
