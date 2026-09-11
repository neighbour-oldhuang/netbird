//go:build harmony

package ice

import (
	"context"
	"testing"
)

type harmonyICEInterfaceDiscover struct{}

func (harmonyICEInterfaceDiscover) IFaces() (string, error) {
	return "rmnet0 7 1500 true true false false true|192.0.2.10/24", nil
}

func TestHarmonyNewStdNetUsesExternalInterfaceDiscover(t *testing.T) {
	network, err := newStdNet(context.Background(), harmonyICEInterfaceDiscover{}, nil)
	if err != nil {
		t.Fatalf("newStdNet() error = %v", err)
	}
	interfaces, err := network.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error = %v", err)
	}
	if len(interfaces) != 1 {
		t.Fatalf("Interfaces() count = %d, want 1", len(interfaces))
	}
	if interfaces[0].Name != "rmnet0" || interfaces[0].Index != 7 {
		t.Fatalf("Interfaces()[0] = %s/%d, want rmnet0/7", interfaces[0].Name, interfaces[0].Index)
	}
	addresses, err := interfaces[0].Addrs()
	if err != nil {
		t.Fatalf("Addrs() error = %v", err)
	}
	if len(addresses) != 1 || addresses[0].String() != "192.0.2.10/24" {
		t.Fatalf("Addrs() = %v, want [192.0.2.10/24]", addresses)
	}
}
