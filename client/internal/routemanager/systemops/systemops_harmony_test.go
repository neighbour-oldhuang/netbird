//go:build harmony

package systemops_test

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

type routeListener struct{ updates []string }

func (l *routeListener) OnNetworkChanged(routes string) { l.updates = append(l.updates, routes) }
func (*routeListener) SetInterfaceIP(string)            {}
func (*routeListener) SetInterfaceIPv6(string)          {}

func TestHarmonySysOpsOnlyPublishesRoutePrefixes(t *testing.T) {
	listener := &routeListener{}
	n := notifier.NewNotifier()
	n.SetListener(listener)
	sys := systemops.New(nil, n)

	if err := sys.SetupRouting(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	p2 := netip.MustParsePrefix("192.0.2.0/24")
	p1 := netip.MustParsePrefix("10.0.0.0/8")
	if err := sys.AddVPNRoute(p2, nil); err != nil {
		t.Fatal(err)
	}
	if err := sys.AddVPNRoute(p1, nil); err != nil {
		t.Fatal(err)
	}
	if got := listener.updates[len(listener.updates)-1]; got != "10.0.0.0/8,192.0.2.0/24" {
		t.Fatalf("route update = %q", got)
	}

	if err := sys.RemoveVPNRoute(p2, nil); err != nil {
		t.Fatal(err)
	}
	if got := listener.updates[len(listener.updates)-1]; got != "10.0.0.0/8" {
		t.Fatalf("route removal update = %q", got)
	}
}
