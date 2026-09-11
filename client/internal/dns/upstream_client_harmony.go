//go:build harmony

package dns

import (
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/harmony/netbinding"
)

// GetClientPrivate returns a DNS client whose socket is pinned to the VPN network.
//
// The HarmonyOS VPN process protects itself as a whole, so every socket it creates
// leaves through the physical network and can never reach a tunnel address. That
// is required for the WireGuard and ICE sockets, but the DNS interceptor has to
// talk to the DNS forwarder of a routing peer, which only exists inside the
// tunnel. Without this binding those queries time out and every domain based
// network resource fails to resolve.
func GetClientPrivate(_ privateClientIface, _ netip.Addr, dialTimeout time.Duration) (*dns.Client, error) {
	return &dns.Client{
		Timeout: dialTimeout,
		Net:     "udp",
		Dialer: &net.Dialer{
			Timeout: dialTimeout,
			Control: netbinding.BindControl,
		},
	}, nil
}
