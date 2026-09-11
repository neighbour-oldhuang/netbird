//go:build !android && !ios && !harmony

package dns

import (
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// GetClientPrivate returns a plain client: platforms in this group reach the
// tunnel through the system routing table without extra socket binding.
func GetClientPrivate(_ privateClientIface, _ netip.Addr, dialTimeout time.Duration) (*dns.Client, error) {
	return &dns.Client{
		Timeout: dialTimeout,
		Net:     "udp",
	}, nil
}
