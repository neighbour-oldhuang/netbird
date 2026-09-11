package dns

import (
	"encoding/json"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type mobileHostManager struct {
	dnsManager MobileDNSManager
	config     HostDNSConfig
}

func newMobileHostManager(dnsManager MobileDNSManager) (*mobileHostManager, error) {
	if dnsManager == nil {
		return nil, fmt.Errorf("mobile DNS manager is required")
	}
	return &mobileHostManager{dnsManager: dnsManager}, nil
}

func (a mobileHostManager) getOriginalNameservers() []netip.Addr {
	// Mobile VPN extensions do not expose the pre-tunnel resolver list. Keep
	// the existing iOS behavior until the host API supplies that information.
	return []netip.Addr{
		netip.AddrFrom4([4]byte{9, 9, 9, 9}),
		netip.AddrFrom16([16]byte{0x26, 0x20, 0x00, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe}),
	}
}

func (a mobileHostManager) applyDNSConfig(config HostDNSConfig, _ *statemanager.Manager) error {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal mobile DNS config: %w", err)
	}
	log.Debug("Applying DNS settings through mobile host")
	a.dnsManager.ApplyDns(string(jsonData))
	return nil
}

func (a mobileHostManager) restoreHostDNS() error   { return nil }
func (a mobileHostManager) supportCustomPort() bool { return false }
func (a mobileHostManager) string() string          { return "mobile" }
