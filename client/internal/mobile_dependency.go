package internal

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// MobilePlatform identifies mobile ports whose GOOS value is not sufficient for
// platform dispatch. In particular, HarmonyOS is built with GOOS=linux.
type MobilePlatform uint8

const (
	MobilePlatformNone MobilePlatform = iota
	MobilePlatformAndroid
	MobilePlatformIOS
	MobilePlatformHarmony
)

// IsMobile reports whether platform services must be supplied by the host app.
func (p MobilePlatform) IsMobile() bool {
	return p != MobilePlatformNone
}

// OSName returns the platform name used in diagnostics and metrics.
func (p MobilePlatform) OSName() string {
	switch p {
	case MobilePlatformAndroid:
		return "android"
	case MobilePlatformIOS:
		return "ios"
	case MobilePlatformHarmony:
		return "harmony"
	default:
		return ""
	}
}

// MobileDependency collects dependencies supplied by a mobile host app.
type MobileDependency struct {
	Platform MobilePlatform

	NetworkChangeListener listener.NetworkChangeListener
	IFaceDiscover         stdnet.ExternalIFaceDiscover

	// Android only.
	TunAdapter       device.TunAdapter
	HostDNSAddresses []netip.AddrPort
	DnsReadyListener dns.ReadyListener

	// iOS and HarmonyOS.
	DnsManager     dns.MobileDNSManager
	FileDescriptor int32
	TunFDProvider  device.TunFDProvider
	StateFilePath  string

	// TempDir is a writable app-private directory for temporary files.
	TempDir string
}
