//go:build harmony

package device

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/harmony/fdtun"
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// TunDevice is a userspace WireGuard device backed by a HarmonyOS-owned VPN
// fd. The fdtun layer duplicates the fd; this type never creates a system TUN.
type TunDevice struct {
	ctx           context.Context
	name          string
	address       wgaddr.Address
	port          int
	key           string
	mtu           uint16
	iceBind       *bind.ICEBind
	tunFD         int
	tunFDProvider TunFDProvider
	tunFDLease    uint64
	tunDuplicated bool
	tunReleased   bool

	device         *wgdevice.Device
	filteredDevice *FilteredDevice
	udpMux         *udpmux.UniversalUDPMuxDefault
	configurer     WGConfigurer
}

func NewTunDevice(ctx context.Context, name string, address wgaddr.Address, port int, key string, mtu uint16, iceBind *bind.ICEBind, tunFD int, tunFDProvider TunFDProvider) *TunDevice {
	if ctx == nil {
		ctx = context.Background()
	}
	return &TunDevice{
		ctx:           ctx,
		name:          name,
		address:       address,
		port:          port,
		key:           key,
		mtu:           mtu,
		iceBind:       iceBind,
		tunFD:         tunFD,
		tunFDProvider: tunFDProvider,
	}
}

func (t *TunDevice) Create() (WGConfigurer, error) {
	if t.device != nil {
		return t.configurer, nil
	}

	tunFD := t.tunFD
	lease := uint64(0)
	if tunFD <= 0 {
		if t.tunFDProvider == nil {
			return nil, fmt.Errorf("HarmonyOS tunnel fd is unavailable")
		}
		var err error
		if leaseProvider, ok := t.tunFDProvider.(TunFDLeaseProvider); ok {
			tunFD, lease, err = leaseProvider.WaitTunFDLease(t.ctx)
		} else {
			tunFD, err = t.tunFDProvider.WaitTunFD(t.ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("wait for HarmonyOS tunnel fd: %w", err)
		}
		if tunFD <= 0 {
			return nil, fmt.Errorf("HarmonyOS late-fd provider returned invalid fd: %d", tunFD)
		}
	}

	tunDevice, err := fdtun.NewFromFD(tunFD, t.name, int(t.mtu))
	if err != nil {
		return nil, fmt.Errorf("create HarmonyOS fd TUN adapter: %w", err)
	}
	t.tunFDLease = lease
	t.tunDuplicated = true
	if notifier, ok := t.tunFDProvider.(TunFDLeaseLifecycleNotifier); ok && lease != 0 {
		notifier.TunFDConsumedForLease(lease)
	} else if notifier, ok := t.tunFDProvider.(TunFDConsumptionNotifier); ok {
		notifier.TunFDConsumed()
	}

	t.filteredDevice = newDeviceFilter(tunDevice)
	t.device = wgdevice.NewDevice(
		t.filteredDevice,
		t.iceBind,
		wgdevice.NewLogger(wgLogLevel(), "[netbird-harmony] "),
	)

	// HarmonyOS has no filesystem UAPI socket contract. Configure the embedded
	// device directly and leave platform lifecycle ownership to VpnConnection.
	t.configurer = configurer.NewUSPConfigurerNoUAPI(t.device, t.name, t.iceBind.ActivityRecorder())
	if err := t.configurer.ConfigureInterface(t.key, t.port); err != nil {
		t.configurer.Close()
		t.device.Close()
		t.device = nil
		t.filteredDevice = nil
		t.notifyTunFDReleased()
		return nil, fmt.Errorf("configure HarmonyOS WireGuard interface: %w", err)
	}

	log.Debugf("HarmonyOS fd-backed WireGuard device created: %s", t.name)
	return t.configurer, nil
}

func (t *TunDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
	if t.device == nil {
		return nil, fmt.Errorf("HarmonyOS WireGuard device is not created")
	}
	if err := t.device.Up(); err != nil {
		return nil, err
	}

	udpMux, err := t.iceBind.GetICEMux()
	if err != nil {
		return nil, err
	}
	t.udpMux = udpMux
	return udpMux, nil
}

func (t *TunDevice) UpdateAddr(address wgaddr.Address) error {
	// HarmonyOS owns interface addressing through VpnConfig. Keep the NetBird
	// model in sync without issuing Linux netlink operations.
	t.address = address
	return nil
}

func (t *TunDevice) Close() error {
	if t.configurer != nil {
		t.configurer.Close()
		t.configurer = nil
	}
	if t.device != nil {
		t.device.Close()
		t.device = nil
		t.filteredDevice = nil
	}
	t.notifyTunFDReleased()
	if t.udpMux != nil {
		err := t.udpMux.Close()
		t.udpMux = nil
		return err
	}
	return nil
}

func (t *TunDevice) notifyTunFDReleased() {
	if !t.tunDuplicated || t.tunReleased {
		return
	}
	t.tunReleased = true
	if notifier, ok := t.tunFDProvider.(TunFDLeaseLifecycleNotifier); ok && t.tunFDLease != 0 {
		notifier.TunFDReleasedForLease(t.tunFDLease)
	}
}

func (t *TunDevice) WgAddress() wgaddr.Address { return t.address }
func (t *TunDevice) MTU() uint16               { return t.mtu }
func (t *TunDevice) DeviceName() string        { return t.name }
func (t *TunDevice) FilteredDevice() *FilteredDevice {
	return t.filteredDevice
}
func (t *TunDevice) Device() *wgdevice.Device { return t.device }
func (t *TunDevice) GetNet() *netstack.Net    { return nil }
func (t *TunDevice) GetICEBind() EndpointManager {
	return t.iceBind
}
