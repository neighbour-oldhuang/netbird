//go:build harmony

package iface

import (
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

var ErrHarmonyTunFDRequired = errors.New("HarmonyOS tunnel file descriptor is required")

// NewWGIFace creates a userspace WireGuard interface backed exclusively by a
// platform-provided fd. It never probes kernel WireGuard or /dev/net/tun.
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	if opts.MobileArgs == nil {
		return nil, ErrHarmonyTunFDRequired
	}
	if opts.MobileArgs.TunFd <= 0 && opts.MobileArgs.TunFDProvider == nil {
		return nil, fmt.Errorf("%w: no static fd or late-fd provider", ErrHarmonyTunFDRequired)
	}

	iceBind := bind.NewICEBind(opts.TransportNet, opts.Address, opts.MTU)
	return &WGIface{
		tun: device.NewTunDevice(
			opts.Context,
			opts.IFaceName,
			opts.Address,
			opts.WGPort,
			opts.WGPrivKey,
			opts.MTU,
			iceBind,
			opts.MobileArgs.TunFd,
			opts.MobileArgs.TunFDProvider,
		),
		userspaceBind:  true,
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
	}, nil
}
