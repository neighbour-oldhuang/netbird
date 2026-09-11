//go:build android

package internal

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

func configureMobileIFaceArgs(opts *iface.WGIFaceOpts, dependency MobileDependency) {
	opts.MobileArgs = &device.MobileIFaceArguments{
		TunAdapter: dependency.TunAdapter,
		TunFd:      int(dependency.FileDescriptor),
	}
}
