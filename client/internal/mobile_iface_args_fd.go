//go:build ios

package internal

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

func configureMobileIFaceArgs(opts *iface.WGIFaceOpts, dependency MobileDependency) {
	opts.MobileArgs = &device.MobileIFaceArguments{
		TunFd: int(dependency.FileDescriptor),
	}
}
