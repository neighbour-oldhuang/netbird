//go:build harmony

package internal

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

func configureMobileIFaceArgs(opts *iface.WGIFaceOpts, dependency MobileDependency) {
	// A zero MobileDependency is used by the generic Run entrypoint. Never
	// treat stdin (fd 0) as a tunnel if that entrypoint is called by mistake.
	if dependency.FileDescriptor <= 0 && dependency.TunFDProvider == nil {
		return
	}
	opts.MobileArgs = &device.MobileIFaceArguments{
		TunFd:         int(dependency.FileDescriptor),
		TunFDProvider: dependency.TunFDProvider,
	}
}
