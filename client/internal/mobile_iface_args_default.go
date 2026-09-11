//go:build !android && !ios && !harmony

package internal

import "github.com/netbirdio/netbird/client/iface"

func configureMobileIFaceArgs(_ *iface.WGIFaceOpts, _ MobileDependency) {
}
