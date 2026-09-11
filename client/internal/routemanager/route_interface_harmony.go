//go:build harmony

package routemanager

import (
	"net"

	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
)

func routeSystemInterface(iface.WGIface) *net.Interface {
	return nil
}
