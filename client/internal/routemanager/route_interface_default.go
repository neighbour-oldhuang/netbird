//go:build !harmony

package routemanager

import (
	"net"

	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
)

func routeSystemInterface(wg iface.WGIface) *net.Interface {
	return wg.ToInterface()
}
