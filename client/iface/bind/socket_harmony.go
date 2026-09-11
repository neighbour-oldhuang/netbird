//go:build harmony

package bind

import (
	"net"

	"github.com/netbirdio/netbird/client/harmony/netbinding"
)

func bindUDPConnToDefaultNetwork(conn *net.UDPConn) error {
	return netbinding.BindUDPConn(conn)
}
