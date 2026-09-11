//go:build !harmony

package bind

import "net"

func bindUDPConnToDefaultNetwork(_ *net.UDPConn) error {
	return nil
}
