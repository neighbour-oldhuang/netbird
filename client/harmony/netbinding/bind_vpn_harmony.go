//go:build harmony

package netbinding

/*
#cgo LDFLAGS: -lnet_connection
#include <stdint.h>
#include <network/netmanager/net_connection.h>
*/
import "C"

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

var (
	vpnBindAttempts  atomic.Uint64
	vpnBindSucceeded atomic.Uint64
	vpnBindFailed    atomic.Uint64
)

// VPNStats reports how often a socket was pinned to the VPN network.
func VPNStats() (attempts uint64, succeeded uint64, failed uint64) {
	return vpnBindAttempts.Load(), vpnBindSucceeded.Load(), vpnBindFailed.Load()
}

// BindSocketToVPN pins one socket to the VPN network.
//
// The VPN process protects itself as a whole so its sockets leave through the
// physical network and cannot recurse into the tunnel. That is right for the
// WireGuard and ICE sockets, but it also blocks the few sockets that must reach
// a tunnel address: the DNS interceptor queries the DNS forwarder of a routing
// peer at its tunnel IP. Binding those sockets to the VPN network restores that
// single path without giving up the process-wide protection.
func BindSocketToVPN(fd uintptr) (err error) {
	vpnBindAttempts.Add(1)
	defer func() {
		if err != nil {
			vpnBindFailed.Add(1)
			return
		}
		vpnBindSucceeded.Add(1)
	}()

	handle, err := vpnNetHandle()
	if err != nil {
		return err
	}
	if result := C.OH_NetConn_BindSocket(C.int32_t(fd), &handle); result != 0 {
		return fmt.Errorf("bind socket to VPN network %d: code %d", int32(handle.netId), int32(result))
	}
	return nil
}

// BindControl is a net.Dialer Control hook that pins the dialed socket to the
// VPN network.
func BindControl(_, _ string, c syscall.RawConn) error {
	var bindErr error
	if err := c.Control(func(fd uintptr) {
		bindErr = BindSocketToVPN(fd)
	}); err != nil {
		return err
	}
	return bindErr
}

func vpnNetHandle() (C.NetConn_NetHandle, error) {
	var list C.NetConn_NetHandleList
	if result := C.OH_NetConn_GetAllNets(&list); result != 0 {
		return C.NetConn_NetHandle{}, fmt.Errorf("list networks: code %d", int32(result))
	}
	size := int(list.netHandleListSize)
	if size > len(list.netHandles) {
		size = len(list.netHandles)
	}
	for index := 0; index < size; index++ {
		handle := list.netHandles[index]
		if handle.netId <= 0 {
			continue
		}
		var caps C.NetConn_NetCapabilities
		if result := C.OH_NetConn_GetNetCapabilities(&handle, &caps); result != 0 {
			continue
		}
		bearerCount := int(caps.bearerTypesSize)
		if bearerCount > len(caps.bearerTypes) {
			bearerCount = len(caps.bearerTypes)
		}
		for bearer := 0; bearer < bearerCount; bearer++ {
			if caps.bearerTypes[bearer] == C.NETCONN_BEARER_VPN {
				return handle, nil
			}
		}
	}
	return C.NetConn_NetHandle{}, fmt.Errorf("no VPN network is available")
}
