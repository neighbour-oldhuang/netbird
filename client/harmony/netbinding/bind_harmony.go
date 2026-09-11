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
	"net"
	"sync/atomic"
)

var (
	bindAttempts  atomic.Uint64
	bindSucceeded atomic.Uint64
	bindFailed    atomic.Uint64
)

func Stats() (attempts uint64, succeeded uint64, failed uint64) {
	return bindAttempts.Load(), bindSucceeded.Load(), bindFailed.Load()
}

func BindUDPConn(conn *net.UDPConn) (err error) {
	bindAttempts.Add(1)
	defer func() {
		if err != nil {
			bindFailed.Add(1)
			return
		}
		bindSucceeded.Add(1)
	}()

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		var handle C.NetConn_NetHandle
		if result := C.OH_NetConn_GetDefaultNet(&handle); result != 0 {
			bindErr = fmt.Errorf("get default network: code %d", int32(result))
			return
		}
		if handle.netId <= 0 {
			bindErr = fmt.Errorf("default network is unavailable")
			return
		}
		if result := C.OH_NetConn_BindSocket(C.int32_t(fd), &handle); result != 0 {
			bindErr = fmt.Errorf("bind socket to default network: code %d", int32(result))
		}
	}); err != nil {
		return err
	}
	return bindErr
}
