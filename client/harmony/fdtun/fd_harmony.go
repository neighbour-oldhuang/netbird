//go:build harmony

package fdtun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// NewFromFD duplicates a HarmonyOS VpnConnection fd and returns a Device that
// owns only the duplicate. Closing Device never closes the original fd.
func NewFromFD(fd int, name string, mtu int) (*Device, error) {
	if fd <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidFD, fd)
	}

	dupFD, err := unix.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("duplicate tunnel fd: %w", err)
	}
	unix.CloseOnExec(dupFD)
	// O_NONBLOCK belongs to the shared open-file description, so this also
	// changes the original descriptor's status flags. VpnConnection retains
	// close ownership but must not rely on blocking I/O while Go owns the dup.
	// Nonblocking mode is required so Go netpoll can cancel a blocked Read on
	// Device.Close.
	if err := unix.SetNonblock(dupFD, true); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("set duplicated tunnel fd nonblocking: %w", err)
	}
	flags, err := unix.FcntlInt(uintptr(dupFD), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("verify duplicated tunnel fd nonblocking")
	}
	markRuntimeNonblockingVerified()

	file := os.NewFile(uintptr(dupFD), name)
	if file == nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("%w: os.NewFile failed", ErrInvalidFD)
	}
	device, err := newDevice(file, file, name, mtu)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return device, nil
}
