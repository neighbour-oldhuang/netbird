// Package fdtun adapts a platform-owned packet tunnel file descriptor to the
// wireguard-go tun.Device contract used by NetBird.
package fdtun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

const defaultName = "nb-harmony-fd"

var (
	ErrInvalidFD     = errors.New("invalid tunnel file descriptor")
	ErrInvalidMTU    = errors.New("invalid tunnel MTU")
	ErrInvalidBuffer = errors.New("invalid tunnel packet buffer")
	ErrInvalidOffset = errors.New("invalid tunnel packet offset")
	ErrUnsupported   = errors.New("fd-backed tunnel is unsupported on this build")
)

type readWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

// Device performs raw IP packet I/O over a duplicated platform tunnel fd.
// It owns only the duplicate; the original fd remains owned by HarmonyOS.
type Device struct {
	transport readWriteCloser
	file      *os.File
	name      string
	mtu       int
	events    chan tun.Event

	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

var _ tun.Device = (*Device)(nil)

func newDevice(transport readWriteCloser, file *os.File, name string, mtu int) (*Device, error) {
	if transport == nil {
		return nil, ErrInvalidFD
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
	}
	if name == "" {
		name = defaultName
	}

	device := &Device{
		transport: transport,
		file:      file,
		name:      name,
		mtu:       mtu,
		events:    make(chan tun.Event, 2),
	}
	device.events <- tun.EventUp
	return device, nil
}

// File returns the duplicated fd owned by this device. It never returns the
// original HarmonyOS VpnConnection fd.
func (d *Device) File() *os.File {
	return d.file
}

// Read reads exactly one raw IP packet. HarmonyOS VPN fds preserve packet
// boundaries, so batching multiple reads into one call is intentionally not
// attempted.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, ErrInvalidBuffer
	}
	if offset < 0 || offset >= len(bufs[0]) {
		return 0, fmt.Errorf("%w: %d", ErrInvalidOffset, offset)
	}

	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}

	n, err := d.transport.Read(bufs[0][offset:])
	if n > 0 {
		recordRuntimePacket(bufs[0][offset:offset+n], true)
		sizes[0] = n
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, io.ErrNoProgress
}

// Write writes each supplied raw IP packet with one transport write so packet
// boundaries are not merged or split.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if offset < 0 {
		return 0, fmt.Errorf("%w: %d", ErrInvalidOffset, offset)
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}

	for i, buf := range bufs {
		if offset >= len(buf) {
			return i, fmt.Errorf("%w: packet=%d offset=%d length=%d", ErrInvalidOffset, i, offset, len(buf))
		}
		packet := buf[offset:]
		n, err := d.transport.Write(packet)
		if n > 0 {
			recordRuntimePacket(packet[:n], false)
		}
		if err != nil {
			return i, err
		}
		if n != len(packet) {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}

func (d *Device) MTU() (int, error) {
	return d.mtu, nil
}

func (d *Device) Name() (string, error) {
	return d.name, nil
}

func (d *Device) Events() <-chan tun.Event {
	return d.events
}

// Close is idempotent. Closing the duplicated fd cancels Go-side blocking I/O
// without closing the original fd retained by HarmonyOS VpnConnection.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		d.closeErr = d.transport.Close()
		d.events <- tun.EventDown
		close(d.events)
	})
	return d.closeErr
}

func (d *Device) BatchSize() int {
	return 1
}
