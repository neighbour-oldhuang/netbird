package fdtun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func newPipeDevice(t *testing.T) (*Device, net.Conn) {
	t.Helper()
	deviceConn, peerConn := net.Pipe()
	device, err := newDevice(deviceConn, nil, "test-fd-tun", 1280)
	if err != nil {
		t.Fatalf("newDevice: %v", err)
	}
	t.Cleanup(func() {
		_ = device.Close()
		_ = peerConn.Close()
	})
	return device, peerConn
}

func TestDeviceReadPreservesPacketAndOffset(t *testing.T) {
	device, peer := newPipeDevice(t)
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(packet)
		writeDone <- err
	}()

	buf := bytes.Repeat([]byte{0xaa}, 64)
	sizes := make([]int, 1)
	n, err := device.Read([][]byte{buf}, sizes, 8)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 || sizes[0] != len(packet) {
		t.Fatalf("Read result packets=%d size=%d", n, sizes[0])
	}
	if !bytes.Equal(buf[8:8+sizes[0]], packet) {
		t.Fatalf("packet mismatch: %x", buf[8:8+sizes[0]])
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("peer Write: %v", err)
	}
}

func TestDeviceWritePreservesPacketsAndOffset(t *testing.T) {
	device, peer := newPipeDevice(t)
	packet := []byte{0x60, 0x00, 0x00, 0x00}
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(packet))
		_, _ = io.ReadFull(peer, buf)
		readDone <- buf
	}()

	withHeadroom := append(bytes.Repeat([]byte{0xbb}, 6), packet...)
	n, err := device.Write([][]byte{withHeadroom}, 6)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 1 {
		t.Fatalf("Write packets=%d", n)
	}
	if got := <-readDone; !bytes.Equal(got, packet) {
		t.Fatalf("packet mismatch: %x", got)
	}
}

func TestDeviceCloseCancelsReadAndIsIdempotent(t *testing.T) {
	deviceConn, peerConn := net.Pipe()
	tracked := &countingCloser{Conn: deviceConn}
	device, err := newDevice(tracked, nil, "test-close", 1280)
	if err != nil {
		t.Fatalf("newDevice: %v", err)
	}
	defer peerConn.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := device.Read([][]byte{buf}, make([]int, 1), 0)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		t.Fatalf("Read returned before Close: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	if err := device.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := tracked.closeCalls.Load(); got != 1 {
		t.Fatalf("transport close calls=%d", got)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read returned nil error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Read was not cancelled by Close")
	}
}

func TestDeviceEventsAndMetadata(t *testing.T) {
	device, _ := newPipeDevice(t)
	if device.BatchSize() != 1 {
		t.Fatalf("BatchSize=%d", device.BatchSize())
	}
	if name, _ := device.Name(); name != "test-fd-tun" {
		t.Fatalf("Name=%q", name)
	}
	if mtu, _ := device.MTU(); mtu != 1280 {
		t.Fatalf("MTU=%d", mtu)
	}
	if event := <-device.Events(); event != tun.EventUp {
		t.Fatalf("first event=%v", event)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if event := <-device.Events(); event != tun.EventDown {
		t.Fatalf("second event=%v", event)
	}
	if _, ok := <-device.Events(); ok {
		t.Fatal("events channel remains open")
	}
}

func TestDeviceRejectsInvalidArguments(t *testing.T) {
	if _, err := newDevice(nil, nil, "bad", 1280); !errors.Is(err, ErrInvalidFD) {
		t.Fatalf("nil transport error=%v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := newDevice(left, nil, "bad", 0); !errors.Is(err, ErrInvalidMTU) {
		t.Fatalf("invalid MTU error=%v", err)
	}

	device, _ := newPipeDevice(t)
	if _, err := device.Read(nil, nil, 0); !errors.Is(err, ErrInvalidBuffer) {
		t.Fatalf("empty Read error=%v", err)
	}
	if _, err := device.Read([][]byte{make([]byte, 4)}, []int{}, 0); !errors.Is(err, ErrInvalidBuffer) {
		t.Fatalf("short sizes error=%v", err)
	}
	if _, err := device.Read([][]byte{make([]byte, 4)}, make([]int, 1), 4); !errors.Is(err, ErrInvalidOffset) {
		t.Fatalf("Read offset error=%v", err)
	}
	if _, err := device.Write([][]byte{make([]byte, 4)}, 4); !errors.Is(err, ErrInvalidOffset) {
		t.Fatalf("Write offset error=%v", err)
	}
}

type countingCloser struct {
	net.Conn
	closeCalls atomic.Int32
}

func (c *countingCloser) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func TestRuntimeStatsRecordRawPacketHeaders(t *testing.T) {
	ResetRuntimeStats()
	device, peer := newPipeDevice(t)

	ipv4 := []byte{0x45, 0x00, 0x00, 0x14}
	go func() { _, _ = peer.Write(ipv4) }()
	buf := make([]byte, 64)
	sizes := make([]int, 1)
	if packets, err := device.Read([][]byte{buf}, sizes, 0); err != nil || packets != 1 {
		t.Fatalf("Read packets=%d error=%v", packets, err)
	}

	ipv6 := []byte{0x60, 0x00, 0x00, 0x00}
	readDone := make(chan struct{})
	go func() {
		_, _ = peer.Read(make([]byte, 64))
		close(readDone)
	}()
	if packets, err := device.Write([][]byte{ipv6}, 0); err != nil || packets != 1 {
		t.Fatalf("Write packets=%d error=%v", packets, err)
	}
	<-readDone

	stats := GetRuntimeStats()
	if stats.ReadPackets != 1 || stats.WritePackets != 1 || stats.InvalidPackets != 0 {
		t.Fatalf("unexpected runtime stats: %+v", stats)
	}
	recordRuntimePacket([]byte{0x00}, true)
	if got := GetRuntimeStats(); got.InvalidPackets != 1 || got.ReadPackets != 2 {
		t.Fatalf("invalid packet stats: %+v", got)
	}
}
