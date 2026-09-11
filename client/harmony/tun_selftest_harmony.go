//go:build harmony

package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/pion/transport/v3/vnet"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/harmony/fdtun"
	"github.com/netbirdio/netbird/client/iface"
	ifacedevice "github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal"
)

type harmonySelfTestFDProvider struct {
	fd            int
	lease         uint64
	consumedLease uint64
	releasedLease uint64
}

func (p *harmonySelfTestFDProvider) WaitTunFD(ctx context.Context) (int, error) {
	fd, _, err := p.WaitTunFDLease(ctx)
	return fd, err
}

func (p *harmonySelfTestFDProvider) WaitTunFDLease(ctx context.Context) (int, uint64, error) {
	select {
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	default:
		return p.fd, p.lease, nil
	}
}

func (p *harmonySelfTestFDProvider) TunFDConsumed() {
	p.consumedLease = p.lease
}

func (p *harmonySelfTestFDProvider) TunFDConsumedForLease(lease uint64) {
	p.consumedLease = lease
}

func (p *harmonySelfTestFDProvider) TunFDReleasedForLease(lease uint64) {
	p.releasedLease = lease
}

func runFDTunSelfTest() (string, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("create packet socketpair: %w", err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	device, err := fdtun.NewFromFD(pair[0], "nb-harmony-selftest", 1280)
	if err != nil {
		return "", fmt.Errorf("create fd adapter: %w", err)
	}

	outbound := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00}
	if _, err := unix.Write(pair[1], outbound); err != nil {
		_ = device.Close()
		return "", fmt.Errorf("queue outbound packet: %w", err)
	}
	readBuffer := make([]byte, 64)
	readSizes := make([]int, 1)
	readPackets, err := device.Read([][]byte{readBuffer}, readSizes, 8)
	if err != nil {
		_ = device.Close()
		return "", fmt.Errorf("adapter read: %w", err)
	}
	if readPackets != 1 || !bytes.Equal(readBuffer[8:8+readSizes[0]], outbound) {
		_ = device.Close()
		return "", fmt.Errorf("adapter read packet mismatch")
	}

	inbound := []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0x40}
	withHeadroom := append(make([]byte, 12), inbound...)
	writtenPackets, err := device.Write([][]byte{withHeadroom}, 12)
	if err != nil {
		_ = device.Close()
		return "", fmt.Errorf("adapter write: %w", err)
	}
	peerBuffer := make([]byte, 64)
	peerSize, err := unix.Read(pair[1], peerBuffer)
	if err != nil {
		_ = device.Close()
		return "", fmt.Errorf("read adapter packet: %w", err)
	}
	if writtenPackets != 1 || !bytes.Equal(peerBuffer[:peerSize], inbound) {
		_ = device.Close()
		return "", fmt.Errorf("adapter write packet mismatch")
	}

	if err := device.Close(); err != nil {
		return "", fmt.Errorf("close adapter: %w", err)
	}
	if err := device.Close(); err != nil {
		return "", fmt.Errorf("idempotent close: %w", err)
	}

	ownershipPacket := []byte{0x45, 0x00, 0x00, 0x04}
	if _, err := unix.Write(pair[0], ownershipPacket); err != nil {
		return "", fmt.Errorf("original fd was closed by adapter: %w", err)
	}
	ownerSize, err := unix.Read(pair[1], peerBuffer)
	if err != nil {
		return "", fmt.Errorf("read original fd ownership packet: %w", err)
	}
	if !bytes.Equal(peerBuffer[:ownerSize], ownershipPacket) {
		return "", fmt.Errorf("original fd ownership packet mismatch")
	}

	if err := verifyFDTunReadCancellation(); err != nil {
		return "", err
	}
	if err := verifyHarmonyInterfaceFactory(); err != nil {
		return "", err
	}
	if err := internal.HarmonyPolicySelfTest(); err != nil {
		return "", fmt.Errorf("Harmony platform policy: %w", err)
	}
	if _, err := runHarmonyPlatformAdapterSelfTest(); err != nil {
		return "", fmt.Errorf("Harmony platform adapter: %w", err)
	}
	return "raw packet read/write OK; duplicate ownership OK; close cancellation OK; Harmony interface factory OK; Harmony late-fd consumed/released lease acknowledgement OK; Harmony platform policy OK; Harmony initial NetworkMap preparation OK; Harmony platform adapter OK; NB_INITIAL_MAP_PREFETCH_SELFTEST_DONE; NB_RECONFIGURATION_SELFTEST_DONE; NB_LATE_FD_SELFTEST_DONE; NB_PLATFORM_ADAPTER_SELFTEST_DONE; NB_FDTUN_SELFTEST_DONE", nil
}

func verifyFDTunReadCancellation() error {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create cancellation socketpair: %w", err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	device, err := fdtun.NewFromFD(pair[0], "nb-harmony-cancel-selftest", 1280)
	if err != nil {
		return fmt.Errorf("create cancellation adapter: %w", err)
	}

	started := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		close(started)
		buffer := make([]byte, 64)
		_, readErr := device.Read([][]byte{buffer}, make([]int, 1), 0)
		readDone <- readErr
	}()
	<-started

	select {
	case earlyErr := <-readDone:
		_ = device.Close()
		return fmt.Errorf("adapter read returned before close: %v", earlyErr)
	case <-time.After(30 * time.Millisecond):
	}

	if err := device.Close(); err != nil {
		return fmt.Errorf("close cancellation adapter: %w", err)
	}
	select {
	case readErr := <-readDone:
		if readErr == nil {
			return fmt.Errorf("cancelled read returned nil error")
		}
	case <-time.After(2 * time.Second):
		return fmt.Errorf("close did not cancel adapter read")
	}
	return nil
}

func verifyHarmonyInterfaceFactory() error {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create interface socketpair: %w", err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	transportNet, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.0.2.10"},
	})
	if err != nil {
		return fmt.Errorf("create in-memory interface transport net: %w", err)
	}
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate interface private key: %w", err)
	}

	provider := &harmonySelfTestFDProvider{fd: pair[0], lease: 7}
	wgInterface, err := iface.NewWGIFace(iface.WGIFaceOpts{
		Context:      context.Background(),
		IFaceName:    "nb-harmony-iface-selftest",
		Address:      wgaddr.MustParseWGAddress("100.64.0.1/32"),
		WGPort:       0,
		WGPrivKey:    privateKey.String(),
		MTU:          iface.DefaultMTU,
		MobileArgs:   &ifacedevice.MobileIFaceArguments{TunFDProvider: provider},
		TransportNet: transportNet,
		DisableDNS:   true,
	})
	if err != nil {
		return fmt.Errorf("create HarmonyOS WGIFace: %w", err)
	}
	if !wgInterface.IsUserspaceBind() {
		return fmt.Errorf("HarmonyOS WGIFace did not select userspace bind")
	}
	if err := wgInterface.Create(); err != nil {
		_ = wgInterface.Close()
		return fmt.Errorf("create HarmonyOS fd-backed WireGuard device: %w", err)
	}
	if provider.consumedLease != provider.lease {
		_ = wgInterface.Close()
		return fmt.Errorf("HarmonyOS late-fd provider consumed lease = %d, want %d", provider.consumedLease, provider.lease)
	}
	if wgInterface.GetWGDevice() == nil || wgInterface.GetDevice() == nil {
		_ = wgInterface.Close()
		return fmt.Errorf("HarmonyOS WGIFace did not expose its userspace devices")
	}
	if err := wgInterface.Close(); err != nil {
		return fmt.Errorf("close HarmonyOS WGIFace: %w", err)
	}
	if provider.releasedLease != provider.lease {
		return fmt.Errorf("HarmonyOS late-fd provider released lease = %d, want %d", provider.releasedLease, provider.lease)
	}

	// WGIface closes only the duplicated fd through fdtun. The platform-owned
	// original must remain usable until VpnConnection destroys it.
	packet := []byte{0x45, 0x00, 0x00, 0x04}
	if _, err := unix.Write(pair[0], packet); err != nil {
		return fmt.Errorf("HarmonyOS WGIFace closed the platform fd: %w", err)
	}
	buffer := make([]byte, 64)
	n, err := unix.Read(pair[1], buffer)
	if err != nil {
		return fmt.Errorf("read interface ownership packet: %w", err)
	}
	if !bytes.Equal(buffer[:n], packet) {
		return fmt.Errorf("interface ownership packet mismatch")
	}
	return nil
}
