package device

import "context"

// TunFDProvider supplies a platform-owned tunnel fd when the mobile host has
// finished constructing its VPN configuration. Implementations must unblock
// when ctx is cancelled.
type TunFDProvider interface {
	WaitTunFD(ctx context.Context) (int, error)
}

// TunFDConsumptionNotifier is implemented by legacy providers that expose an
// acknowledgement after the consumer has successfully duplicated the
// platform-owned fd.
type TunFDConsumptionNotifier interface {
	TunFDConsumed()
}

// TunFDLeaseProvider atomically returns an fd and a monotonically increasing
// lease. The lease lets lifecycle acknowledgements reject callbacks from an
// older tunnel generation.
type TunFDLeaseProvider interface {
	WaitTunFDLease(ctx context.Context) (fd int, lease uint64, err error)
}

// TunFDLeaseLifecycleNotifier receives acknowledgements for the exact lease
// duplicated by a TunDevice. Consumed means dup succeeded; released means the
// duplicated transport was closed during Engine teardown.
type TunFDLeaseLifecycleNotifier interface {
	TunFDConsumedForLease(lease uint64)
	TunFDReleasedForLease(lease uint64)
}

type MobileIFaceArguments struct {
	TunAdapter    TunAdapter    // Android only
	TunFd         int           // iOS and HarmonyOS static-fd mode
	TunFDProvider TunFDProvider // HarmonyOS late-fd mode
}
