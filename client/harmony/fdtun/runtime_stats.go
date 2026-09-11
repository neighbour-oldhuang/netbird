package fdtun

import "sync/atomic"

// RuntimeStats contains process-local evidence from the most recently reset
// fd-backed TUN run. It never includes packet contents or addresses.
type RuntimeStats struct {
	NonblockingVerified bool   `json:"nonblockingVerified"`
	ReadPackets         uint64 `json:"readPackets"`
	WritePackets        uint64 `json:"writePackets"`
	InvalidPackets      uint64 `json:"invalidPackets"`
}

var (
	runtimeNonblocking    atomic.Bool
	runtimeReadPackets    atomic.Uint64
	runtimeWritePackets   atomic.Uint64
	runtimeInvalidPackets atomic.Uint64
)

// ResetRuntimeStats starts a new evidence window before a real fd handoff.
func ResetRuntimeStats() {
	runtimeNonblocking.Store(false)
	runtimeReadPackets.Store(0)
	runtimeWritePackets.Store(0)
	runtimeInvalidPackets.Store(0)
}

// GetRuntimeStats returns counters only; raw packets are never retained.
func GetRuntimeStats() RuntimeStats {
	return RuntimeStats{
		NonblockingVerified: runtimeNonblocking.Load(),
		ReadPackets:         runtimeReadPackets.Load(),
		WritePackets:        runtimeWritePackets.Load(),
		InvalidPackets:      runtimeInvalidPackets.Load(),
	}
}

func markRuntimeNonblockingVerified() {
	runtimeNonblocking.Store(true)
}

func recordRuntimePacket(packet []byte, read bool) {
	if read {
		runtimeReadPackets.Add(1)
	} else {
		runtimeWritePackets.Add(1)
	}
	if len(packet) == 0 {
		runtimeInvalidPackets.Add(1)
		return
	}
	version := packet[0] >> 4
	if version != 4 && version != 6 {
		runtimeInvalidPackets.Add(1)
	}
}
