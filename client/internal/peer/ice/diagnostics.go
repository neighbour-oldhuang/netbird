package ice

import "sync/atomic"

type Diagnostics struct {
	AgentsCreated    uint64
	OffersReceived   uint64
	GatherStarted    uint64
	GatherFailed     uint64
	LocalCandidates  uint64
	RemoteCandidates uint64
}

var (
	diagnosticAgentsCreated    atomic.Uint64
	diagnosticOffersReceived   atomic.Uint64
	diagnosticGatherStarted    atomic.Uint64
	diagnosticGatherFailed     atomic.Uint64
	diagnosticLocalCandidates  atomic.Uint64
	diagnosticRemoteCandidates atomic.Uint64
)

func RecordAgentCreated() {
	diagnosticAgentsCreated.Add(1)
}

func RecordOfferReceived() {
	diagnosticOffersReceived.Add(1)
}

func RecordGatherStarted() {
	diagnosticGatherStarted.Add(1)
}

func RecordGatherFailed() {
	diagnosticGatherFailed.Add(1)
}

func RecordLocalCandidate() {
	diagnosticLocalCandidates.Add(1)
}

func RecordRemoteCandidate() {
	diagnosticRemoteCandidates.Add(1)
}

func DiagnosticSnapshot() Diagnostics {
	return Diagnostics{
		AgentsCreated:    diagnosticAgentsCreated.Load(),
		OffersReceived:   diagnosticOffersReceived.Load(),
		GatherStarted:    diagnosticGatherStarted.Load(),
		GatherFailed:     diagnosticGatherFailed.Load(),
		LocalCandidates:  diagnosticLocalCandidates.Load(),
		RemoteCandidates: diagnosticRemoteCandidates.Load(),
	}
}
