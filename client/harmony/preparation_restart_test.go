package main

import "testing"

// A rolled-back preparation must be restartable so that an explicit reconnect
// after Disconnect does not fail with "core preparation stopped: rolled-back".
func TestBeginPreparationCycleClearsTerminalState(t *testing.T) {
	for _, terminal := range []string{"rolled-back", "cancelled"} {
		adapter := newHarmonyPlatformAdapter()
		adapter.preparationState = terminal
		adapter.beginPreparationCycle()
		if got := adapter.snapshot().PreparationState; got != "idle" {
			t.Fatalf("preparation state after reset from %q = %q, want idle", terminal, got)
		}
	}
}

func TestBeginPreparationCycleClearsReconfigurationTerminalState(t *testing.T) {
	adapter := newHarmonyPlatformAdapter()
	adapter.preparationState = "rolled-back"
	adapter.reconfigurationState = "rolled-back"
	adapter.reconfigurationTarget = 7
	adapter.beginPreparationCycle()
	snapshot := adapter.snapshot()
	if snapshot.ReconfigurationState != "idle" || snapshot.ReconfigurationTargetRevision != 0 {
		t.Fatalf("reconfiguration state = %q target = %d, want idle/0",
			snapshot.ReconfigurationState, snapshot.ReconfigurationTargetRevision)
	}
}

func TestBeginPreparationCycleKeepsActivePreparation(t *testing.T) {
	adapter := newHarmonyPlatformAdapter()
	adapter.preparationState = "awaiting-fd"
	adapter.beginPreparationCycle()
	if got := adapter.snapshot().PreparationState; got != "awaiting-fd" {
		t.Fatalf("active preparation state = %q, want awaiting-fd", got)
	}
}
