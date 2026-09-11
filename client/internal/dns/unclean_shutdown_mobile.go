//go:build ios || android || harmony

package dns

type ShutdownState struct {
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	return nil
}
