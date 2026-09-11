package dns

import (
	"encoding/json"
	"testing"
)

type recordingMobileDNSManager struct{ configs []string }

func (m *recordingMobileDNSManager) ApplyDns(config string) {
	m.configs = append(m.configs, config)
}

func TestMobileHostManagerRequiresAdapter(t *testing.T) {
	if _, err := newMobileHostManager(nil); err == nil {
		t.Fatal("expected missing mobile DNS manager error")
	}
}

func TestMobileHostManagerAppliesSerializedConfig(t *testing.T) {
	adapter := &recordingMobileDNSManager{}
	manager, err := newMobileHostManager(adapter)
	if err != nil {
		t.Fatal(err)
	}
	config := HostDNSConfig{}
	if err := manager.applyDNSConfig(config, nil); err != nil {
		t.Fatal(err)
	}
	if len(adapter.configs) != 1 {
		t.Fatalf("ApplyDns calls = %d, want 1", len(adapter.configs))
	}
	var decoded HostDNSConfig
	if err := json.Unmarshal([]byte(adapter.configs[0]), &decoded); err != nil {
		t.Fatalf("invalid serialized DNS config: %v", err)
	}
}
