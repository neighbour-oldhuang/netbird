package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/internal/peer"
)

func TestPeerRuntimeSnapshotAggregatesWithoutIdentifiers(t *testing.T) {
	recorder := peer.NewRecorder("")
	const publicKey = "synthetic-public-key"
	const fqdn = "peer.example.test"
	const address = "192.0.2.10"
	if err := recorder.AddPeer(publicKey, fqdn, address, ""); err != nil {
		t.Fatalf("add peer: %v", err)
	}
	if err := recorder.UpdatePeerState(peer.State{
		PubKey:     publicKey,
		ConnStatus: peer.StatusConnected,
	}); err != nil {
		t.Fatalf("update peer state: %v", err)
	}
	if err := recorder.UpdateWireGuardPeerState(publicKey, configurer.WGStats{
		LastHandshake: time.Now(),
		TxBytes:       123,
		RxBytes:       456,
	}); err != nil {
		t.Fatalf("update WireGuard state: %v", err)
	}

	got := peerRuntimeSnapshot(recorder)
	if got.Known != 1 || got.Connected != 1 || got.P2PConnected != 1 || got.RelayedConnected != 0 ||
		got.WithHandshake != 1 || got.BytesTx != 123 || got.BytesRx != 456 {
		t.Fatalf("unexpected peer runtime summary: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal peer runtime summary: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, publicKey) {
		t.Fatalf("peer runtime summary leaked the WireGuard public key")
	}
	if !strings.Contains(text, address) {
		t.Fatalf("peer runtime summary is missing the peer IP required by the UI")
	}
	if len(got.Details) != 1 || got.Details[0].ConnectionType != "P2P" ||
		got.Details[0].IP != address || got.Details[0].Name != "peer" ||
		!got.Details[0].Connected || !got.Details[0].Handshaked {
		t.Fatalf("unexpected peer detail: %+v", got.Details)
	}
	_ = fqdn
}

func TestPeerRuntimeSnapshotSeparatesP2PAndRelay(t *testing.T) {
	recorder := peer.NewRecorder("")
	for _, item := range []struct {
		key     string
		address string
		relayed bool
	}{
		{key: "p2p-key", address: "192.0.2.11", relayed: false},
		{key: "relay-key", address: "192.0.2.12", relayed: true},
	} {
		if err := recorder.AddPeer(item.key, item.key+".example.test", item.address, ""); err != nil {
			t.Fatalf("add peer: %v", err)
		}
		if err := recorder.UpdatePeerState(peer.State{
			PubKey:     item.key,
			ConnStatus: peer.StatusConnected,
			Relayed:    item.relayed,
		}); err != nil {
			t.Fatalf("update peer state: %v", err)
		}
	}

	got := peerRuntimeSnapshot(recorder)
	if got.Connected != 2 || got.P2PConnected != 1 || got.RelayedConnected != 1 {
		t.Fatalf("unexpected connection type summary: %+v", got)
	}
}

func TestPeerRuntimeSnapshotNilRecorder(t *testing.T) {
	got := peerRuntimeSnapshot(nil)
	if got.Known != 0 || got.Connected != 0 || got.P2PConnected != 0 || got.RelayedConnected != 0 ||
		got.WithHandshake != 0 || got.BytesTx != 0 || got.BytesRx != 0 {
		t.Fatalf("unexpected nil-recorder summary: %+v", got)
	}
}
