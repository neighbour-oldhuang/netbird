package main

import (
	"sort"
	"strings"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type peerDetailView struct {
	Name           string `json:"name"`
	IP             string `json:"ip"`
	ConnectionType string `json:"connectionType"`
	Connected      bool   `json:"connected"`
	Handshaked     bool   `json:"handshaked"`
}

type peerRuntimeView struct {
	Known            int              `json:"known"`
	Connected        int              `json:"connected"`
	P2PConnected     int              `json:"p2pConnected"`
	RelayedConnected int              `json:"relayedConnected"`
	WithHandshake    int              `json:"withHandshake"`
	AllowedIPs       int              `json:"allowedIPs"`
	RoutedPeers      int              `json:"routedPeers"`
	AssignedRoutes   int              `json:"assignedRoutes"`
	BytesTx          int64            `json:"bytesTx"`
	BytesRx          int64            `json:"bytesRx"`
	Details          []peerDetailView `json:"details"`
}

type routeDetailView struct {
	Prefix string `json:"prefix"`
	Via    string `json:"via"`
}

// appliedRouteDetails maps each route that is actually installed on the tunnel to
// the peer that advertises it, so the UI can show the gateway instead of a bare
// prefix. Routes without an advertising peer belong to the tunnel itself.
func appliedRouteDetails(recorder *peer.Status, routes []string) []routeDetailView {
	details := make([]routeDetailView, 0, len(routes))
	owners := make(map[string]string)
	if recorder != nil {
		for _, state := range recorder.GetPeerStates() {
			if state.Mux == nil {
				continue
			}
			name := peerDisplayName(state)
			for prefix := range state.GetRoutes() {
				if _, taken := owners[prefix]; !taken {
					owners[prefix] = name
				}
			}
		}
	}
	for _, prefix := range routes {
		details = append(details, routeDetailView{Prefix: prefix, Via: owners[prefix]})
	}
	return details
}

func peerConnectionType(state peer.State) string {
	if state.ConnStatus != peer.StatusConnected {
		return "-"
	}
	if state.Relayed {
		return "Relay"
	}
	return "P2P"
}

func peerDisplayName(state peer.State) string {
	if state.FQDN != "" {
		if host, _, found := strings.Cut(state.FQDN, "."); found && host != "" {
			return host
		}
		return state.FQDN
	}
	if state.IP != "" {
		return state.IP
	}
	return "peer"
}

func peerRuntimeSnapshot(recorder *peer.Status) peerRuntimeView {
	view := peerRuntimeView{}
	if recorder == nil {
		return view
	}
	// Pull fresh userspace WireGuard statistics before reading the recorder.
	// Connection state updates initialize these fields to zero and do not
	// otherwise refresh them on the Harmony status path.
	_ = recorder.RefreshWireGuardStats()
	if stats, err := recorder.PeersStatus(); err == nil && stats != nil {
		for _, state := range stats.Peers {
			view.AllowedIPs += len(state.AllowedIPs)
		}
	}
	states := recorder.GetPeerStates()
	view.Known = len(states)
	for _, state := range states {
		if state.Mux != nil {
			routes := state.GetRoutes()
			if len(routes) > 0 {
				view.RoutedPeers++
				view.AssignedRoutes += len(routes)
			}
		}
		if state.ConnStatus == peer.StatusConnected {
			view.Connected++
			if state.Relayed {
				view.RelayedConnected++
			} else {
				view.P2PConnected++
			}
		}
		if !state.LastWireguardHandshake.IsZero() {
			view.WithHandshake++
		}
		if state.BytesTx > 0 {
			view.BytesTx += state.BytesTx
		}
		if state.BytesRx > 0 {
			view.BytesRx += state.BytesRx
		}
		view.Details = append(view.Details, peerDetailView{
			Name:           peerDisplayName(state),
			IP:             state.IP,
			ConnectionType: peerConnectionType(state),
			Connected:      state.ConnStatus == peer.StatusConnected,
			Handshaked:     !state.LastWireguardHandshake.IsZero(),
		})
	}
	sort.SliceStable(view.Details, func(i, j int) bool {
		if view.Details[i].Connected != view.Details[j].Connected {
			return view.Details[i].Connected
		}
		return view.Details[i].Name < view.Details[j].Name
	})
	return view
}
