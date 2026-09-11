package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestPrepareRouteRanges(t *testing.T) {
	manager := &DefaultManager{
		pubKey:        "local-peer",
		routeSelector: routeselector.NewRouteSelector(),
	}

	routes := []*route.Route{
		{ID: "lan-a", NetID: "lan", Network: netip.MustParsePrefix("10.20.0.0/16"), NetworkType: route.IPv4Network, Peer: "remote-a", Enabled: true},
		{ID: "lan-b", NetID: "lan", Network: netip.MustParsePrefix("10.20.0.0/16"), NetworkType: route.IPv4Network, Peer: "remote-b", Enabled: true},
		{ID: "server", NetID: "owned", Network: netip.MustParsePrefix("10.30.0.0/16"), NetworkType: route.IPv4Network, Peer: "local-peer", Enabled: true},
		{ID: "domain", NetID: "domain", Domains: domain.List{"corp.example.com"}, NetworkType: route.DomainNetwork, Peer: "remote-a", Enabled: true},
	}

	got := manager.PrepareRouteRanges(routes)
	require.Equal(t, []string{"10.20.0.0/16"}, got)
	require.Len(t, manager.clientRoutes, 2, "static and dynamic client route groups are cached for replay")
	require.Empty(t, manager.activeRoutes, "preparation must not create route handlers")
}

func TestPrepareRouteRangesHonorsDisableClientRoutes(t *testing.T) {
	manager := &DefaultManager{
		pubKey:              "local-peer",
		routeSelector:       routeselector.NewRouteSelector(),
		disableClientRoutes: true,
	}

	got := manager.PrepareRouteRanges([]*route.Route{{
		ID: "lan", NetID: "lan", Network: netip.MustParsePrefix("10.20.0.0/16"),
		NetworkType: route.IPv4Network, Peer: "remote", Enabled: true,
	}})
	require.Empty(t, got)
	require.Len(t, manager.clientRoutes, 1, "model remains available while platform routes stay disabled")
}
