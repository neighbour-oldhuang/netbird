package internal

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/route"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type initialMapPlatformRecorder struct {
	mu       sync.Mutex
	routes   []string
	dnsCalls []string
}

func (r *initialMapPlatformRecorder) OnNetworkChanged(routes string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = append(r.routes, routes)
}
func (r *initialMapPlatformRecorder) SetInterfaceIP(string)   {}
func (r *initialMapPlatformRecorder) SetInterfaceIPv6(string) {}
func (r *initialMapPlatformRecorder) ApplyDns(raw string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dnsCalls = append(r.dnsCalls, raw)
}

func newInitialMapTestEngine(t *testing.T, managementClient mgm.Client, recorder *initialMapPlatformRecorder) (*Engine, context.CancelFunc) {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	address := wgaddr.MustParseWGAddress("100.64.10.1/24")
	engine := NewEngine(ctx, cancel, &EngineConfig{
		WgAddr:       address,
		WgPrivateKey: key,
		WgIfaceName:  "nb-prefetch",
		MTU:          1280,
	}, EngineServices{MgmClient: managementClient}, MobileDependency{
		Platform:              MobilePlatformHarmony,
		NetworkChangeListener: recorder,
		DnsManager:            recorder,
	})
	engine.wgInterface = &MockWGIface{AddressFunc: func() wgaddr.Address { return address }}
	engine.dnsServer = &dns.MockServer{}
	return engine, cancel
}

func initialMapFixture() *mgmProto.NetworkMap {
	return &mgmProto.NetworkMap{
		Serial: 7,
		Routes: []*mgmProto.Route{{
			ID: "route-a", Network: "10.20.0.0/16", NetID: "corp", Peer: "remote", NetworkType: 1,
		}},
		DNSConfig: &mgmProto.DNSConfig{
			ServiceEnable: true,
			CustomZones:   []*mgmProto.CustomZone{{Domain: "corp.example.com."}},
		},
	}
}

func TestPrepareInitialNetworkMapPublishesRoutesAndDNSWithoutApplying(t *testing.T) {
	recorder := &initialMapPlatformRecorder{}
	engine, cancel := newInitialMapTestEngine(t, &mgm.MockClient{}, recorder)
	defer cancel()

	var preparedRoutes int
	engine.routeManager = &routemanager.MockManager{
		PrepareRouteRangesFunc: func(routes []*route.Route) []string {
			preparedRoutes++
			require.Len(t, routes, 1)
			return []string{"10.20.0.0/16"}
		},
		UpdateRoutesFunc: func(uint64, map[route.ID]*route.Route, route.HAMap, bool) error {
			t.Fatal("prefetch must not apply route handlers")
			return nil
		},
	}

	require.NoError(t, engine.prepareInitialNetworkMap(initialMapFixture()))
	require.Equal(t, 1, preparedRoutes)
	require.Equal(t, []string{"10.20.0.0/16"}, recorder.routes)
	require.Len(t, recorder.dnsCalls, 1)
	var hostConfig dns.HostDNSConfig
	require.NoError(t, json.Unmarshal([]byte(recorder.dnsCalls[0]), &hostConfig))
	require.Equal(t, netip.MustParseAddr("100.10.254.255"), hostConfig.ServerIP)
	require.Equal(t, "corp.example.com.", hostConfig.Domains[0].Domain)
}

func TestPrefetchInitialNetworkMapUsesOneStreamAndDefersReplay(t *testing.T) {
	recorder := &initialMapPlatformRecorder{}
	streamExited := make(chan struct{})
	client := &mgm.MockClient{SyncFunc: func(ctx context.Context, _ *system.Info, handler func(*mgmProto.SyncResponse) error) error {
		defer close(streamExited)
		require.NoError(t, handler(&mgmProto.SyncResponse{NetbirdConfig: &mgmProto.NetbirdConfig{}}))
		return handler(&mgmProto.SyncResponse{NetworkMap: initialMapFixture()})
	}}
	engine, cancel := newInitialMapTestEngine(t, client, recorder)
	engine.routeManager = &routemanager.MockManager{PrepareRouteRangesFunc: func([]*route.Route) []string {
		return []string{"10.20.0.0/16"}
	}}

	// Start holds this lock while prefetching. The stream callback must publish
	// the prepared projection, report success, then block here until startup is
	// ready to replay the retained responses through handleSync.
	engine.syncMsgMux.Lock()
	require.NoError(t, engine.prefetchInitialNetworkMap(time.Second))
	require.True(t, engine.managementStreamStarted)
	require.Equal(t, []string{"10.20.0.0/16"}, recorder.routes)
	require.Len(t, recorder.dnsCalls, 1)

	cancel()
	engine.syncMsgMux.Unlock()
	select {
	case <-streamExited:
	case <-time.After(time.Second):
		t.Fatal("management stream did not unblock after cancellation")
	}
}

func TestPrefetchInitialNetworkMapTimeoutCancelsStream(t *testing.T) {
	recorder := &initialMapPlatformRecorder{}
	client := &mgm.MockClient{SyncFunc: func(ctx context.Context, _ *system.Info, _ func(*mgmProto.SyncResponse) error) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	engine, _ := newInitialMapTestEngine(t, client, recorder)

	err := engine.prefetchInitialNetworkMap(20 * time.Millisecond)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "context canceled"))
	require.Error(t, engine.ctx.Err())
	require.Empty(t, recorder.routes)
	require.Empty(t, recorder.dnsCalls)
}
