package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/harmony/fdtun"
	"github.com/netbirdio/netbird/client/harmony/netbinding"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/peer"
	peerice "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/version"
)

const (
	apiOK                   = 0
	apiInvalidArgument      = -1
	apiInvalidConfig        = -2
	apiNotInitialized       = -3
	apiCredentialInvalid    = -4
	apiAuthenticationFailed = -5
	apiPlatformNotReady     = -100
	apiTunSelfTestFailed    = -101
	harmonyAuthTimeout      = 45 * time.Second
	harmonyOSName           = "HarmonyOS"
	harmonyCorePhase        = "core-ready-platform-pending"
	harmonyPartialPhase     = "platform-adapter-partial"
	harmonyReadyPhase       = "platform-ready-engine-stopped"
	defaultHarmonyDevice    = "HarmonyOS Device"
	defaultHarmonyOSVersion = "unknown"
)

type apiEnvelope struct {
	OK      bool        `json:"ok"`
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type configView struct {
	ManagementURL        string `json:"managementUrl"`
	AdminURL             string `json:"adminUrl"`
	WireGuardInterface   string `json:"wireGuardInterface"`
	WireGuardPort        int    `json:"wireGuardPort"`
	PrivateKeyConfigured bool   `json:"privateKeyConfigured"`
	DisableDNS           bool   `json:"disableDns"`
	DisableClientRoutes  bool   `json:"disableClientRoutes"`
	DisableServerRoutes  bool   `json:"disableServerRoutes"`
}

type authenticationView struct {
	State      string `json:"state"`
	Running    bool   `json:"running"`
	Configured bool   `json:"configured"`
	Persistent bool   `json:"persistent"`
	LastError  string `json:"lastError,omitempty"`
}

type platformView struct {
	VpnExtensionReady             bool   `json:"vpnExtensionReady"`
	ProcessProtectReady           bool   `json:"processProtectReady"`
	TunFDReady                    bool   `json:"tunFdReady"`
	DNSReady                      bool   `json:"dnsReady"`
	NetworkChangeReady            bool   `json:"networkChangeReady"`
	PreparationRunning            bool   `json:"preparationRunning"`
	PreparationState              string `json:"preparationState"`
	PreparationGeneration         uint64 `json:"preparationGeneration"`
	ConfigRevision                uint64 `json:"configRevision"`
	AppliedConfigRevision         uint64 `json:"appliedConfigRevision"`
	ReconfigurationGeneration     uint64 `json:"reconfigurationGeneration"`
	ReconfigurationState          string `json:"reconfigurationState"`
	ReconfigurationTargetRevision uint64 `json:"reconfigurationTargetRevision"`
	LastError                     string `json:"lastError,omitempty"`
}

type networkMapRuntimeView struct {
	AdvertisedSyncVersion int32 `json:"advertisedSyncVersion"`
	SyncVersion           int32 `json:"syncVersion"`
	DecodedRoutes         int   `json:"decodedRoutes"`
	NetworkResources      int   `json:"networkResources"`
	NetworkRouters        int   `json:"networkRouters"`
	ResourcePolicies      int   `json:"resourcePolicies"`
}

type networkBindingView struct {
	Attempts  uint64 `json:"attempts"`
	Succeeded uint64 `json:"succeeded"`
	Failed    uint64 `json:"failed"`
}

type iceDiagnosticsView struct {
	AgentsCreated    uint64 `json:"agentsCreated"`
	OffersReceived   uint64 `json:"offersReceived"`
	GatherStarted    uint64 `json:"gatherStarted"`
	GatherFailed     uint64 `json:"gatherFailed"`
	LocalCandidates  uint64 `json:"localCandidates"`
	RemoteCandidates uint64 `json:"remoteCandidates"`
}

type coreView struct {
	Initialized         bool                  `json:"initialized"`
	Phase               string                `json:"phase"`
	ClientStatus        string                `json:"clientStatus"`
	EngineRunning       bool                  `json:"engineRunning"`
	ManagementConnected bool                  `json:"managementConnected"`
	ManagementErrorCode string                `json:"managementErrorCode,omitempty"`
	SignalConnected     bool                  `json:"signalConnected"`
	SignalErrorCode     string                `json:"signalErrorCode,omitempty"`
	Peers               peerRuntimeView       `json:"peers"`
	AppliedRoutes       []routeDetailView     `json:"appliedRoutes"`
	ResolvedDomains     []resolvedDomainView  `json:"resolvedDomains,omitempty"`
	TunnelAddresses     []string              `json:"tunnelAddresses"`
	DNSAddresses        []string              `json:"dnsAddresses"`
	PreDNSAddress       string                `json:"preDnsAddress,omitempty"`
	NetworkMap          networkMapRuntimeView `json:"networkMap"`
	NetworkBinding      networkBindingView    `json:"networkBinding"`
	ICEDiagnostics      iceDiagnosticsView    `json:"iceDiagnostics"`
	PlatformReady       bool                  `json:"platformReady"`
	Platform            platformView          `json:"platform"`
	Authentication      authenticationView    `json:"authentication"`
	MissingCapabilities []string              `json:"missingCapabilities,omitempty"`
	DeviceName          string                `json:"deviceName,omitempty"`
	OSName              string                `json:"osName"`
	OSVersion           string                `json:"osVersion"`
	NetBirdVersion      string                `json:"netBirdVersion"`
	NetBirdCommit       string                `json:"netBirdCommit,omitempty"`
	Config              *configView           `json:"config,omitempty"`
}

type harmonyCore struct {
	mu                    sync.RWMutex
	client                *internal.ConnectClient
	config                *profilemanager.Config
	recorder              *peer.Status
	netEvents             *netevents.Manager
	platformAdapter       *harmonyPlatformAdapter
	deviceName            string
	osVersion             string
	tunFD                 int
	vpnExtensionReady     bool
	processProtectReady   bool
	dnsReady              bool
	networkChangeReady    bool
	preparationRunning    bool
	preparationStarted    bool
	preparationID         uint64
	platformLastError     string
	authenticationState   string
	authenticationError   string
	authenticationRun     bool
	privateConfigured     bool
	privatePersistent     bool
	managementDialAddress string
	authenticationID      uint64
	authenticationCancel  context.CancelFunc
}

var core = harmonyCore{tunFD: -1, authenticationState: "not-configured"}

func cString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

func jsonCString(ok bool, code int, message string, data interface{}) *C.char {
	payload, err := json.Marshal(apiEnvelope{
		OK:      ok,
		Code:    code,
		Message: message,
		Data:    data,
	})
	if err != nil {
		return C.CString(`{"ok":false,"code":-1,"message":"failed to encode response"}`)
	}
	return C.CString(string(payload))
}

func safeExport(fn func() *C.char) (result *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = jsonCString(false, apiInvalidArgument, fmt.Sprintf("panic recovered: %v", recovered), nil)
		}
	}()
	return fn()
}

func configSnapshot(cfg *profilemanager.Config) *configView {
	if cfg == nil {
		return nil
	}

	managementURL := ""
	if cfg.ManagementURL != nil {
		managementURL = cfg.ManagementURL.String()
	}
	adminURL := ""
	if cfg.AdminURL != nil {
		adminURL = cfg.AdminURL.String()
	}

	return &configView{
		ManagementURL:        managementURL,
		AdminURL:             adminURL,
		WireGuardInterface:   cfg.WgIface,
		WireGuardPort:        cfg.WgPort,
		PrivateKeyConfigured: cfg.PrivateKey != "",
		DisableDNS:           cfg.DisableDNS,
		DisableClientRoutes:  cfg.DisableClientRoutes,
		DisableServerRoutes:  cfg.DisableServerRoutes,
	}
}

func (c *harmonyCore) snapshotLocked() coreView {
	adapterSnapshot := harmonyPlatformSnapshot{PreparationState: "idle", ReconfigurationState: "idle"}
	if c.platformAdapter != nil {
		adapterSnapshot = c.platformAdapter.snapshot()
	}
	platform := platformView{
		VpnExtensionReady:             c.vpnExtensionReady,
		ProcessProtectReady:           c.processProtectReady,
		TunFDReady:                    c.tunFD >= 0,
		DNSReady:                      c.dnsReady,
		NetworkChangeReady:            c.networkChangeReady,
		PreparationRunning:            c.preparationRunning,
		PreparationState:              adapterSnapshot.PreparationState,
		PreparationGeneration:         adapterSnapshot.PreparationGeneration,
		ConfigRevision:                adapterSnapshot.ConfigRevision,
		AppliedConfigRevision:         adapterSnapshot.AppliedConfigRevision,
		ReconfigurationGeneration:     adapterSnapshot.ReconfigurationGeneration,
		ReconfigurationState:          adapterSnapshot.ReconfigurationState,
		ReconfigurationTargetRevision: adapterSnapshot.ReconfigurationTargetRevision,
		LastError:                     c.platformLastError,
	}

	missing := make([]string, 0, 5)
	if !platform.VpnExtensionReady {
		missing = append(missing, "vpn-extension-lifecycle")
	}
	if !platform.TunFDReady {
		missing = append(missing, "vpn-extension-tun-fd")
	}
	if !platform.ProcessProtectReady {
		missing = append(missing, "socket-protect-or-bypass")
	}
	if !platform.DNSReady {
		missing = append(missing, "dns-manager")
	}
	if !platform.NetworkChangeReady {
		missing = append(missing, "network-change-listener")
	}
	platformReady := len(missing) == 0

	phase := harmonyCorePhase
	if platformReady {
		phase = harmonyReadyPhase
	} else if platform.VpnExtensionReady || platform.ProcessProtectReady || platform.TunFDReady {
		phase = harmonyPartialPhase
	}

	authenticationState := c.authenticationState
	if authenticationState == "" {
		authenticationState = "not-configured"
	}
	if c.privateConfigured && (adapterSnapshot.PreparationState == "awaiting-fd" ||
		adapterSnapshot.PreparationState == "fd-provided" ||
		adapterSnapshot.PreparationState == "fd-received" ||
		adapterSnapshot.PreparationState == "fd-consumed") {
		authenticationState = "network-map-ready"
	}

	attempts, succeeded, failed := netbinding.Stats()
	iceDiagnostics := peerice.DiagnosticSnapshot()
	view := coreView{
		Initialized:     c.client != nil,
		Phase:           phase,
		ClientStatus:    string(internal.StatusIdle),
		EngineRunning:   false,
		Peers:           peerRuntimeSnapshot(c.recorder),
		AppliedRoutes:   appliedRouteDetails(c.recorder, adapterSnapshot.Routes),
		ResolvedDomains: resolvedDomainDetails(c.recorder),
		TunnelAddresses: adapterSnapshot.Addresses,
		DNSAddresses:    adapterSnapshot.DNSAddresses,
		PreDNSAddress:   adapterSnapshot.PreDNSAddress,
		NetworkBinding: networkBindingView{
			Attempts:  attempts,
			Succeeded: succeeded,
			Failed:    failed,
		},
		ICEDiagnostics: iceDiagnosticsView{
			AgentsCreated:    iceDiagnostics.AgentsCreated,
			OffersReceived:   iceDiagnostics.OffersReceived,
			GatherStarted:    iceDiagnostics.GatherStarted,
			GatherFailed:     iceDiagnostics.GatherFailed,
			LocalCandidates:  iceDiagnostics.LocalCandidates,
			RemoteCandidates: iceDiagnostics.RemoteCandidates,
		},
		PlatformReady: platformReady,
		Platform:      platform,
		Authentication: authenticationView{
			State:      authenticationState,
			Running:    c.authenticationRun,
			Configured: c.privateConfigured,
			Persistent: c.privatePersistent,
			LastError:  c.authenticationError,
		},
		MissingCapabilities: missing,
		DeviceName:          c.deviceName,
		OSName:              harmonyOSName,
		OSVersion:           c.osVersion,
		NetBirdVersion:      version.NetbirdVersion(),
		NetBirdCommit:       version.NetbirdCommit(),
		Config:              configSnapshot(c.config),
	}
	if c.client != nil {
		view.ClientStatus = string(c.client.Status())
		engine := c.client.Engine()
		view.EngineRunning = engine != nil
		if engine != nil {
			summary := engine.NetworkMapRuntimeSummary()
			view.NetworkMap = networkMapRuntimeView{
				AdvertisedSyncVersion: summary.AdvertisedSyncVersion,
				SyncVersion:           summary.SyncVersion,
				DecodedRoutes:         summary.DecodedRoutes,
				NetworkResources:      summary.NetworkResources,
				NetworkRouters:        summary.NetworkRouters,
				ResourcePolicies:      summary.ResourcePolicies,
			}
		}
	}
	if c.recorder != nil {
		managementState := c.recorder.GetManagementState()
		view.ManagementConnected = managementState.Connected
		if managementState.Error != nil {
			if grpcStatus, ok := status.FromError(managementState.Error); ok {
				view.ManagementErrorCode = grpcStatus.Code().String()
			} else {
				view.ManagementErrorCode = "transport-error"
			}
		}
		signalState := c.recorder.GetSignalState()
		view.SignalConnected = signalState.Connected
		if signalState.Error != nil {
			if grpcStatus, ok := status.FromError(signalState.Error); ok {
				view.SignalErrorCode = grpcStatus.Code().String()
			} else {
				view.SignalErrorCode = "transport-error"
			}
		}
	}
	return view
}

type harmonyClientBundle struct {
	client    *internal.ConnectClient
	config    *profilemanager.Config
	recorder  *peer.Status
	netEvents *netevents.Manager
}

func buildHarmonyClient(deviceName, osVersion, configJSON string) (*harmonyClientBundle, string, string, error) {
	return buildHarmonyClientWithDialAddress(deviceName, osVersion, configJSON, "")
}

func buildHarmonyClientWithDialAddress(deviceName, osVersion, configJSON, managementDialAddress string) (*harmonyClientBundle, string, string, error) {
	if strings.TrimSpace(configJSON) == "" {
		configJSON = "{}"
	}
	cfg, err := profilemanager.ConfigFromJSON(configJSON)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid NetBird config: %w", err)
	}

	if strings.TrimSpace(deviceName) == "" {
		deviceName = defaultHarmonyDevice
	}
	if strings.TrimSpace(osVersion) == "" {
		osVersion = defaultHarmonyOSVersion
	}

	recorder := peer.NewRecorder("")
	if cfg.ManagementURL != nil {
		recorder.UpdateManagementAddress(cfg.ManagementURL.String())
	}
	recorder.UpdateRosenpass(cfg.RosenpassEnabled, cfg.RosenpassPermissive)
	netEvents := netevents.NewManager(recorder)

	ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, deviceName)
	ctx = context.WithValue(ctx, system.OsNameCtxKey, harmonyOSName)
	ctx = context.WithValue(ctx, system.OsVersionCtxKey, osVersion)
	if managementDialAddress != "" {
		ctx = mgm.ContextWithDialAddress(ctx, managementDialAddress)
		ctx = signal.ContextWithDialAddress(ctx, managementDialAddress)
	}
	ctx = internal.CtxInitState(ctx)
	client := internal.NewConnectClient(ctx, cfg, recorder, internal.WithNetEvents(netEvents))
	return &harmonyClientBundle{client: client, config: cfg, recorder: recorder, netEvents: netEvents}, deviceName, osVersion, nil
}

func (c *harmonyCore) installClientBundleLocked(bundle *harmonyClientBundle, deviceName, osVersion string) {
	if c.platformAdapter == nil {
		c.platformAdapter = newHarmonyPlatformAdapter()
	} else {
		c.platformAdapter.rollbackDesired()
	}
	c.preparationID++
	c.preparationRunning = false
	c.preparationStarted = false
	if c.client != nil {
		_ = c.client.Stop()
	}
	c.client = bundle.client
	c.config = bundle.config
	c.recorder = bundle.recorder
	c.netEvents = bundle.netEvents
	c.deviceName = deviceName
	c.osVersion = osVersion
}

func (c *harmonyCore) replaceClientLocked(deviceName, osVersion, configJSON string) error {
	bundle, deviceName, osVersion, err := buildHarmonyClient(deviceName, osVersion, configJSON)
	if err != nil {
		return err
	}
	c.installClientBundleLocked(bundle, deviceName, osVersion)
	return nil
}

// rebuildClientForReconnectLocked recreates the ConnectClient so an explicit
// reconnect after Disconnect can run the engine again. A ConnectClient whose run
// already finished cannot be reused: a second run returns immediately without
// waiting for the tunnel fd, which makes every reconnect time out. The persisted
// profile configuration is reused, so the peer keeps its existing identity.
func (c *harmonyCore) rebuildClientForReconnectLocked() error {
	if c.config == nil {
		return errors.New("HarmonyOS core configuration is unavailable for reconnect")
	}
	recorder := peer.NewRecorder("")
	if c.config.ManagementURL != nil {
		recorder.UpdateManagementAddress(c.config.ManagementURL.String())
	}
	recorder.UpdateRosenpass(c.config.RosenpassEnabled, c.config.RosenpassPermissive)
	netEvents := netevents.NewManager(recorder)

	ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	ctx = context.WithValue(ctx, system.OsNameCtxKey, harmonyOSName)
	ctx = context.WithValue(ctx, system.OsVersionCtxKey, c.osVersion)
	if c.managementDialAddress != "" {
		ctx = mgm.ContextWithDialAddress(ctx, c.managementDialAddress)
		ctx = signal.ContextWithDialAddress(ctx, c.managementDialAddress)
	}
	ctx = internal.CtxInitState(ctx)
	client := internal.NewConnectClient(ctx, c.config, recorder, internal.WithNetEvents(netEvents))

	if c.client != nil {
		_ = c.client.Stop()
	}
	c.preparationID++
	c.preparationRunning = false
	c.preparationStarted = false
	c.platformLastError = ""
	c.tunFD = -1
	c.client = client
	c.recorder = recorder
	c.netEvents = netEvents
	return nil
}

func (c *harmonyCore) clearPlatformLocked() {
	if c.authenticationCancel != nil {
		c.authenticationCancel()
		c.authenticationCancel = nil
		c.authenticationID++
		c.authenticationRun = false
		if c.authenticationState == "authenticating" {
			c.authenticationState = "cancelled"
		}
	}
	c.tunFD = -1
	c.vpnExtensionReady = false
	c.processProtectReady = false
	c.dnsReady = false
	c.networkChangeReady = false
	c.preparationRunning = false
	c.preparationStarted = false
	c.platformLastError = ""
	if c.platformAdapter != nil {
		c.platformAdapter.rollbackDesired()
	}
}

func (c *harmonyCore) startPreparationLocked(
	client *internal.ConnectClient,
	adapter *harmonyPlatformAdapter,
	statePath, cachePath, logPath string,
	reconfigurationGeneration uint64,
) coreView {
	c.preparationID++
	preparationID := c.preparationID
	adapter.beginPreparationCycle()
	c.preparationRunning = true
	c.preparationStarted = true
	c.platformLastError = ""
	view := c.snapshotLocked()

	startedAt := time.Now()
	go func() {
		err := client.RunOnHarmonyWithFDProvider(
			adapter,
			adapter,
			adapter,
			adapter,
			statePath,
			cachePath,
			logPath,
		)

		c.mu.Lock()
		if c.preparationID != preparationID || c.client != client {
			c.mu.Unlock()
			return
		}

		// Only the goroutine that still owns the current preparation may mutate
		// adapter state. A stale Engine stopped for reconfiguration must not erase
		// the next generation's desired configuration.
		if reconfigurationGeneration != 0 {
			adapter.failReconfiguration(reconfigurationGeneration)
		} else {
			adapter.rollbackDesired()
		}
		c.preparationRunning = false
		if err != nil && !errors.Is(err, context.Canceled) {
			message := strings.TrimSpace(err.Error())
			if len(message) > 512 {
				message = message[:512]
			}
			c.platformLastError = message
		} else if err == nil {
			// A nil error means the engine run returned without ever waiting for a
			// tunnel fd. Record it so a failed reconnect is diagnosable.
			c.platformLastError = fmt.Sprintf(
				"engine run returned without tunnel fd after %dms", time.Since(startedAt).Milliseconds())
		}
		c.mu.Unlock()
	}()

	return view
}

//export NbCoreInit
func NbCoreInit(deviceName *C.char, osVersion *C.char, configJSON *C.char) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()

		if core.authenticationCancel != nil {
			core.authenticationCancel()
			core.authenticationCancel = nil
		}
		core.authenticationID++
		core.authenticationRun = false
		core.authenticationState = "not-configured"
		core.authenticationError = ""
		core.privateConfigured = false
		core.privatePersistent = false
		core.managementDialAddress = ""
		if err := core.replaceClientLocked(cString(deviceName), cString(osVersion), cString(configJSON)); err != nil {
			return jsonCString(false, apiInvalidConfig, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "NetBird core initialized; platform tunnel pending", core.snapshotLocked())
	})
}

// NbCoreStorePrivateCredentialImport validates setup-key input and atomically
// stores it as a 0600 one-time file in the caller's app-private filesDir. The
// response contains no credential material.
//
//export NbCoreStorePrivateCredentialImport
func NbCoreStorePrivateCredentialImport(credentialFilePath *C.char, setupKey *C.char, managementURL *C.char, managementDialAddress *C.char) *C.char {
	return safeExport(func() *C.char {
		if err := writeHarmonyCredentialImport(
			cString(credentialFilePath), cString(setupKey), cString(managementURL), cString(managementDialAddress),
		); err != nil {
			return jsonCString(false, apiCredentialInvalid, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "HarmonyOS private credential import stored", nil)
	})
}

// NbCoreStartPrivateAuthentication consumes an optional one-time credential
// import from the same app-private directory as the persistent config. The
// setup key never crosses ordinary status/IPC and the import file is removed
// before the network operation starts. With no import, an existing private
// config is restored without performing a duplicate registration.
//
//export NbCoreStartPrivateAuthentication
func NbCoreStartPrivateAuthentication(deviceName *C.char, osVersion *C.char, configFilePath *C.char, credentialFilePath *C.char) *C.char {
	return safeExport(func() *C.char {
		configPath, credentialPath, err := validateHarmonyPrivatePaths(
			cString(configFilePath), cString(credentialFilePath),
		)
		if err != nil {
			return jsonCString(false, apiInvalidArgument, err.Error(), nil)
		}

		credential, hasCredential, err := readHarmonyCredentialImport(credentialPath)
		if err != nil {
			return jsonCString(false, apiCredentialInvalid, err.Error(), nil)
		}
		cfg, err := loadHarmonyPrivateConfig(configPath, credential)
		if errors.Is(err, os.ErrNotExist) {
			core.mu.Lock()
			defer core.mu.Unlock()
			if core.client == nil {
				if err := core.replaceClientLocked(cString(deviceName), cString(osVersion), "{}"); err != nil {
					return jsonCString(false, apiInvalidConfig, err.Error(), nil)
				}
			}
			core.authenticationState = "not-configured"
			core.authenticationError = ""
			core.authenticationRun = false
			core.privateConfigured = false
			core.privatePersistent = false
			core.managementDialAddress = ""
			return jsonCString(true, apiOK, "HarmonyOS private credentials are not configured", core.snapshotLocked())
		}
		if err != nil {
			return jsonCString(false, apiInvalidConfig, err.Error(), nil)
		}

		configJSON, err := profilemanager.ConfigToJSON(cfg)
		if err != nil {
			return jsonCString(false, apiInvalidConfig, "failed to serialize HarmonyOS private config", nil)
		}
		if !hasCredential {
			core.mu.Lock()
			defer core.mu.Unlock()
			if core.authenticationRun || core.preparationRunning {
				return jsonCString(false, apiInvalidArgument, "HarmonyOS authentication or preparation is already running", core.snapshotLocked())
			}
			managementDialAddress := ""
			if credential != nil {
				managementDialAddress = credential.ManagementDialAddress
			}
			bundle, normalizedDevice, normalizedOSVersion, buildErr := buildHarmonyClientWithDialAddress(
				cString(deviceName), cString(osVersion), configJSON, managementDialAddress,
			)
			if buildErr != nil {
				return jsonCString(false, apiInvalidConfig, buildErr.Error(), nil)
			}
			core.installClientBundleLocked(bundle, normalizedDevice, normalizedOSVersion)
			core.managementDialAddress = managementDialAddress
			core.authenticationState = "configured"
			core.authenticationError = ""
			core.privateConfigured = true
			core.privatePersistent = true
			return jsonCString(true, apiOK, "HarmonyOS private NetBird config restored", core.snapshotLocked())
		}

		device := strings.TrimSpace(cString(deviceName))
		if device == "" {
			device = defaultHarmonyDevice
		}
		osVersionValue := strings.TrimSpace(cString(osVersion))
		if osVersionValue == "" {
			osVersionValue = defaultHarmonyOSVersion
		}

		managementDialAddress := credential.ManagementDialAddress
		core.mu.Lock()
		if core.authenticationRun || core.preparationRunning {
			view := core.snapshotLocked()
			core.mu.Unlock()
			return jsonCString(false, apiInvalidArgument, "HarmonyOS authentication or preparation is already running", view)
		}
		if core.client == nil {
			if err := core.replaceClientLocked(device, osVersionValue, "{}"); err != nil {
				core.mu.Unlock()
				return jsonCString(false, apiInvalidConfig, err.Error(), nil)
			}
		}
		core.authenticationID++
		authenticationID := core.authenticationID
		ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, device)
		ctx = context.WithValue(ctx, system.OsNameCtxKey, harmonyOSName)
		ctx = context.WithValue(ctx, system.OsVersionCtxKey, osVersionValue)
		if managementDialAddress != "" {
			ctx = mgm.ContextWithDialAddress(ctx, managementDialAddress)
		}
		ctx = internal.CtxInitState(ctx)
		authCtx, cancel := context.WithTimeout(ctx, harmonyAuthTimeout)
		core.authenticationCancel = cancel
		core.authenticationRun = true
		core.authenticationState = "authenticating"
		core.authenticationError = ""
		core.privateConfigured = false
		core.privatePersistent = false
		view := core.snapshotLocked()
		core.mu.Unlock()

		setupKey := credential.SetupKey
		go func() {
			defer cancel()
			var authErr error
			probeAddress, probeAddressErr := harmonyManagementTransportAddress(cfg.ManagementURL, managementDialAddress)
			if probeAddressErr != nil {
				authErr = probeAddressErr
			} else {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				probe, probeErr := dialer.DialContext(authCtx, "tcp", probeAddress)
				if probeErr != nil {
					if managementDialAddress == "" {
						authErr = errors.New("Management direct transport unavailable")
					} else {
						authErr = errors.New("Management private transport unavailable")
					}
				} else {
					_ = probe.Close()
				}
			}
			var authClient *auth.Auth
			if authErr == nil {
				authClient, authErr = auth.NewAuth(authCtx, cfg.PrivateKey, cfg.ManagementURL, cfg)
			}
			if authErr == nil {
				authErr, _ = authClient.Login(authCtx, setupKey, "")
				_ = authClient.Close()
			}
			if authErr == nil {
				authErr = profilemanager.WriteOutConfig(configPath, cfg)
			}

			var bundle *harmonyClientBundle
			var normalizedDevice, normalizedOSVersion string
			if authErr == nil {
				updatedJSON, serializeErr := profilemanager.ConfigToJSON(cfg)
				if serializeErr != nil {
					authErr = serializeErr
				} else {
					bundle, normalizedDevice, normalizedOSVersion, authErr = buildHarmonyClientWithDialAddress(
						device, osVersionValue, updatedJSON, managementDialAddress,
					)
				}
			}

			core.mu.Lock()
			defer core.mu.Unlock()
			if core.authenticationID != authenticationID {
				if bundle != nil {
					_ = bundle.client.Stop()
				}
				return
			}
			core.authenticationCancel = nil
			core.authenticationRun = false
			if authErr != nil {
				core.authenticationState = "failed"
				core.authenticationError = sanitizeHarmonyAuthenticationError(
					authErr, setupKey, cfg.PrivateKey, cfg.SSHKey,
				)
				core.privateConfigured = false
				core.privatePersistent = false
				return
			}
			core.installClientBundleLocked(bundle, normalizedDevice, normalizedOSVersion)
			core.managementDialAddress = managementDialAddress
			core.authenticationState = "authenticated"
			core.authenticationError = ""
			core.privateConfigured = true
			core.privatePersistent = true
		}()

		return jsonCString(true, apiOK, "HarmonyOS private authentication started", view)
	})
}

//export NbCoreSetConfig
func NbCoreSetConfig(configJSON *C.char) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()

		if core.client == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", core.snapshotLocked())
		}
		if core.preparationRunning || core.authenticationRun {
			return jsonCString(false, apiInvalidArgument, "HarmonyOS authentication or preparation is running", core.snapshotLocked())
		}
		if err := core.replaceClientLocked(core.deviceName, core.osVersion, cString(configJSON)); err != nil {
			return jsonCString(false, apiInvalidConfig, err.Error(), core.snapshotLocked())
		}
		return jsonCString(true, apiOK, "NetBird config loaded", core.snapshotLocked())
	})
}

// NbCoreSetPlatformState records platform-owned resources. The TUN fd remains
// owned by VpnConnection until the real fd-backed Go adapter is connected.
//
//export NbCoreSetPlatformState
func NbCoreSetPlatformState(tunFD C.int, vpnExtensionReady C.int, processProtectReady C.int, dnsReady C.int, networkChangeReady C.int, lastError *C.char) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		core.tunFD = int(tunFD)
		core.vpnExtensionReady = vpnExtensionReady != 0
		core.processProtectReady = processProtectReady != 0
		core.dnsReady = dnsReady != 0
		core.networkChangeReady = networkChangeReady != 0
		core.platformLastError = strings.TrimSpace(cString(lastError))
		return jsonCString(true, apiOK, "HarmonyOS platform state updated", core.snapshotLocked())
	})
}

//export NbCoreClearPlatformState
func NbCoreClearPlatformState() *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		core.clearPlatformLocked()
		return jsonCString(true, apiOK, "HarmonyOS platform state cleared", core.snapshotLocked())
	})
}

// NbCoreSetInterfaces validates and stores a physical, non-VPN interface
// snapshot supplied by HarmonyOS NetworkKit. The raw snapshot remains local to
// the VPN process and is not added to ordinary core status responses.
//
//export NbCoreSetInterfaces
func NbCoreSetInterfaces(interfacesJSON *C.char) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		if core.client == nil || core.platformAdapter == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if err := core.platformAdapter.setInterfacesJSON(cString(interfacesJSON)); err != nil {
			return jsonCString(false, apiInvalidArgument, err.Error(), nil)
		}
		snapshot := core.platformAdapter.snapshot()
		return jsonCString(true, apiOK, "HarmonyOS interfaces updated", map[string]interface{}{
			"interfaceRevision": snapshot.InterfaceRevision,
			"interfacesReady":   snapshot.InterfacesReady,
		})
	})
}

//export NbCorePlatformSnapshot
func NbCorePlatformSnapshot() *C.char {
	return safeExport(func() *C.char {
		core.mu.RLock()
		defer core.mu.RUnlock()
		if core.client == nil || core.platformAdapter == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		return jsonCString(true, apiOK, "HarmonyOS platform configuration snapshot", core.platformAdapter.snapshot())
	})
}

// NbCoreStartPreparation starts management login and Engine initialization on
// a Go goroutine. It never creates a system VPN; the engine blocks at the
// context-aware TunFDProvider until NbCoreProvideTunFD is called or rollback
// cancels the preparation.
//
//export NbCoreStartPreparation
func NbCoreStartPreparation(stateFilePath *C.char, cacheDir *C.char, logFilePath *C.char) *C.char {
	return safeExport(func() *C.char {
		statePath := strings.TrimSpace(cString(stateFilePath))
		cachePath := strings.TrimSpace(cString(cacheDir))
		logPath := strings.TrimSpace(cString(logFilePath))
		if statePath == "" || cachePath == "" {
			return jsonCString(false, apiInvalidArgument, "HarmonyOS preparation requires state and cache paths", nil)
		}

		core.mu.Lock()
		if core.client == nil || core.platformAdapter == nil {
			core.mu.Unlock()
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if core.authenticationRun || core.preparationRunning {
			view := core.snapshotLocked()
			core.mu.Unlock()
			return jsonCString(false, apiInvalidArgument, "HarmonyOS preparation already started for this core", view)
		}
		if !core.platformAdapter.snapshot().InterfacesReady {
			core.mu.Unlock()
			return jsonCString(false, apiPlatformNotReady, "HarmonyOS physical interfaces are not ready", nil)
		}
		// A finished preparation leaves a consumed ConnectClient behind. Rebuild it so
		// an explicit reconnect after Disconnect can run the engine again.
		if core.preparationStarted {
			if err := core.rebuildClientForReconnectLocked(); err != nil {
				view := core.snapshotLocked()
				core.mu.Unlock()
				return jsonCString(false, apiNotInitialized, err.Error(), view)
			}
		}
		client := core.client
		adapter := core.platformAdapter
		view := core.startPreparationLocked(client, adapter, statePath, cachePath, logPath, 0)
		core.mu.Unlock()

		return jsonCString(true, apiOK, "HarmonyOS preparation started; system VPN creation remains disabled", view)
	})
}

//export NbCoreProvideTunFD
func NbCoreProvideTunFD(tunFD C.int) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		if core.client == nil || core.platformAdapter == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if !core.preparationRunning {
			return jsonCString(false, apiPlatformNotReady, "HarmonyOS preparation is not running", core.snapshotLocked())
		}
		if err := core.platformAdapter.provideTunFD(int(tunFD)); err != nil {
			return jsonCString(false, apiInvalidArgument, err.Error(), core.platformAdapter.snapshot())
		}
		core.tunFD = int(tunFD)
		return jsonCString(true, apiOK, "HarmonyOS tunnel fd provided to waiting engine", core.snapshotLocked())
	})
}

// NbCoreDebugRequestReconfiguration advances only the config revision while
// preserving the current desired addresses/routes/DNS. It is gated by the
// Harmony debug host and requires a stable consumed fd lease.
//
//export NbCoreDebugRequestReconfiguration
func NbCoreDebugRequestReconfiguration() *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		if core.client == nil || core.platformAdapter == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if err := core.platformAdapter.debugRequestReconfiguration(); err != nil {
			return jsonCString(false, apiPlatformNotReady, err.Error(), core.platformAdapter.snapshot())
		}
		return jsonCString(true, apiOK, "HarmonyOS debug reconfiguration is pending", core.platformAdapter.snapshot())
	})
}

// NbCoreBeginReconfiguration asynchronously stops the active Engine. Success is
// acknowledged only after TunDevice has closed the duplicated fd for the exact
// active lease and a fresh ConnectClient has been built from the in-memory
// config. It never creates or destroys a HarmonyOS VpnConnection.
//
//export NbCoreBeginReconfiguration
func NbCoreBeginReconfiguration(generation C.ulonglong, targetRevision C.ulonglong) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		if core.client == nil || core.platformAdapter == nil || core.config == nil {
			core.mu.Unlock()
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		configJSON, err := profilemanager.ConfigToJSON(core.config)
		if err != nil {
			core.mu.Unlock()
			return jsonCString(false, apiInvalidConfig, "failed to clone NetBird config", nil)
		}
		adapter := core.platformAdapter
		gen := uint64(generation)
		if err := adapter.beginReconfiguration(gen, uint64(targetRevision)); err != nil {
			view := core.snapshotLocked()
			core.mu.Unlock()
			return jsonCString(false, apiInvalidArgument, err.Error(), view)
		}
		oldClient := core.client
		deviceName := core.deviceName
		osVersion := core.osVersion
		managementDialAddress := core.managementDialAddress
		core.preparationID++
		operationID := core.preparationID
		core.preparationRunning = false
		core.preparationStarted = false
		core.platformLastError = ""
		view := core.snapshotLocked()
		core.mu.Unlock()

		go func() {
			stopErr := oldClient.Stop()
			if stopErr != nil || !adapter.oldFDReleaseAcknowledged(gen) {
				adapter.failReconfiguration(gen)
				core.mu.Lock()
				if core.preparationID == operationID && core.client == oldClient {
					core.tunFD = -1
					if stopErr != nil {
						core.platformLastError = "failed to stop old NetBird engine"
					} else {
						core.platformLastError = "old HarmonyOS fd release was not acknowledged"
					}
				}
				core.mu.Unlock()
				return
			}

			bundle, normalizedDeviceName, normalizedOSVersion, buildErr := buildHarmonyClientWithDialAddress(
				deviceName, osVersion, configJSON, managementDialAddress,
			)
			if buildErr != nil {
				adapter.failReconfiguration(gen)
				core.mu.Lock()
				if core.preparationID == operationID && core.client == oldClient {
					core.tunFD = -1
					core.platformLastError = "failed to rebuild NetBird client"
				}
				core.mu.Unlock()
				return
			}

			core.mu.Lock()
			if core.preparationID != operationID || core.client != oldClient {
				core.mu.Unlock()
				_ = bundle.client.Stop()
				return
			}
			if err := adapter.completeClientRebuild(gen); err != nil {
				core.platformLastError = "HarmonyOS reconfiguration acknowledgement became stale"
				core.mu.Unlock()
				_ = bundle.client.Stop()
				adapter.failReconfiguration(gen)
				return
			}
			core.client = bundle.client
			core.config = bundle.config
			core.recorder = bundle.recorder
			core.netEvents = bundle.netEvents
			core.deviceName = normalizedDeviceName
			core.osVersion = normalizedOSVersion
			core.tunFD = -1
			core.mu.Unlock()
		}()

		return jsonCString(true, apiOK, "HarmonyOS reconfiguration stop started", view)
	})
}

// NbCoreRestartPreparation starts a new management/Engine preparation only
// after the matching old lease has reached old-fd-released.
//
//export NbCoreRestartPreparation
func NbCoreRestartPreparation(generation C.ulonglong, stateFilePath *C.char, cacheDir *C.char, logFilePath *C.char) *C.char {
	return safeExport(func() *C.char {
		statePath := strings.TrimSpace(cString(stateFilePath))
		cachePath := strings.TrimSpace(cString(cacheDir))
		logPath := strings.TrimSpace(cString(logFilePath))
		if statePath == "" || cachePath == "" {
			return jsonCString(false, apiInvalidArgument, "HarmonyOS preparation requires state and cache paths", nil)
		}

		core.mu.Lock()
		if core.client == nil || core.platformAdapter == nil {
			core.mu.Unlock()
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if core.authenticationRun || core.preparationRunning || core.preparationStarted {
			view := core.snapshotLocked()
			core.mu.Unlock()
			return jsonCString(false, apiInvalidArgument, "HarmonyOS preparation already started for this core", view)
		}
		gen := uint64(generation)
		if err := core.platformAdapter.restartReconfiguration(gen); err != nil {
			view := core.snapshotLocked()
			core.mu.Unlock()
			return jsonCString(false, apiInvalidArgument, err.Error(), view)
		}
		view := core.startPreparationLocked(
			core.client,
			core.platformAdapter,
			statePath,
			cachePath,
			logPath,
			gen,
		)
		core.mu.Unlock()
		return jsonCString(true, apiOK, "HarmonyOS reconfiguration preparation restarted", view)
	})
}

//export NbCoreProvideTunFDForGeneration
func NbCoreProvideTunFDForGeneration(
	tunFD C.int,
	preparationGeneration C.ulonglong,
	reconfigurationGeneration C.ulonglong,
	configRevision C.ulonglong,
) *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		if core.client == nil || core.platformAdapter == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		if !core.preparationRunning {
			return jsonCString(false, apiPlatformNotReady, "HarmonyOS preparation is not running", core.snapshotLocked())
		}
		if err := core.platformAdapter.provideTunFDForGeneration(
			int(tunFD),
			uint64(preparationGeneration),
			uint64(reconfigurationGeneration),
			uint64(configRevision),
		); err != nil {
			return jsonCString(false, apiInvalidArgument, err.Error(), core.platformAdapter.snapshot())
		}
		core.tunFD = int(tunFD)
		return jsonCString(true, apiOK, "HarmonyOS tunnel fd provided for matching generations", core.snapshotLocked())
	})
}

//export NbCorePlatformRollback
func NbCorePlatformRollback() *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		if core.client == nil || core.platformAdapter == nil {
			core.mu.Unlock()
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", nil)
		}
		client := core.client
		adapter := core.platformAdapter
		wasRunning := core.preparationRunning
		adapter.rollbackDesired()
		core.tunFD = -1
		core.preparationRunning = false
		core.preparationStarted = false
		core.preparationID++
		core.mu.Unlock()

		if wasRunning {
			_ = client.Stop()
		}
		rolledBack := adapter.rollbackDesired()
		return jsonCString(true, apiOK, "HarmonyOS platform configuration rolled back", rolledBack)
	})
}

//export NbCorePlatformSelfTest
func NbCorePlatformSelfTest() *C.char {
	return safeExport(func() *C.char {
		snapshot, err := runHarmonyPlatformAdapterSelfTest()
		if err != nil {
			return jsonCString(false, apiTunSelfTestFailed, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "HarmonyOS platform adapter self-test passed", map[string]interface{}{
			"report":            "interface normalization OK; desired config aggregation OK; late-fd wait/provide/cancel OK; generation-safe reconfiguration OK; stale lease rejection OK; idempotent rollback OK; NB_RECONFIGURATION_SELFTEST_DONE; NB_LATE_FD_SELFTEST_DONE; NB_PLATFORM_ADAPTER_SELFTEST_DONE",
			"revision":          snapshot.Revision,
			"interfaceRevision": snapshot.InterfaceRevision,
		})
	})
}

//export NbCoreStatus
func NbCoreStatus() *C.char {
	return safeExport(func() *C.char {
		core.mu.RLock()
		defer core.mu.RUnlock()
		if core.client == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", core.snapshotLocked())
		}
		return jsonCString(true, apiOK, "NetBird core status", core.snapshotLocked())
	})
}

// NbCoreConnect deliberately does not start internal.Run until the fd-backed
// TUN adapter, DNS and network-change integration are all implemented.
//
//export NbCoreConnect
func NbCoreConnect() *C.char {
	return safeExport(func() *C.char {
		core.mu.RLock()
		defer core.mu.RUnlock()
		if core.client == nil {
			return jsonCString(false, apiNotInitialized, "NetBird core is not initialized", core.snapshotLocked())
		}
		return jsonCString(false, apiPlatformNotReady, "HarmonyOS VPN engine adapter is not ready", core.snapshotLocked())
	})
}

//export NbCoreShutdown
func NbCoreShutdown() *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		defer core.mu.Unlock()
		if core.client != nil {
			_ = core.client.Stop()
		}
		core.client = nil
		core.config = nil
		core.recorder = nil
		core.netEvents = nil
		core.deviceName = ""
		core.osVersion = ""
		core.clearPlatformLocked()
		core.platformAdapter = nil
		core.authenticationID++
		core.authenticationState = "not-configured"
		core.authenticationError = ""
		core.authenticationRun = false
		core.privateConfigured = false
		core.privatePersistent = false
		core.managementDialAddress = ""
		return jsonCString(true, apiOK, "NetBird core stopped", core.snapshotLocked())
	})
}

//export NbCoreSelfTest
func NbCoreSelfTest() *C.char {
	var report string

	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return C.CString("rand err: " + err.Error())
	}
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return C.CString("curve25519 err: " + err.Error())
	}
	report += fmt.Sprintf("wg pubkey len=%d; ", len(publicKey))

	var waitGroup sync.WaitGroup
	results := make(chan int, 16)
	for i := 0; i < 16; i++ {
		waitGroup.Add(1)
		go func(n int) {
			defer waitGroup.Done()
			sum := 0
			for j := 0; j < n*1000; j++ {
				sum += j
			}
			results <- sum
		}(i)
	}
	waitGroup.Wait()
	close(results)
	total := 0
	for result := range results {
		total += result
	}
	report += fmt.Sprintf("goroutines sum=%d; ", total)

	localIP := netip.MustParseAddr("10.0.0.2")
	dnsIP := netip.MustParseAddr("8.8.8.8")
	tunDevice, _, err := netstack.CreateNetTUN([]netip.Addr{localIP}, []netip.Addr{dnsIP}, 1280)
	if err != nil {
		return C.CString(report + "netstack tun err: " + err.Error())
	}
	wireGuardDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "nbharmony"))
	if wireGuardDevice != nil {
		report += "wg device created OK; "
		wireGuardDevice.Close()
	}

	return C.CString(report + "NB_SELFTEST_DONE")
}

//export NbCoreTunSelfTest
func NbCoreTunSelfTest() *C.char {
	return safeExport(func() *C.char {
		report, err := runFDTunSelfTest()
		if err != nil {
			return jsonCString(false, apiTunSelfTestFailed, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "Harmony fd TUN adapter self-test passed", map[string]string{
			"report": report,
		})
	})
}

//export NbCoreResetTunRuntimeStats
func NbCoreResetTunRuntimeStats() *C.char {
	return safeExport(func() *C.char {
		fdtun.ResetRuntimeStats()
		return jsonCString(true, apiOK, "Harmony fd TUN runtime stats reset", fdtun.GetRuntimeStats())
	})
}

//export NbCoreTunRuntimeStats
func NbCoreTunRuntimeStats() *C.char {
	return safeExport(func() *C.char {
		return jsonCString(true, apiOK, "Harmony fd TUN runtime stats", fdtun.GetRuntimeStats())
	})
}

//export NbFreeString
func NbFreeString(value unsafe.Pointer) {
	if value != nil {
		C.free(value)
	}
}

func main() {}
