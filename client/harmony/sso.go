package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

// SSO enrollment reuses the setup key path: the only difference is that Login is
// called with a JWT instead of a key. The interactive part is handed to the host,
// which shows the authorization page and lets the redirect happen; everything that
// touches the token stays inside the Core.
type harmonySSOView struct {
	Flow                    string `json:"flow"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	VerificationURI         string `json:"verificationUri,omitempty"`
	UserCode                string `json:"userCode,omitempty"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval,omitempty"`
	RedirectURL             string `json:"redirectUrl,omitempty"`
}

const harmonySSOTimeout = 5 * time.Minute

// startSSOLogin prepares an OAuth flow for the active profile and returns what the
// host needs to render it. The token exchange and the peer registration continue in
// the background and are reported through the regular authentication state.
func (c *harmonyCore) startSSOLogin(deviceName, osVersion, configPath, managementURL string,
	preferDeviceCode bool) (*harmonySSOView, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, errors.New("HarmonyOS SSO requires a config path")
	}
	device := strings.TrimSpace(deviceName)
	if device == "" {
		device = defaultHarmonyDevice
	}
	osVersionValue := strings.TrimSpace(osVersion)
	if osVersionValue == "" {
		osVersionValue = defaultHarmonyOSVersion
	}

	cfg, err := loadHarmonySSOConfig(configPath, managementURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.authenticationRun || c.preparationRunning {
		c.mu.Unlock()
		return nil, errors.New("HarmonyOS authentication or preparation is already running")
	}
	if c.client == nil {
		if err := c.replaceClientLocked(device, osVersionValue, "{}"); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}
	managementDialAddress := c.managementDialAddress
	c.authenticationID++
	authenticationID := c.authenticationID
	c.mu.Unlock()

	ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, device)
	ctx = context.WithValue(ctx, system.OsNameCtxKey, harmonyOSName)
	ctx = context.WithValue(ctx, system.OsVersionCtxKey, osVersionValue)
	if managementDialAddress != "" {
		ctx = mgm.ContextWithDialAddress(ctx, managementDialAddress)
	}
	ctx = internal.CtxInitState(ctx)
	authCtx, cancel := context.WithTimeout(ctx, harmonySSOTimeout)

	authClient, err := auth.NewAuth(authCtx, cfg.PrivateKey, cfg.ManagementURL, cfg)
	if err != nil {
		cancel()
		return nil, errors.New(sanitizeHarmonyAuthenticationError(err))
	}

	supported, err := authClient.IsSSOSupported(authCtx)
	if err != nil {
		cancel()
		_ = authClient.Close()
		return nil, errors.New(sanitizeHarmonyAuthenticationError(err))
	}
	if !supported {
		cancel()
		_ = authClient.Close()
		return nil, errors.New("Management does not offer interactive login")
	}

	// A device flow keeps the whole interactive part in the system browser, which is
	// what an IdP chain that hands off to another app (an enterprise SSO opening its
	// own client, for example) needs: nothing has to be redirected back into this
	// process. The PKCE flow is only usable when the browser can reach the loopback
	// address this process listens on.
	flow, err := authClient.GetOAuthFlow(authCtx, preferDeviceCode, "")
	if err != nil {
		cancel()
		_ = authClient.Close()
		return nil, errors.New(sanitizeHarmonyAuthenticationError(err))
	}

	info, err := flow.RequestAuthInfo(authCtx)
	if err != nil {
		cancel()
		_ = authClient.Close()
		return nil, errors.New(sanitizeHarmonyAuthenticationError(err))
	}

	view := &harmonySSOView{
		Flow:                    ssoFlowName(info),
		VerificationURIComplete: info.VerificationURIComplete,
		VerificationURI:         info.VerificationURI,
		UserCode:                info.UserCode,
		ExpiresIn:               info.ExpiresIn,
		Interval:                info.Interval,
		RedirectURL:             ssoRedirectURL(info.VerificationURIComplete),
	}

	c.mu.Lock()
	if c.authenticationID != authenticationID {
		c.mu.Unlock()
		cancel()
		_ = authClient.Close()
		return nil, errors.New("HarmonyOS authentication was superseded")
	}
	c.authenticationCancel = cancel
	c.authenticationRun = true
	c.authenticationState = "awaiting-user"
	c.authenticationError = ""
	c.privateConfigured = false
	c.privatePersistent = false
	c.mu.Unlock()

	go c.completeSSOLogin(authCtx, cancel, authClient, flow, info, cfg, configPath,
		device, osVersionValue, managementDialAddress, authenticationID)

	return view, nil
}

func (c *harmonyCore) completeSSOLogin(authCtx context.Context, cancel context.CancelFunc,
	authClient *auth.Auth, flow auth.OAuthFlow, info auth.AuthFlowInfo,
	cfg *profilemanager.Config, configPath, device, osVersion, managementDialAddress string,
	authenticationID uint64) {
	defer cancel()
	defer func() {
		_ = authClient.Close()
	}()

	tokenInfo, authErr := flow.WaitToken(authCtx, info)
	if authErr == nil {
		c.mu.Lock()
		if c.authenticationID == authenticationID {
			c.authenticationState = "registering"
		}
		c.mu.Unlock()
		authErr, _ = authClient.Login(authCtx, "", tokenInfo.GetTokenToUse())
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
				device, osVersion, updatedJSON, managementDialAddress,
			)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authenticationID != authenticationID {
		return
	}
	c.authenticationRun = false
	c.authenticationCancel = nil
	if authErr != nil {
		c.authenticationState = "failed"
		c.authenticationError = sanitizeHarmonyAuthenticationError(authErr)
		c.privateConfigured = false
		c.privatePersistent = false
		return
	}
	c.installClientBundleLocked(bundle, normalizedDevice, normalizedOSVersion)
	c.authenticationState = "configured"
	c.authenticationError = ""
	c.privateConfigured = true
	c.privatePersistent = true
}

// loadHarmonySSOConfig reuses an existing profile config so the peer keeps its
// identity, and only creates one when the profile has never been enrolled.
func loadHarmonySSOConfig(configPath, managementURL string) (*profilemanager.Config, error) {
	cfg, err := loadHarmonyPrivateConfig(configPath, nil)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	managementURL = strings.TrimSpace(managementURL)
	parsed, parseErr := url.ParseRequestURI(managementURL)
	if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, errors.New("invalid management URL")
	}
	created, createErr := profilemanager.CreateInMemoryConfig(profilemanager.ConfigInput{
		ManagementURL: managementURL,
		ConfigPath:    configPath,
	})
	if createErr != nil {
		return nil, errors.New("failed to create HarmonyOS private config")
	}
	created = useHarmonyComponentNetworkMap(created)
	applyHarmonyClientSettings(created)
	return created, nil
}

// A device flow answer always carries a user code; the PKCE flow only returns the
// authorization URL it expects a browser to open.
func ssoFlowName(info auth.AuthFlowInfo) string {
	if strings.TrimSpace(info.UserCode) != "" {
		return "device"
	}
	return "pkce"
}

// The PKCE authorization URL carries the loopback address the Core listens on. The
// host needs it to recognise the redirect that ends the flow.
func ssoRedirectURL(authURL string) string {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("redirect_uri")
}

//export NbCoreStartSSOLogin
func NbCoreStartSSOLogin(deviceName *C.char, osVersion *C.char, configFilePath *C.char,
	managementURL *C.char, preferDeviceCode C.int) *C.char {
	return safeExport(func() *C.char {
		view, err := core.startSSOLogin(cString(deviceName), cString(osVersion),
			cString(configFilePath), cString(managementURL), preferDeviceCode != 0)
		if err != nil {
			return jsonCString(false, apiInvalidConfig, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "HarmonyOS interactive login started", view)
	})
}

//export NbCoreCancelSSOLogin
func NbCoreCancelSSOLogin() *C.char {
	return safeExport(func() *C.char {
		core.mu.Lock()
		cancel := core.authenticationCancel
		running := core.authenticationRun
		if running {
			core.authenticationCancel = nil
			core.authenticationRun = false
			core.authenticationState = "cancelled"
			core.authenticationError = ""
		}
		view := core.snapshotLocked()
		core.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if !running {
			return jsonCString(true, apiOK, "HarmonyOS interactive login is not running", view)
		}
		return jsonCString(true, apiOK, "HarmonyOS interactive login cancelled", view)
	})
}
