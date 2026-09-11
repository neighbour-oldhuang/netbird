package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Client settings are global on this platform: a phone is normally used the same
// way across every server configuration. They are applied to whichever profile
// config the Core loads, so a fresh enrollment and a restored identity end up with
// the same behaviour, and the values persist because the config is written out
// after login.
type harmonyClientSettings struct {
	ManageDNS           *bool   `json:"manageDns,omitempty"`
	AcceptRoutes        *bool   `json:"acceptRoutes,omitempty"`
	BlockLANAccess      *bool   `json:"blockLanAccess,omitempty"`
	BlockInbound        *bool   `json:"blockInbound,omitempty"`
	RosenpassEnabled    *bool   `json:"rosenpassEnabled,omitempty"`
	RosenpassPermissive *bool   `json:"rosenpassPermissive,omitempty"`
	DisableIPv6         *bool   `json:"disableIpv6,omitempty"`
	MTU                 *int    `json:"mtu,omitempty"`
	WireguardPort       *int    `json:"wireguardPort,omitempty"`
	CustomDNSAddress    *string `json:"customDnsAddress,omitempty"`
}

var (
	clientSettingsMu sync.RWMutex
	clientSettings   *harmonyClientSettings
)

func setHarmonyClientSettings(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		clientSettingsMu.Lock()
		clientSettings = nil
		clientSettingsMu.Unlock()
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var parsed harmonyClientSettings
	if err := decoder.Decode(&parsed); err != nil {
		return errors.New("invalid HarmonyOS client settings")
	}
	if err := validateHarmonyClientSettings(&parsed); err != nil {
		return err
	}
	clientSettingsMu.Lock()
	clientSettings = &parsed
	clientSettingsMu.Unlock()
	return nil
}

func validateHarmonyClientSettings(settings *harmonyClientSettings) error {
	if settings.MTU != nil && *settings.MTU != 0 && (*settings.MTU < 1280 || *settings.MTU > 1500) {
		return errors.New("MTU must be between 1280 and 1500")
	}
	if settings.WireguardPort != nil && *settings.WireguardPort != 0 &&
		(*settings.WireguardPort < 1024 || *settings.WireguardPort > 65535) {
		return errors.New("WireGuard port must be between 1024 and 65535")
	}
	if settings.CustomDNSAddress != nil {
		value := strings.TrimSpace(*settings.CustomDNSAddress)
		if value != "" {
			host, port, err := net.SplitHostPort(value)
			if err != nil {
				host = value
				port = "53"
			}
			if net.ParseIP(host) == nil || port == "" {
				return errors.New("custom DNS address must be an IP with an optional port")
			}
		}
	}
	return nil
}

// applyHarmonyClientSettings mutates the loaded profile config in place. A nil or
// zero value keeps whatever the config already carries, so an unset switch never
// overwrites a server or profile provided value.
func applyHarmonyClientSettings(cfg *profilemanager.Config) {
	if cfg == nil {
		return
	}
	clientSettingsMu.RLock()
	settings := clientSettings
	clientSettingsMu.RUnlock()
	if settings == nil {
		return
	}

	if settings.ManageDNS != nil {
		cfg.DisableDNS = !*settings.ManageDNS
	}
	if settings.AcceptRoutes != nil {
		cfg.DisableClientRoutes = !*settings.AcceptRoutes
	}
	if settings.BlockLANAccess != nil {
		cfg.BlockLANAccess = *settings.BlockLANAccess
	}
	if settings.BlockInbound != nil {
		cfg.BlockInbound = *settings.BlockInbound
	}
	if settings.RosenpassEnabled != nil {
		cfg.RosenpassEnabled = *settings.RosenpassEnabled
	}
	if settings.RosenpassPermissive != nil {
		cfg.RosenpassPermissive = *settings.RosenpassPermissive
	}
	if settings.DisableIPv6 != nil {
		cfg.DisableIPv6 = *settings.DisableIPv6
	}
	if settings.MTU != nil && *settings.MTU != 0 {
		cfg.MTU = uint16(*settings.MTU)
	}
	if settings.WireguardPort != nil && *settings.WireguardPort != 0 {
		cfg.WgPort = *settings.WireguardPort
	}
	if settings.CustomDNSAddress != nil {
		cfg.CustomDNSAddress = strings.TrimSpace(*settings.CustomDNSAddress)
	}
}

//export NbCoreSetClientSettings
func NbCoreSetClientSettings(settingsJSON *C.char) *C.char {
	return safeExport(func() *C.char {
		if err := setHarmonyClientSettings(cString(settingsJSON)); err != nil {
			return jsonCString(false, apiInvalidArgument, err.Error(), nil)
		}
		return jsonCString(true, apiOK, "HarmonyOS client settings applied", nil)
	})
}
