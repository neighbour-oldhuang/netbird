package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
)

func normalizeHarmonyManagementDialAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("invalid Management dial override")
	}
	address := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if address == nil || (!address.IsLoopback() && !address.IsPrivate()) || portErr != nil || port <= 0 || port > 65535 {
		return "", errors.New("Management dial override must be a loopback or private address and valid port")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(port)), nil
}

func harmonyManagementTransportAddress(managementURL *url.URL, dialOverride string) (string, error) {
	if dialOverride != "" {
		return normalizeHarmonyManagementDialAddress(dialOverride)
	}
	if managementURL == nil || managementURL.Hostname() == "" {
		return "", errors.New("invalid Management transport URL")
	}
	port := managementURL.Port()
	if port == "" {
		switch managementURL.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", errors.New("invalid Management transport scheme")
		}
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort <= 0 || parsedPort > 65535 {
		return "", errors.New("invalid Management transport port")
	}
	return net.JoinHostPort(managementURL.Hostname(), strconv.Itoa(parsedPort)), nil
}

const harmonyCredentialMaxLen = 4096

func writeHarmonyCredentialImport(path, setupKey, managementURL, managementDialAddress string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || filepath.Base(path) != "netbird-credential-import.json" {
		return errors.New("invalid HarmonyOS credential import path")
	}
	parsedKey, err := uuid.Parse(strings.TrimSpace(setupKey))
	if err != nil {
		return errors.New("invalid setup key")
	}
	managementURL = strings.TrimSpace(managementURL)
	parsedURL, err := url.ParseRequestURI(managementURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") || parsedURL.Host == "" {
		return errors.New("invalid management URL")
	}
	managementDialAddress, err = normalizeHarmonyManagementDialAddress(managementDialAddress)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(harmonyCredentialImport{
		SetupKey:              parsedKey.String(),
		ManagementURL:         parsedURL.String(),
		ManagementDialAddress: managementDialAddress,
	})
	if err != nil {
		return errors.New("failed to encode HarmonyOS credential import")
	}

	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return errors.New("invalid HarmonyOS private credential directory")
	}
	temp, err := os.CreateTemp(dir, ".netbird-credential-*")
	if err != nil {
		return errors.New("failed to create HarmonyOS credential import")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return errors.New("failed to secure HarmonyOS credential import")
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return errors.New("failed to write HarmonyOS credential import")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return errors.New("failed to sync HarmonyOS credential import")
	}
	if err := temp.Close(); err != nil {
		return errors.New("failed to close HarmonyOS credential import")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("failed to replace HarmonyOS credential import")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return errors.New("failed to publish HarmonyOS credential import")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return errors.New("failed to secure HarmonyOS credential import")
	}
	return nil
}

type harmonyCredentialImport struct {
	SetupKey              string `json:"setupKey"`
	ManagementURL         string `json:"managementUrl"`
	ManagementDialAddress string `json:"managementDialAddress,omitempty"`
}

func validateHarmonyPrivatePaths(configPath, credentialPath string) (string, string, error) {
	configPath = filepath.Clean(strings.TrimSpace(configPath))
	credentialPath = filepath.Clean(strings.TrimSpace(credentialPath))
	if !filepath.IsAbs(configPath) || !filepath.IsAbs(credentialPath) {
		return "", "", errors.New("HarmonyOS private config and credential paths must be absolute")
	}
	if filepath.Dir(configPath) != filepath.Dir(credentialPath) || configPath == credentialPath {
		return "", "", errors.New("HarmonyOS private config and credential import must be distinct files in the same directory")
	}
	return configPath, credentialPath, nil
}

func readHarmonyCredentialImport(path string) (*harmonyCredentialImport, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("failed to inspect HarmonyOS credential import")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("HarmonyOS credential import must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > harmonyCredentialMaxLen {
		return nil, false, errors.New("HarmonyOS credential import has an invalid size")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, false, errors.New("HarmonyOS credential import permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("failed to read HarmonyOS credential import")
	}
	// The setup key is single-use input for this client. Remove the transfer
	// file before any network operation; callers can explicitly transfer it
	// again after a failure.
	_ = os.Remove(path)

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var credential harmonyCredentialImport
	if err := decoder.Decode(&credential); err != nil {
		return nil, false, errors.New("invalid HarmonyOS credential import")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false, errors.New("invalid trailing data in HarmonyOS credential import")
	}
	credential.SetupKey = strings.TrimSpace(credential.SetupKey)
	credential.ManagementURL = strings.TrimSpace(credential.ManagementURL)
	parsedKey, err := uuid.Parse(credential.SetupKey)
	if err != nil {
		return nil, false, errors.New("invalid setup key in HarmonyOS credential import")
	}
	credential.SetupKey = parsedKey.String()
	if credential.ManagementURL == "" {
		return nil, false, errors.New("HarmonyOS credential import is missing management URL")
	}
	credential.ManagementDialAddress, err = normalizeHarmonyManagementDialAddress(credential.ManagementDialAddress)
	if err != nil {
		return nil, false, err
	}
	return &credential, true, nil
}

func useHarmonyComponentNetworkMap(cfg *profilemanager.Config) *profilemanager.Config {
	if cfg == nil {
		return nil
	}
	version := int(sharedgrpc.HighestSyncMessageVersion)
	cfg.SyncMessageVersion = &version
	return cfg
}

func loadHarmonyPrivateConfig(configPath string, credential *harmonyCredentialImport) (*profilemanager.Config, error) {
	cfg, err := readOrCreateHarmonyPrivateConfig(configPath, credential)
	if err != nil {
		return nil, err
	}
	// 全局客户端设置对新建和已有 config 都生效，且随后的登录会把它们写回配置文件。
	applyHarmonyClientSettings(cfg)
	return cfg, nil
}

func readOrCreateHarmonyPrivateConfig(configPath string, credential *harmonyCredentialImport) (*profilemanager.Config, error) {
	info, err := os.Lstat(configPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("HarmonyOS private config must be a regular file")
		}
		cfg, err := profilemanager.ReadConfig(configPath)
		if err != nil {
			return nil, errors.New("failed to load HarmonyOS private config")
		}
		return useHarmonyComponentNetworkMap(cfg), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("failed to inspect HarmonyOS private config")
	}
	if credential == nil {
		return nil, os.ErrNotExist
	}
	cfg, err := profilemanager.CreateInMemoryConfig(profilemanager.ConfigInput{
		ManagementURL: credential.ManagementURL,
		ConfigPath:    configPath,
	})
	if err != nil {
		return nil, errors.New("failed to create HarmonyOS private config")
	}
	return useHarmonyComponentNetworkMap(cfg), nil
}

func sanitizeHarmonyAuthenticationError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "[redacted]")
		message = strings.ReplaceAll(message, strings.ToLower(secret), "[redacted]")
		message = strings.ReplaceAll(message, strings.ToUpper(secret), "[redacted]")
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
