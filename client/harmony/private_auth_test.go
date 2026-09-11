package main

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
)

const testSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

func TestValidateHarmonyPrivatePaths(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "netbird-private.json")
	credential := filepath.Join(dir, "netbird-credential-import.json")
	gotConfig, gotCredential, err := validateHarmonyPrivatePaths(config, credential)
	if err != nil {
		t.Fatal(err)
	}
	if gotConfig != config || gotCredential != credential {
		t.Fatalf("unexpected paths: %q %q", gotConfig, gotCredential)
	}
	if _, _, err := validateHarmonyPrivatePaths("relative.json", credential); err == nil {
		t.Fatal("relative config path accepted")
	}
	if _, _, err := validateHarmonyPrivatePaths(config, config); err == nil {
		t.Fatal("identical config/credential path accepted")
	}
	if _, _, err := validateHarmonyPrivatePaths(config, filepath.Join(t.TempDir(), "credential.json")); err == nil {
		t.Fatal("credential outside private config directory accepted")
	}
}

func TestReadHarmonyCredentialImportConsumesValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	payload := `{"setupKey":"` + testSetupKey + `","managementUrl":"https://api.example.test:443"}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, found, err := readHarmonyCredentialImport(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || credential == nil || credential.SetupKey != strings.ToLower(testSetupKey) ||
		credential.ManagementURL != "https://api.example.test:443" {
		t.Fatalf("unexpected credential metadata: found=%v credential=%+v", found, credential)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential import was not consumed: %v", err)
	}
}

func TestReadHarmonyCredentialImportRejectsInvalidData(t *testing.T) {
	tests := []string{
		`{"setupKey":"not-a-key","managementUrl":"https://api.example.test:443"}`,
		`{"setupKey":"` + testSetupKey + `","managementUrl":""}`,
		`{"setupKey":"` + testSetupKey + `","managementUrl":"https://api.example.test:443","extra":true}`,
		`{"setupKey":"` + testSetupKey + `","managementUrl":"https://api.example.test:443"} {}`,
	}
	for i, payload := range tests {
		path := filepath.Join(t.TempDir(), "credential.json")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, found, err := readHarmonyCredentialImport(path); err == nil || found {
			t.Fatalf("case %d accepted invalid credential", i)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("case %d invalid import was not removed: %v", i, err)
		}
	}
}

func TestReadHarmonyCredentialImportRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits consistently")
	}
	path := filepath.Join(t.TempDir(), "credential.json")
	payload := `{"setupKey":"` + testSetupKey + `","managementUrl":"https://api.example.test:443"}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, found, err := readHarmonyCredentialImport(path); err == nil || found {
		t.Fatal("broad credential permissions accepted")
	}
}

func TestLoadHarmonyPrivateConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netbird-private.json")
	credential := &harmonyCredentialImport{
		SetupKey:      strings.ToLower(testSetupKey),
		ManagementURL: "https://api.example.test:443",
	}
	cfg, err := loadHarmonyPrivateConfig(path, credential)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManagementURL.String() != credential.ManagementURL || cfg.PrivateKey == "" || cfg.SSHKey == "" {
		t.Fatal("new private config did not apply URL and generate keys")
	}
	if cfg.SyncMessageVersion == nil || *cfg.SyncMessageVersion != int(sharedgrpc.HighestSyncMessageVersion) {
		t.Fatal("new private config did not enable the highest component NetworkMap version")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate config was persisted before authentication")
	}
	legacyVersion := 0
	cfg.SyncMessageVersion = &legacyVersion
	if err := profilemanager.WriteOutConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	restored, err := loadHarmonyPrivateConfig(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if restored.SyncMessageVersion == nil || *restored.SyncMessageVersion != int(sharedgrpc.HighestSyncMessageVersion) {
		t.Fatal("restored private config did not upgrade the component NetworkMap version")
	}
	if restored.PrivateKey != cfg.PrivateKey || restored.SSHKey != cfg.SSHKey {
		t.Fatal("persistent private keys were not restored")
	}
	mismatch := &harmonyCredentialImport{SetupKey: credential.SetupKey, ManagementURL: "https://other.example.test:443"}
	restoredWithCredential, err := loadHarmonyPrivateConfig(path, mismatch)
	if err != nil {
		t.Fatal(err)
	}
	if restoredWithCredential.ManagementURL.String() != cfg.ManagementURL.String() ||
		restoredWithCredential.PrivateKey != cfg.PrivateKey {
		t.Fatal("credential import replaced persistent private config")
	}
}

func TestSanitizeHarmonyAuthenticationError(t *testing.T) {
	secret := testSetupKey
	message := sanitizeHarmonyAuthenticationError(errors.New("login rejected key "+secret), secret)
	if strings.Contains(strings.ToLower(message), strings.ToLower(secret)) || !strings.Contains(message, "[redacted]") {
		t.Fatalf("secret was not redacted: %q", message)
	}
	long := sanitizeHarmonyAuthenticationError(errors.New(strings.Repeat("x", 700)))
	if len(long) != 512 {
		t.Fatalf("sanitized error length = %d", len(long))
	}
}

func TestNormalizeHarmonyManagementDialAddressAllowsPrivateTransport(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18443", "192.168.12.33:18446", "[fd00::1]:18446"} {
		normalized, err := normalizeHarmonyManagementDialAddress(address)
		if err != nil || normalized == "" {
			t.Fatalf("normalize %q: value=%q error=%v", address, normalized, err)
		}
	}
	for _, address := range []string{"192.0.2.1:18443", "8.8.8.8:443"} {
		if _, err := normalizeHarmonyManagementDialAddress(address); err == nil {
			t.Fatalf("public address %q accepted", address)
		}
	}
}

func TestWriteHarmonyCredentialImport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netbird-credential-import.json")
	if err := writeHarmonyCredentialImport(path, testSetupKey, "https://api.example.test:443", "127.0.0.1:18443"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %o, want 600", info.Mode().Perm())
	}
	credential, found, err := readHarmonyCredentialImport(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || credential == nil || credential.ManagementURL != "https://api.example.test:443" ||
		credential.ManagementDialAddress != "127.0.0.1:18443" {
		t.Fatal("stored credential could not be consumed")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stored credential was not removed after consumption")
	}
}

func TestWriteHarmonyCredentialImportRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "netbird-credential-import.json")
	tests := []struct {
		path string
		key  string
		url  string
		dial string
	}{
		{filepath.Join(dir, "wrong-name.json"), testSetupKey, "https://api.example.test:443", ""},
		{validPath, "not-a-key", "https://api.example.test:443", ""},
		{validPath, testSetupKey, "file:///tmp/management", ""},
		{validPath, testSetupKey, "https://", ""},
		{validPath, testSetupKey, "https://api.example.test:443", "192.0.2.1:18443"},
	}
	for i, test := range tests {
		if err := writeHarmonyCredentialImport(test.path, test.key, test.url, test.dial); err == nil {
			t.Fatalf("case %d accepted invalid input", i)
		}
	}
}

func TestHarmonyManagementTransportAddress(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		override string
		want     string
		wantErr  bool
	}{
		{name: "https default", rawURL: "https://api.example.test", want: "api.example.test:443"},
		{name: "http default", rawURL: "http://api.example.test", want: "api.example.test:80"},
		{name: "explicit port", rawURL: "https://api.example.test:8443", want: "api.example.test:8443"},
		{name: "private override", rawURL: "https://api.example.test", override: "127.0.0.1:18447", want: "127.0.0.1:18447"},
		{name: "invalid scheme", rawURL: "ftp://api.example.test", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := url.Parse(test.rawURL)
			got, err := harmonyManagementTransportAddress(parsed, test.override)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got %q, %v; want %q", got, err, test.want)
			}
		})
	}
}
