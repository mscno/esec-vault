package service

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
)

type exitError int

func (e exitError) Error() string { return fmt.Sprint(int(e)) }
func (e exitError) ExitCode() int { return int(e) }

type fakeOS struct {
	unit                     string
	loaded, running, enabled bool
	failStop                 bool
	commands                 []string
}

func (f *fakeOS) run(_ context.Context, name string, args ...string) ([]byte, error) {
	s := strings.Join(args, " ")
	f.commands = append(f.commands, name+" "+s)
	if name == "launchctl" {
		switch args[0] {
		case "print":
			if !f.loaded {
				return nil, exitError(113)
			}
			return []byte("running"), nil
		case "enable":
			f.enabled = true
		case "disable":
			f.enabled = false
		case "bootstrap", "kickstart":
			f.loaded = true
			f.running = true
		case "bootout":
			if f.failStop {
				return nil, fmt.Errorf("stop failed")
			}
			f.loaded = false
			f.running = false
		}
	} else {
		switch args[1] {
		case "enable":
			f.enabled = true
		case "disable":
			f.enabled = false
		case "start":
			f.loaded = true
			f.running = true
		case "stop":
			if f.failStop {
				return nil, fmt.Errorf("stop failed")
			}
			f.running = false
		case "daemon-reload":
			_, err := os.Stat(f.unit)
			f.loaded = err == nil
		case "show":
			if strings.Contains(s, "LoadState") {
				if f.loaded {
					return []byte("loaded"), nil
				}
				return []byte("not-found"), nil
			}
			if f.running {
				return []byte("100"), nil
			}
			return []byte("0"), nil
		}
	}
	return nil, nil
}

func manager(t *testing.T, platform string) (*Manager, *fakeOS) {
	t.Helper()
	dir := t.TempDir()
	f := &fakeOS{}
	m, err := NewAt(platform, 501, dir, filepath.Join(dir, "vault & spaces"), "", f.run)
	if err != nil {
		t.Fatal(err)
	}
	f.unit = m.Manifest.Unit
	return m, f
}
func source(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "exe")
	if err := os.WriteFile(p, []byte("test executable"), 0700); err != nil { //nolint:gosec // test executable fixture
		t.Fatal(err)
	}
	return p
}

func TestInstallDisableStartUninstallBothPlatforms(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, f := manager(t, platform)
			ctx := context.Background()
			if err := m.Install(ctx, source(t), true); err != nil {
				t.Fatal(err)
			}
			if !f.running || !f.enabled {
				t.Fatal("not started/enabled")
			}
			secret := filepath.Join(m.Manifest.Home, "vault.esec")
			if err := os.WriteFile(secret, []byte("ciphertext"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := m.Disable(ctx); err != nil {
				t.Fatal(err)
			}
			if f.running || f.enabled {
				t.Fatal("disable left running service")
			}
			if err := m.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := m.Uninstall(ctx); err != nil {
				t.Fatal(err)
			}
			if f.running || f.loaded {
				t.Fatal("dangling service")
			}
			for _, p := range append(m.artifacts(), m.Manifest.Unit, m.manifestPath()) {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("leftover %s: %v", p, err)
				}
			}
			if _, err := os.Stat(secret); err != nil {
				t.Fatal("uninstall deleted vault", err)
			}
			if err := m.Uninstall(ctx); err != nil {
				t.Fatal("uninstall not idempotent", err)
			}
		})
	}
}

func TestFailedStopPreservesManifestAndExecutable(t *testing.T) {
	m, f := manager(t, "darwin")
	if err := m.Install(context.Background(), source(t), true); err != nil {
		t.Fatal(err)
	}
	f.failStop = true
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("ignored failed stop")
	}
	for _, p := range []string{m.Manifest.Binary, m.manifestPath()} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}
func TestForgedManifestCannotDeleteOtherFiles(t *testing.T) {
	m, _ := manager(t, "linux")
	if err := m.Install(context.Background(), source(t), false); err != nil {
		t.Fatal(err)
	}
	forged := m.Manifest
	forged.Binary = source(t)
	data, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.manifestPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("accepted forged ownership")
	}
	if _, err := os.Stat(forged.Binary); err != nil {
		t.Fatal("deleted unowned file")
	}
}
func TestUnitsEscapePathsAndDoNotPersistSecrets(t *testing.T) {
	m, _ := manager(t, "darwin")
	m.Manifest.Environment["PATH"] = "a&b<c>\"d"
	data, err := m.UnitContents()
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "&amp;") {
		t.Fatal("unescaped XML")
	}
	m, _ = manager(t, "linux")
	m.Manifest.Binary += " $HOME %n"
	data, err = m.UnitContents()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "$$HOME %%n") {
		t.Fatal("systemd expansion not escaped")
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-be-saved")
	if err := m.Install(context.Background(), source(t), false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.manifestPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "must-not-be-saved") {
		t.Fatal("credential in manifest")
	}
}

func TestPurgeRemovesKeysAndPreservesUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", dir)
	t.Setenv("ESEC_KEYRING_DIR", "")
	kr := keyring.NewMemory()
	if err := kr.Set("unrelated", "keep"); err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(keyring.IdentityPrivateKey, "test"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{paths.IdentityFile(), paths.VaultFile(), filepath.Join(paths.KeyringDir(), "org_repo.keyring"), filepath.Join(dir, "snapshots", "one.esec"), filepath.Join(dir, "notes.txt")} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	preview, err := PurgePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := Purge(kr, preview); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Get(keyring.IdentityPrivateKey); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("keychain entry remains")
	}
	if value, err := kr.Get("unrelated"); err != nil || value != "keep" {
		t.Fatal("purged unrelated keychain entry")
	}
	for _, p := range preview {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("leftover %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("removed unknown file")
	}
	if err := Purge(kr, nil); err != nil {
		t.Fatal("purge not repeatable", err)
	}
}

func TestPurgeRejectsChangedPreview(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", "")
	preview, err := PurgePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.VaultFile(), []byte("new backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Purge(keyring.NewMemory(), preview); err == nil {
		t.Fatal("accepted changed preview")
	}
	if _, err := os.Stat(paths.VaultFile()); err != nil {
		t.Fatal("deleted unconfirmed file")
	}
}

// Opt-in test uses a short-lived isolated service running only /bin/sleep,
// never the user's real daemon, vault, keychain or transport credentials.
func TestNativeUserServiceLifecycle(t *testing.T) {
	if os.Getenv("ESEC_TEST_NATIVE_SERVICE") != "1" {
		t.Skip("opt-in native service test")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no user service manager")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewAt(runtime.GOOS, os.Getuid(), home, t.TempDir(), os.Getenv("XDG_CONFIG_HOME"), run)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "test-daemon")
	if err := os.WriteFile(src, []byte("#!/bin/sh\nexec /bin/sleep 600\n"), 0700); err != nil { //nolint:gosec // isolated executable fixture
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := m.Uninstall(ctx); err != nil {
			t.Error("service cleanup:", err)
		}
	})
	if err := m.Install(ctx, src, true); err != nil {
		t.Fatal(err)
	}
	if running, err := m.Running(ctx); err != nil || !running {
		t.Fatalf("running=%t err=%v", running, err)
	}
	if err := m.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
}
