package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAppMigrationPreservesKeysAndPendingWork(t *testing.T) {
	m, f := manager(t, "darwin")
	ctx := context.Background()
	exe := source(t)
	if err := m.Install(ctx, exe, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.esec", "keyrings/project.keyring", "server/pending.esec"} {
		path := filepath.Join(m.Manifest.Home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unchanged ciphertext"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := m.UseApp(ctx); err != nil {
			t.Fatal(err)
		}
		if f.running || f.loaded || f.enabled {
			t.Fatal("legacy service still enabled")
		}
	}
	for _, name := range []string{"identity.esec", "keyrings/project.keyring", "server/pending.esec"} {
		data, err := os.ReadFile(filepath.Join(m.Manifest.Home, name)) //nolint:gosec // synthetic files under the test vault
		if err != nil || string(data) != "unchanged ciphertext" {
			t.Fatalf("changed vault data %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(m.Manifest.Home, "desktop-managed")); err != nil {
		t.Fatal(err)
	}
	if err := m.Install(ctx, exe, true); err != nil {
		t.Fatal("explicit return to service failed:", err)
	}
	if err := m.UseService(); err != nil {
		t.Fatal(err)
	}
	if !f.running || !f.enabled {
		t.Fatal("explicit standalone service did not start")
	}
}

func TestAppMigrationRefusesFailedStopAndForeignManifest(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		m, f := manager(t, "darwin")
		if err := m.Install(context.Background(), source(t), true); err != nil {
			t.Fatal(err)
		}
		if malformed {
			if err := os.WriteFile(m.manifestPath(), []byte(`{"version":999}`), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			f.failStop = true
		}
		if err := m.UseApp(context.Background()); err == nil {
			t.Fatal("unsafe migration accepted")
		}
		if _, err := os.Stat(filepath.Join(m.Manifest.Home, "desktop-managed")); !os.IsNotExist(err) {
			t.Fatal("failed migration claimed ownership")
		}
		if !f.running {
			t.Fatal("foreign/unstoppable service was changed")
		}
	}
}

func TestLinuxCannotMigrateToMacApp(t *testing.T) {
	m, f := manager(t, "linux")
	if err := m.UseApp(context.Background()); err == nil {
		t.Fatal("Linux app ownership accepted")
	}
	if len(f.commands) != 0 {
		t.Fatal("Linux service was changed")
	}
}

func TestAppMigrationDoesNotSilentlyChangeCustomKeyringDirectory(t *testing.T) {
	m, f := manager(t, "darwin")
	t.Setenv("ESEC_KEYRING_DIR", filepath.Join(t.TempDir(), "custom-keyrings"))
	if err := m.Install(context.Background(), source(t), true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_KEYRING_DIR", "")
	if err := m.UseApp(context.Background()); err == nil {
		t.Fatal("migration silently changed the keyring location")
	}
	if !f.running || !f.enabled {
		t.Fatal("migration stopped the service before checking its keyring location")
	}
}
