package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// AppManaged remembers the Mac app's ownership even while the app is closed.
// Setup must not silently re-install a competing LaunchAgent in that case.
func AppManaged() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := os.Stat(filepath.Join(paths.Home(), "desktop-managed"))
	return err == nil
}

// UseApp stops only our validated legacy LaunchAgent, preserving its manifest
// and every key/cache/pending revision. A later explicit service install can
// reuse it. The caller holds the app-helper process lock throughout its life.
func (m *Manager) UseApp(ctx context.Context) error {
	if m.Manifest.OS != "darwin" {
		return fmt.Errorf("app-owned helper requires macOS")
	}
	if err := m.validateDirectories(); err != nil {
		return err
	}
	if err := m.load(); err == nil {
		data, err := os.ReadFile(m.manifestPath())
		if err != nil {
			return err
		}
		var installed Manifest
		if err := json.Unmarshal(data, &installed); err != nil {
			return err
		}
		if dir := installed.Environment["ESEC_KEYRING_DIR"]; dir != "" && filepath.Clean(dir) != filepath.Clean(paths.KeyringDir()) {
			return fmt.Errorf("legacy service uses a custom ESEC_KEYRING_DIR (%s); launch EsecVault with that same directory before migrating", dir)
		}
		if err := m.Disable(ctx); err != nil {
			return fmt.Errorf("stop legacy background service: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return storage.Write(filepath.Join(m.Manifest.Home, "desktop-managed"), []byte("EsecVault owns the local helper. Open the app to start it.\n"))
}

// UseService records an explicit return to standalone service management.
func (m *Manager) UseService() error {
	return remove(filepath.Join(m.Manifest.Home, "desktop-managed"))
}
