package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// PurgePaths previews only known vault data. It never walks arbitrary directory
// trees and never includes transport credentials or remote objects.
func PurgePaths() ([]string, error) {
	if info, err := os.Lstat(paths.Home()); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink vault home")
	}
	var out []string
	for _, name := range []string{"identity.esec", "identity.esec.previous", "identity.esec.v1.bak", "vault.esec", "download.esec", "remote.toml", "remote-state.json", "push-dirty.json", "policy.toml", "trusted.toml", "audit.log", "agent.pid", "agent.sock"} {
		p := filepath.Join(paths.Home(), name)
		if info, err := os.Lstat(p); err == nil {
			if info.IsDir() {
				return nil, fmt.Errorf("unexpected directory %s", p)
			}
			out = append(out, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	for dir, suffix := range map[string]string{paths.KeyringDir(): ".keyring", filepath.Join(paths.Home(), "snapshots"): ".esec"} {
		if info, err := os.Lstat(dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink directory %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Purge removes previewed local data and the two esec-vault OS-keyring entries.
// The caller must first stop/uninstall the service and obtain explicit consent.
func Purge(kr keyring.Keyring, preview []string) error {
	current, err := PurgePaths()
	if err != nil {
		return err
	}
	if strings.Join(current, "\x00") != strings.Join(preview, "\x00") {
		return fmt.Errorf("vault changed after purge preview; retry")
	}
	if err := noActiveSockets(current); err != nil {
		return err
	}
	var releases []func()
	var lockPaths []string
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for _, dir := range []string{paths.Home(), paths.KeyringDir(), filepath.Join(paths.Home(), "uploads")} {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		release, err := storage.Lock(dir)
		if err != nil {
			return err
		}
		releases = append(releases, release)
		lockPaths = append(lockPaths, filepath.Join(dir, ".mutation-lock"))
	}
	for _, key := range []string{keyring.IdentityPrivateKey, keyring.IdentityPublicKey} {
		if err := kr.Delete(key); err != nil {
			return err
		}
	}
	for _, p := range current {
		if err := remove(p); err != nil {
			return err
		}
	}
	for _, p := range lockPaths {
		if err := remove(p); err != nil {
			return err
		}
	}
	for _, release := range releases {
		release()
	}
	releases = nil
	for _, dir := range []string{paths.KeyringDir(), filepath.Join(paths.Home(), "snapshots"), filepath.Join(paths.Home(), "uploads"), paths.Home()} {
		if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
			if err := os.Remove(dir); err != nil {
				return err
			}
		}
	}
	return nil
}

func noActiveSockets(files []string) error {
	for _, p := range files {
		if info, err := os.Lstat(p); err != nil {
			return err
		} else if info.Mode()&os.ModeSocket != 0 {
			if conn, err := net.DialTimeout("unix", p, time.Second); err == nil {
				conn.Close()
				return fmt.Errorf("stop legacy agent before purging: %s", p)
			}
		}
	}
	return nil
}

func sortedEnvironment(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
