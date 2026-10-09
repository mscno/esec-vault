package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/mscno/esec-vault/internal/paths"
)

// Watch parent directories rather than files: atomic replacement changes inodes.
// Events are hints; the periodic scan remains authoritative after overflows or
// edits while the service was stopped.
func (s *Server) watch(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		close(s.watchReady)
		s.Logger.Warn("file notifications unavailable; using periodic scan", "error", err)
		return
	}
	defer w.Close()
	if err := os.MkdirAll(paths.KeyringDir(), 0700); err != nil {
		close(s.watchReady)
		s.Logger.Warn("keyring watcher unavailable", "error", err)
		return
	}
	for _, dir := range []string{paths.Home(), paths.KeyringDir()} {
		if err := w.Add(dir); err != nil {
			s.Logger.Warn("directory watcher unavailable", "path", dir, "error", err)
		}
	}
	close(s.watchReady)
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			name := filepath.Base(event.Name)
			if !strings.HasSuffix(name, ".keyring") && name != "identity.esec" && name != "policy.toml" && name != "trusted.toml" && name != "remote.toml" {
				continue
			}
			select {
			case s.wake <- struct{}{}:
			default:
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			s.Logger.Warn("missed filesystem notification; scan will reconcile", "error", err)
		}
	}
}
