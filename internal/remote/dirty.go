package remote

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// dirty marks that the keyring store changed and a push should happen once
// the debounce window has elapsed. It is separate from push state: a pending
// change that has not been uploaded yet.
type dirtyFile struct {
	Dirty    bool      `json:"dirty"`
	FirstAt  time.Time `json:"first_at"`
	Reason   string    `json:"reason"`
	Projects int       `json:"projects"`
}

// DirtyPath returns the dirty-marker path.
func DirtyPath() string { return filepath.Join(paths.Home(), "push-dirty.json") }

// MarkDirty records that something changed and a push is pending.
func MarkDirty(reason string, projects int) error {
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	d := &dirtyFile{Dirty: true, FirstAt: time.Now().UTC(), Reason: reason, Projects: projects}
	if raw, err := os.ReadFile(DirtyPath()); err == nil {
		var old dirtyFile
		if err := json.Unmarshal(raw, &old); err != nil {
			return err
		}
		if old.Dirty {
			d.FirstAt = old.FirstAt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return storage.Write(DirtyPath(), data)
}

// IsDirty reports whether a push is pending.
func IsDirty() bool {
	data, err := os.ReadFile(DirtyPath())
	if err != nil {
		return false
	}
	var d dirtyFile
	if err := json.Unmarshal(data, &d); err != nil {
		return false
	}
	return d.Dirty
}

// DirtyReason returns the pending-change reason and age.
func DirtyReason() (reason string, age time.Duration, ok bool) {
	data, err := os.ReadFile(DirtyPath())
	if err != nil {
		return "", 0, false
	}
	var d dirtyFile
	if err := json.Unmarshal(data, &d); err != nil || !d.Dirty {
		return "", 0, false
	}
	return d.Reason, time.Since(d.FirstAt), true
}

// DebounceElapsed reports whether enough time has passed since the change to
// push now.
func DebounceElapsed(debounce time.Duration) bool {
	_, age, ok := DirtyReason()
	if !ok {
		return false
	}
	return age >= debounce
}

// ClearDirty removes the pending marker after a successful push.
func ClearDirty() error {
	if err := os.Remove(DirtyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
