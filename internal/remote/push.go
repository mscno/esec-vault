package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// State is the local record of what has been pushed. It lives beside
// remote.toml and is not secret: it holds object keys and timestamps.
type State struct {
	// LastPush is when a push last succeeded.
	LastPush time.Time `json:"last_push"`
	// Generation is the vault generation last pushed.
	Generation uint64 `json:"generation"`
	// Hash is the SHA-256 of the blob last pushed, for change detection.
	Hash string `json:"hash"`
	// Remote records the last successful push per remote name.
	Remote map[string]RemoteState `json:"remote"`
}

// RemoteState is per-remote push bookkeeping.
type RemoteState struct { //nolint:revive // retained name distinguishes per-destination state from aggregate State
	LastPush    time.Time `json:"last_push"`
	Generation  uint64    `json:"generation"`
	Hash        string    `json:"hash"`
	Key         string    `json:"key"`
	Destination string    `json:"destination"`
}

// ErrNotPushed is returned when a remote has never been pushed to.
var ErrNotPushed = errors.New("never pushed")

// StatePath returns the state file path.
func StatePath() string { return filepath.Join(paths.Home(), "remote-state.json") }

// LoadState reads the push state, treating a missing file as empty state.
func LoadState() (*State, error) {
	data, err := os.ReadFile(StatePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{Remote: map[string]RemoteState{}}, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid remote state: %w", err)
	}
	if s.Remote == nil {
		s.Remote = map[string]RemoteState{}
	}
	return &s, nil
}

// Save writes the state file (0600).
func (s *State) Save() error {
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(StatePath(), data)
}

// PushResult describes a completed push.
type PushResult struct {
	Remote     string
	Key        string
	Generation uint64
	Skipped    bool
	Verified   bool
}

// Push writes blob to the named remote (or the default) under a
// generation-named key, records state, and verifies by reading the object
// back unless verify is false. A push whose content is unchanged since the
// last successful push is skipped.
func Push(ctx context.Context, cfg *Config, remoteName string, blob []byte, generation uint64, fingerprint string, createdAt time.Time, verify bool) (*PushResult, error) {
	unlock, err := storage.Lock(filepath.Join(paths.Home(), "uploads"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	cfg, err = configured(cfg)
	if err != nil {
		return nil, err
	}
	name, entry, err := cfg.Resolve(remoteName)
	if err != nil {
		return nil, err
	}
	be, err := New(entry)
	if err != nil {
		return nil, err
	}

	state, err := LoadState()
	if err != nil {
		return nil, err
	}
	prev := state.Remote[name]
	sum := hashObject(blob)
	target, err := json.Marshal(entry) //nolint:musttag // destination hash uses exported fields, not a persistence format
	if err != nil {
		return nil, err
	}
	destination := hashObject(target)
	if prev.Hash == sum && prev.Key != "" && prev.Destination == destination {
		if verify {
			if err := verifyObject(ctx, be, prev.Key, sum); err != nil {
				return nil, err
			}
		}
		// Nothing changed since the last push; avoid a pointless upload.
		return &PushResult{Remote: name, Key: prev.Key, Generation: prev.Generation, Skipped: true, Verified: verify}, nil
	}

	key := GenerationName(createdAt, generation, fingerprint)
	if old, err := be.Get(ctx, key); err == nil && hashObject(old) != sum {
		return nil, fmt.Errorf("remote generation already exists with different content")
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := be.Put(ctx, key, blob); err != nil {
		return nil, fmt.Errorf("push to %q failed: %w", name, err)
	}

	res := &PushResult{Remote: name, Key: key, Generation: generation}
	if verify {
		if err := verifyObject(ctx, be, key, sum); err != nil {
			return nil, err
		}
		res.Verified = true
	}

	now := time.Now().UTC()
	state.Remote[name] = RemoteState{LastPush: now, Generation: generation, Hash: sum, Key: key, Destination: destination}
	state.LastPush = now
	state.Generation = generation
	state.Hash = sum
	if err := state.Save(); err != nil {
		return nil, err
	}
	return res, nil
}

func configured(cfg *Config) (*Config, error) {
	if cfg == nil {
		return Load()
	}
	return cfg, nil
}

func verifyObject(ctx context.Context, be Backend, key, sum string) error {
	back, err := be.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read-back failed: %w", err)
	}
	if hashObject(back) != sum {
		return fmt.Errorf("remote copy differs from local snapshot")
	}
	return nil
}

// vaultKeys filters a backend listing down to vault generation objects and
// returns them oldest-first, with the configured prefix stripped so the result
// can be passed straight back to Get/Delete without double-prefixing.
// Object names embed a UTC timestamp, so lexicographic order is chronological.
func vaultKeys(keys []string, _ string) []string {
	var out []string
	for _, k := range keys {
		if _, ok := ParseGeneration(k); ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Latest fetches the most recent generation object for a remote, returning its
// key and bytes. The newest object name wins.
func Latest(ctx context.Context, cfg *Config, remoteName string) (key string, blob []byte, err error) {
	if cfg == nil {
		var lerr error
		cfg, lerr = Load()
		if lerr != nil {
			return "", nil, lerr
		}
	}
	_, entry, err := cfg.Resolve(remoteName)
	if err != nil {
		return "", nil, err
	}
	be, err := New(entry)
	if err != nil {
		return "", nil, err
	}
	keys, err := be.List(ctx, "vaults/")
	if err != nil {
		return "", nil, err
	}
	generations := vaultKeys(keys, entry.Prefix)
	if len(generations) == 0 {
		return "", nil, ErrNotPushed
	}
	key = generations[len(generations)-1]
	blob, err = be.Get(ctx, key)
	if err != nil {
		return key, nil, err
	}
	return key, blob, nil
}

// Prune deletes old generations beyond keep, newest first. It reports the keys
// it removed. Pruning is opt-in; object stores with versioning make it safe to
// run periodically.
func Prune(ctx context.Context, cfg *Config, remoteName string, keep int) (removed []string, err error) {
	if keep <= 0 {
		return nil, fmt.Errorf("keep must be positive")
	}
	if cfg == nil {
		var lerr error
		cfg, lerr = Load()
		if lerr != nil {
			return nil, lerr
		}
	}
	_, entry, err := cfg.Resolve(remoteName)
	if err != nil {
		return nil, err
	}
	be, err := New(entry)
	if err != nil {
		return nil, err
	}
	keys, err := be.List(ctx, "vaults/")
	if err != nil {
		return nil, err
	}
	generations := vaultKeys(keys, entry.Prefix)
	if len(generations) <= keep {
		return nil, nil
	}
	// Prove the retained newest object is readable before deleting history.
	if len(generations) > 0 {
		if _, err := be.Get(ctx, generations[len(generations)-1]); err != nil {
			return nil, err
		}
	}
	for _, k := range generations[:len(generations)-keep] {
		if err := be.Delete(ctx, k); err != nil {
			return removed, fmt.Errorf("prune %s: %w", k, err)
		}
		removed = append(removed, k)
	}
	return removed, nil
}

// ParseGeneration extracts the generation number from an object key name.
func ParseGeneration(key string) (uint64, bool) {
	if !generationPattern.MatchString(key) {
		return 0, false
	}
	base := filepath.Base(key)
	i := strings.Index(base, "-gen")
	if i < 0 {
		return 0, false
	}
	rest := base[i+4:]
	j := strings.Index(rest, "-")
	if j < 0 {
		j = len(rest)
	}
	n, err := strconv.ParseUint(rest[:j], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

var generationPattern = regexp.MustCompile(`^vaults/[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-gen[0-9]{20}-[a-fA-F0-9]+\.esec$`)

// ShortHash renders a hash for display.
func ShortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
