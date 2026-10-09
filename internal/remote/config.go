// Package remote stores sealed vault blobs outside the local machine.
//
// Design rule: esec-vault stores no credentials. Each backend delegates
// authentication to the tool that already owns it — rclone reads its own
// config file, restic reads environment variables — so the remote config only
// ever names *where* credentials live. That is what lets a single
// non-secret TOML file hold the whole configuration.
//
// Config lives at ~/.config/esec/remote.toml (override with ESEC_VAULT_HOME).
package remote

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
)

// Backend names.
const (
	TypeFile   = "file"
	TypeRclone = "rclone"
	TypeRestic = "restic"
	TypeExec   = "exec"
)

// Push modes.
const (
	PushOnChange = "on-change"
	PushManual   = "manual"
)

// Config is the parsed remote.toml.
type Config struct {
	Default string           `toml:"default"`
	Policy  Policy           `toml:"policy"`
	Remotes map[string]Entry `toml:"remotes"`
}

// Policy controls automatic pushing.
type Policy struct {
	// Push is "on-change" (push after mutations, debounced) or "manual".
	Push string `toml:"push"`
	// Debounce is how long to wait after a mutation before pushing.
	Debounce string `toml:"debounce"`
	// Keep is how many generations to retain on the remote.
	Keep int `toml:"keep"`
	// Interval is how often the agent re-checks for changes (0 = never).
	Interval string `toml:"interval"`
}

// Entry is one configured destination.
type Entry struct {
	Type        string `toml:"type"`
	Description string `toml:"description"`
	// Prefix namespaces objects within a bucket.
	Prefix string `toml:"prefix"`

	// file backend: a local directory (or a synced folder).
	Dir string `toml:"dir"`

	// rclone backend: the remote name as configured in rclone.conf, plus the
	// bucket and an optional path within it.
	RcloneRemote string `toml:"rclone_remote"`
	Bucket       string `toml:"bucket"`
	Path         string `toml:"path"`

	// restic backend: repository and password file are read from the
	// environment (RESTIC_REPOSITORY / RESTIC_PASSWORD_FILE), never stored.
	Repository string `toml:"repository"`

	// exec backend: a command template. {key} is replaced with the object key.
	Command string   `toml:"command"`
	Args    []string `toml:"args,omitempty"`
}

// Validate checks an entry has the fields its type requires.
func (e Entry) Validate() error {
	if err := validKey(e.Prefix, true); err != nil {
		return fmt.Errorf("prefix: %w", err)
	}
	if err := validKey(e.Path, true); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	switch e.Type {
	case TypeFile:
		if e.Dir == "" {
			return fmt.Errorf("file remote requires 'dir'")
		}
		if !filepath.IsAbs(e.Dir) {
			return fmt.Errorf("file remote dir must be absolute for daemon use")
		}
	case TypeRclone:
		if strings.ContainsAny(e.RcloneRemote, ":/\\ \r\n") || strings.ContainsAny(e.Bucket, "/\\\r\n") {
			return fmt.Errorf("invalid rclone remote or bucket")
		}
		if e.RcloneRemote == "" {
			return fmt.Errorf("rclone remote requires 'rclone_remote' (the name in rclone.conf)")
		}
		if e.Bucket == "" {
			return fmt.Errorf("rclone remote requires 'bucket'")
		}
	case TypeRestic:
		if e.Repository == "" {
			return fmt.Errorf("restic remote requires 'repository'")
		}
	case TypeExec:
		if e.Command == "" {
			return fmt.Errorf("exec remote requires 'command'")
		}
		if strings.ContainsAny(e.Command, "/\\") && !filepath.IsAbs(e.Command) {
			return fmt.Errorf("exec adapter must use an absolute path or a program name on PATH")
		}
	case "":
		return fmt.Errorf("remote requires 'type' (file, rclone, restic or exec)")
	default:
		return fmt.Errorf("unknown remote type %q (want file, rclone, restic or exec)", e.Type)
	}
	return nil
}

// DebounceDuration returns the parsed debounce duration.
func (p Policy) DebounceDuration() time.Duration {
	d, err := time.ParseDuration(p.Debounce)
	if err != nil || d < 0 {
		return 15 * time.Minute
	}
	return d
}

// IntervalDuration returns the parsed agent check interval.
func (p Policy) IntervalDuration() time.Duration {
	d, err := time.ParseDuration(p.Interval)
	if err != nil {
		return 0
	}
	return d
}

// AutoPush reports whether mutations should schedule a push. Only an explicit
// on-change policy auto-pushes; an unset or manual policy stays quiet so a
// half-configured setup never uploads anything unexpectedly.
func (p Policy) AutoPush() bool { return p.Push == PushOnChange }

// Retention returns how many generations to keep, defaulting to 30.
func (p Policy) Retention() int {
	if p.Keep <= 0 {
		return 30
	}
	return p.Keep
}

// DefaultConfig returns a config with no remotes.
func DefaultConfig() *Config {
	return &Config{
		Policy: Policy{
			Push:     PushOnChange,
			Debounce: "15m",
			Keep:     30,
			Interval: "1m",
		},
		Remotes: map[string]Entry{},
	}
}

// ConfigPath returns the remote.toml path.
func ConfigPath() string { return filepath.Join(paths.Home(), "remote.toml") }

// ErrNoConfig is returned when no remote.toml exists.
var ErrNoConfig = errors.New("no remote.toml found")

// Load reads remote.toml. A missing file yields an empty config with defaults,
// so callers can treat "not configured yet" uniformly.
func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	cfg := DefaultConfig()
	if err := CheckNoSecrets(data); err != nil {
		return nil, err
	}
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(cfg); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", ConfigPath(), err)
	}
	if cfg.Remotes == nil {
		cfg.Remotes = map[string]Entry{}
	}
	for name, e := range cfg.Remotes {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("remote %q: %w", name, err)
		}
	}
	if err := CheckNoSecrets(data); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes remote.toml with 0600 permissions.
func Save(cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	// Keep remote keys sorted for readable diffs.
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := CheckNoSecrets(data); err != nil {
		return err
	}
	return storage.Write(ConfigPath(), data)
}

// Validate rejects misspelled policies and invalid destination references.
func (c *Config) Validate() error {
	if c.Policy.Push != PushManual && c.Policy.Push != PushOnChange {
		return fmt.Errorf("policy.push must be manual or on-change")
	}
	for _, value := range []string{c.Policy.Debounce, c.Policy.Interval} {
		if d, err := time.ParseDuration(value); err != nil || d < 0 {
			return fmt.Errorf("invalid duration %q", value)
		}
	}
	if c.Policy.Keep <= 0 {
		return fmt.Errorf("policy.keep must be positive")
	}
	if c.Default != "" {
		if _, ok := c.Remotes[c.Default]; !ok {
			return fmt.Errorf("default remote %q does not exist", c.Default)
		}
	}
	for name, e := range c.Remotes {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("remote %s: %w", name, err)
		}
	}
	return nil
}

// Resolve returns the entry to use: an explicit name, else the default.
// The ESEC_VAULT_REMOTE environment variable overrides the config default so
// scripts and CI can redirect without editing files.
func (c *Config) Resolve(name string) (string, Entry, error) {
	if name == "" {
		name = os.Getenv("ESEC_VAULT_REMOTE")
	}
	if name == "" {
		name = c.Default
	}
	if name == "" {
		return "", Entry{}, fmt.Errorf("no remote configured; run 'esec-vault remote add' (or pass --remote)")
	}
	e, ok := c.Remotes[name]
	if !ok {
		known := c.Names()
		return "", Entry{}, fmt.Errorf("unknown remote %q (configured: %s)", name, strings.Join(known, ", "))
	}
	return name, e, nil
}

// Names returns configured remote names, sorted.
func (c *Config) Names() []string {
	out := make([]string, 0, len(c.Remotes))
	for k := range c.Remotes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// secretish matches key names that look like inline credentials. Config must
// never contain them; credentials belong to rclone/restic/the environment.
var secretish = []string{"secret", "password", "passphrase", "token", "credential", "api_key", "apikey", "private_key"}

// indirectionSuffixes mark a field as naming where a credential lives rather
// than holding one (e.g. secret_access_key_env = "R2_SECRET").
var indirectionSuffixes = []string{"_env", "_file", "_cmd", "_path", "_command"}

// CheckNoSecrets rejects inline credentials anywhere in remote.toml. The whole
// document is walked rather than a fixed field list, so a newly added field
// cannot silently bypass the check. Values may still *name* where a credential
// lives via an indirection suffix.
func CheckNoSecrets(data []byte) error {
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return err
	}
	var walk func(prefix string, node any) error
	walk = func(prefix string, node any) error {
		switch v := node.(type) {
		case map[string]any:
			for k, child := range v {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if err := walk(p, child); err != nil {
					return err
				}
			}
		case string:
			if v == "" || !looksSecret(prefix) || hasIndirectionSuffix(prefix) {
				return nil
			}
			return fmt.Errorf("refusing inline credential field %q — keep credentials in rclone.conf or the restic environment, or reference them with a %s suffix (e.g. %s_env)",
				prefix, strings.Join(indirectionSuffixes, "/"), strings.ToLower(shortestSecretWord(prefix)))
		}
		return nil
	}
	return walk("", doc)
}

// looksSecret reports whether a dotted key path names credential material.
func looksSecret(key string) bool {
	// Only inspect the final segment; "secret_access_key_env" is judged by its
	// own name, and a table named e.g. "secrets_dir" under a parent called
	// "remotes" should not trip on the parent.
	leaf := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		leaf = key[i+1:]
	}
	lower := strings.ToLower(leaf)
	for _, s := range secretish {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func hasIndirectionSuffix(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range indirectionSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// shortestSecretWord returns the matched keyword, for the error message.
func shortestSecretWord(key string) string {
	leaf := strings.ToLower(key)
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	best := leaf
	for _, s := range secretish {
		if strings.Contains(leaf, s) && len(s) < len(best) {
			best = s
		}
	}
	return best
}
