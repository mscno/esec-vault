// Package securitykey finds the security keys plugged into this machine
// (YubiKeys with an age identity, through age-plugin-yubikey) and keeps the
// list of the person's own security keys: in their account's chain when
// signed in to a vault server, and in a local file otherwise (and as a copy
// of the chain's, for the background service and the Mac app).
//
// Nobody types a recipient: keys are plugged in, found here, named, and
// registered; seals for the person then include them.
package securitykey

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/paths"
)

// Detected is an age identity on a plugged-in YubiKey.
type Detected struct {
	Serial      string `json:"serial"`
	Slot        string `json:"slot"`
	Name        string `json:"name"`
	Recipient   string `json:"recipient"`
	PINPolicy   string `json:"pin_policy,omitempty"`
	TouchPolicy string `json:"touch_policy,omitempty"`
}

// TouchAlways reports whether every decryption needs a touch: anything less
// lets other programs in for a while after one.
func (d Detected) TouchAlways() bool { return strings.EqualFold(d.TouchPolicy, "Always") }

// ErrNoPlugin is returned when age-plugin-yubikey is not installed.
var ErrNoPlugin = errors.New("age-plugin-yubikey is not installed: brew install age-plugin-yubikey")

// Run runs a command and returns its standard output; tests replace it.
var Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		if name == "age-plugin-yubikey" {
			return nil, ErrNoPlugin
		}
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Detect lists the age identities on the YubiKeys plugged in now.
func Detect(ctx context.Context) ([]Detected, error) {
	out, err := Run(ctx, "age-plugin-yubikey", "--list")
	if err != nil {
		return nil, err
	}
	return Parse(string(out))
}

// DetectUnprovisioned returns the serials of plugged-in YubiKeys that hold
// no age identity yet. It needs ykman to list YubiKeys; without it, it
// returns none.
func DetectUnprovisioned(ctx context.Context) ([]string, error) {
	out, err := Run(ctx, "ykman", "list", "--serials")
	if err != nil {
		return nil, nil //nolint:nilerr // no ykman: cannot tell, which is not a failure
	}
	present, err := Detect(ctx)
	if err != nil && !errors.Is(err, ErrNoPlugin) {
		return nil, err
	}
	have := map[string]bool{}
	for _, d := range present {
		have[d.Serial] = true
	}
	var none []string
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" && !have[s] {
			none = append(none, s)
		}
	}
	return none, nil
}

// Parse reads the output of age-plugin-yubikey --list (or --list-all):
// comment lines describing a slot, then its recipient.
//
//	#       Serial: 15584441, Slot: 1
//	#         Name: age identity 1a2b3c4d
//	#      Created: Sun, 18 Apr 2021 10:20:43 +0000
//	#   PIN policy: Once   (A PIN is required once per session, if set)
//	# Touch policy: Always (A physical touch is required for every decryption)
//	age1yubikey1q…
func Parse(out string) ([]Detected, error) {
	var found []Detected
	var cur Detected
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "#"); ok {
			key, value, ok := strings.Cut(strings.TrimSpace(rest), ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch strings.TrimSpace(key) {
			case "Serial":
				serial, slot, _ := strings.Cut(value, ",")
				cur.Serial = strings.TrimSpace(serial)
				if s, ok := strings.CutPrefix(strings.TrimSpace(slot), "Slot:"); ok {
					cur.Slot = strings.TrimSpace(s)
				}
			case "Name":
				cur.Name = value
			case "PIN policy":
				cur.PINPolicy = firstWord(value)
			case "Touch policy":
				cur.TouchPolicy = firstWord(value)
			}
			continue
		}
		if strings.HasPrefix(line, "age1yubikey1") {
			cur.Recipient = line
			found = append(found, cur)
			cur = Detected{}
		}
	}
	return found, sc.Err()
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// ID names a YubiKey slot: "yubikey:<serial>:<slot>".
func ID(serial, slot string) string {
	if slot == "" {
		slot = "1"
	}
	return "yubikey:" + serial + ":" + slot
}

// DefaultName is the name offered for a newly found key.
func DefaultName(d Detected) string {
	if d.Serial == "" {
		return "YubiKey"
	}
	return "YubiKey " + d.Serial
}

// FromDetected is the security key of a detected slot, named name.
func FromDetected(d Detected, name string) chain.SecurityKey {
	if name == "" {
		name = DefaultName(d)
	}
	return chain.SecurityKey{ID: ID(d.Serial, d.Slot), Kind: chain.SecurityKeyYubiKey, Recipient: d.Recipient, Name: name, Serial: d.Serial}
}

// Entry is a security key as this machine keeps it.
type Entry struct {
	ID        string    `toml:"id" json:"id"`
	Kind      string    `toml:"kind" json:"kind"`
	Recipient string    `toml:"recipient" json:"recipient"`
	Name      string    `toml:"name" json:"name"`
	Serial    string    `toml:"serial,omitempty" json:"serial,omitempty"`
	Tested    time.Time `toml:"tested,omitzero" json:"tested,omitzero"`
}

// Key returns the entry as a chain security key.
func (e Entry) Key() chain.SecurityKey {
	return chain.SecurityKey{ID: e.ID, Kind: e.Kind, Recipient: e.Recipient, Name: e.Name, Serial: e.Serial}
}

// Registry is this machine's list of the person's security keys.
type Registry struct {
	// Source is "account" when the list is a copy of the account's chain,
	// "local" when it is the list itself (not signed in).
	Source string  `toml:"source"`
	Keys   []Entry `toml:"key"`
}

// File is where the registry lives.
func File() string { return filepath.Join(paths.Home(), "security-keys.toml") }

// Load reads the registry; a missing file is an empty local one.
func Load() (*Registry, error) {
	data, err := os.ReadFile(File())
	if errors.Is(err, fs.ErrNotExist) {
		return &Registry{Source: "local"}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := toml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", File(), err)
	}
	if r.Source == "" {
		r.Source = "local"
	}
	return &r, nil
}

// Save writes the registry atomically, readable by its owner only.
func (r *Registry) Save() error {
	sort.Slice(r.Keys, func(i, j int) bool { return r.Keys[i].ID < r.Keys[j].ID })
	var buf bytes.Buffer
	buf.WriteString("# Your security keys (esec vault security-keys). Public keys only.\n")
	if err := toml.NewEncoder(&buf).Encode(r); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(File()), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(File()), ".security-keys-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), File())
}

// Find returns the entry with id, or with name (case-insensitive).
func (r *Registry) Find(idOrName string) (*Entry, bool) {
	for i, e := range r.Keys {
		if e.ID == idOrName {
			return &r.Keys[i], true
		}
	}
	var match *Entry
	for i, e := range r.Keys {
		if strings.EqualFold(e.Name, idOrName) {
			if match != nil {
				return nil, false // ambiguous
			}
			match = &r.Keys[i]
		}
	}
	return match, match != nil
}

// Has reports whether recipient is registered.
func (r *Registry) Has(recipient string) bool {
	for _, e := range r.Keys {
		if e.Recipient == recipient {
			return true
		}
	}
	return false
}

// Add records a key locally; a key with the same recipient is replaced.
func (r *Registry) Add(k chain.SecurityKey) error {
	if err := chain.ValidateSecurityKey(k); err != nil {
		return err
	}
	for _, e := range r.Keys {
		if e.ID == k.ID && e.Recipient != k.Recipient {
			return fmt.Errorf("another key is registered as %s", k.ID)
		}
	}
	r.Remove(k.Recipient)
	r.Keys = append(r.Keys, Entry{ID: k.ID, Kind: k.Kind, Recipient: k.Recipient, Name: k.Name, Serial: k.Serial})
	return nil
}

// Remove forgets the key with recipient, id or name; it reports whether
// there was one.
func (r *Registry) Remove(key string) bool {
	for i, e := range r.Keys {
		if e.Recipient == key || e.ID == key || strings.EqualFold(e.Name, key) {
			r.Keys = append(r.Keys[:i], r.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// Refresh replaces the list with the account's keys, keeping when each was
// last tested here.
func (r *Registry) Refresh(keys []chain.SecurityKey) {
	tested := map[string]time.Time{}
	for _, e := range r.Keys {
		tested[e.Recipient] = e.Tested
	}
	r.Source = "account"
	r.Keys = r.Keys[:0]
	for _, k := range keys {
		r.Keys = append(r.Keys, Entry{ID: k.ID, Kind: k.Kind, Recipient: k.Recipient, Name: k.Name, Serial: k.Serial, Tested: tested[k.Recipient]})
	}
}

// SecurityKeys returns the registry's keys, by name.
func (r *Registry) SecurityKeys() []chain.SecurityKey {
	out := make([]chain.SecurityKey, 0, len(r.Keys))
	for _, e := range r.Keys {
		out = append(out, e.Key())
	}
	// In the order the account lists them.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Mine returns the person's security keys: the account's when a is a
// signed-in account (refreshing the local copy), else the local list.
func Mine(ctx context.Context, a *account.Account) ([]chain.SecurityKey, error) {
	r, err := Load()
	if err != nil {
		return nil, err
	}
	if a == nil {
		return r.SecurityKeys(), nil
	}
	keys, err := a.SecurityKeys(ctx)
	if err != nil {
		return nil, err
	}
	if r.Source == "local" {
		// Keys registered here before signing in join the account, once.
		if keys, err = publishLocal(ctx, a, r, keys); err != nil {
			return nil, err
		}
	}
	r.Refresh(keys)
	_ = r.Save() // a copy for the background service and the app; the chain is the authority
	return keys, nil
}

// publishLocal adds the keys of a local list the account lacks to the
// account, returning the account's keys after.
func publishLocal(ctx context.Context, a *account.Account, r *Registry, keys []chain.SecurityKey) ([]chain.SecurityKey, error) {
	have := map[string]bool{}
	for _, k := range keys {
		have[k.Recipient] = true
	}
	added := false
	for _, e := range r.Keys {
		if have[e.Recipient] {
			continue
		}
		if err := a.AddSecurityKey(ctx, e.Key()); err != nil {
			return nil, fmt.Errorf("add %s to your account: %w", e.Name, err)
		}
		added = true
	}
	if !added {
		return keys, nil
	}
	return a.SecurityKeys(ctx)
}
