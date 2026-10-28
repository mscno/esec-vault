// Package guard keeps private keys that only a hardware touch can open.
//
// The guard is one age X25519 identity, the guard identity, stored wrapped
// to its holders: hardware keys through age plugins (age-plugin-yubikey,
// age-plugin-se) and the recovery key derived from the 24-word phrase. A
// guarded environment key is an age file encrypted to the guard identity.
// Reading one needs the guard identity, so a holder: for a YubiKey with
// touch policy "always", a physical touch that no process can make.
//
// Two levels keep holders cheap to change: adding or removing a YubiKey
// rewraps the guard identity alone. The files are standard age files, so
// rage or age with the same plugin opens them without this program.
package guard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// Keyring entries of the guard, in the default keyring.
const (
	EntryIdentity  = "ESEC_GUARD_IDENTITY"
	EntryRecipient = "ESEC_GUARD_RECIPIENT"
	EntryHolders   = "ESEC_GUARD_HOLDERS"
)

// IdentitiesEnv names a file of age identities to open the guard with,
// instead of asking each hardware holder's plugin (one identity per line:
// AGE-PLUGIN-… stubs or AGE-SECRET-KEY-1… keys).
const IdentitiesEnv = "ESEC_VAULT_GUARD_IDENTITIES"

// ErrNotSetUp is returned when this account has no guard yet.
var ErrNotSetUp = errors.New("no hardware guard yet: set one up with esec vault guard init")

// Guard is the stored, wrapped guard identity.
type Guard struct {
	// Wrapped is the age file of the guard identity, to Holders.
	Wrapped []byte
	// Recipient is the guard identity's age1… recipient. It is a record,
	// not a trust anchor: keys are wrapped to the recipient of the guard
	// identity as opened, never to this stored string.
	Recipient string
	// Holders are the recipients the guard identity is wrapped to.
	Holders []string
}

// FromEntries reads the guard from the default keyring's entries.
func FromEntries(entries map[string]string) (*Guard, error) {
	if entries[EntryIdentity] == "" {
		return nil, ErrNotSetUp
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(entries[EntryIdentity])
	if err != nil {
		return nil, fmt.Errorf("malformed %s: %w", EntryIdentity, err)
	}
	var holders []string
	for _, h := range strings.Split(entries[EntryHolders], ",") {
		if h = strings.TrimSpace(h); h != "" {
			holders = append(holders, h)
		}
	}
	return &Guard{Wrapped: wrapped, Recipient: entries[EntryRecipient], Holders: holders}, nil
}

// Entries returns the guard's keyring entries.
func (g *Guard) Entries() map[string]string {
	return map[string]string{
		EntryIdentity:  base64.RawStdEncoding.EncodeToString(g.Wrapped),
		EntryRecipient: g.Recipient,
		EntryHolders:   strings.Join(g.Holders, ","),
	}
}

// New makes a guard identity and wraps it to holders.
func New(holders []string) (*Guard, *age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, nil, err
	}
	g, err := wrapIdentity(id, holders)
	return g, id, err
}

// Rewrap wraps an opened guard identity to a new set of holders.
func Rewrap(id *age.X25519Identity, holders []string) (*Guard, error) {
	return wrapIdentity(id, holders)
}

func wrapIdentity(id *age.X25519Identity, holders []string) (*Guard, error) {
	if len(holders) == 0 {
		return nil, errors.New("a guard needs at least one holder")
	}
	holders = append([]string(nil), holders...)
	sort.Strings(holders)
	recipients, err := ParseRecipients(holders)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, id.String()+"\n"); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return &Guard{Wrapped: buf.Bytes(), Recipient: id.Recipient().String(), Holders: holders}, nil
}

// ParseRecipients parses age recipients, native or of a plugin.
func ParseRecipients(holders []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, h := range holders {
		if PluginName(h) == "" {
			r, err := age.ParseX25519Recipient(h)
			if err != nil {
				return nil, fmt.Errorf("holder %q: %w", h, err)
			}
			out = append(out, r)
			continue
		}
		r, err := plugin.NewRecipient(h, &plugin.ClientUI{})
		if err != nil {
			return nil, fmt.Errorf("holder %q: %w", h, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// PluginName returns the plugin of an age1<name>1… recipient, or "" for a
// native X25519 recipient.
func PluginName(recipient string) string {
	i := strings.LastIndex(recipient, "1")
	if i < 0 {
		return ""
	}
	hrp := strings.ToLower(recipient[:i])
	if hrp == "age" {
		return ""
	}
	return strings.TrimPrefix(hrp, "age1")
}

// Identities returns the identities that open the guard on this machine:
// those in the IdentitiesEnv file, or else one per hardware plugin among
// the holders, which finds its key by itself (a YubiKey plugged in).
func (g *Guard) Identities(ui *plugin.ClientUI) ([]age.Identity, error) {
	if p := os.Getenv(IdentitiesEnv); p != "" {
		data, err := os.ReadFile(p) //nolint:gosec // an identity file the person names
		if err != nil {
			return nil, err
		}
		return ParseIdentities(string(data), ui)
	}
	seen := map[string]bool{}
	var out []age.Identity
	for _, h := range g.Holders {
		name := PluginName(h)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if _, err := CheckPlugin(name); err != nil {
			return nil, err
		}
		id, err := plugin.NewIdentityWithoutData(name, ui)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, errors.New("no hardware holder: the guard opens only with the recovery phrase (esec vault guard recover)")
	}
	return out, nil
}

// ParseIdentities parses age identity lines: AGE-SECRET-KEY-1… keys and
// AGE-PLUGIN-… stubs. Blank lines and # comments are skipped.
func ParseIdentities(text string, ui *plugin.ClientUI) ([]age.Identity, error) {
	var out []age.Identity
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "AGE-PLUGIN-"):
			id, err := plugin.NewIdentity(line, ui)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
		default:
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, errors.New("malformed age identity")
			}
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no age identity found")
	}
	return out, nil
}

// Open unwraps the guard identity with the given identities. With a
// hardware holder this is the moment the key blinks and waits for a touch.
func (g *Guard) Open(ids ...age.Identity) (*age.X25519Identity, error) {
	r, err := age.Decrypt(bytes.NewReader(g.Wrapped), ids...)
	if err != nil {
		return nil, fmt.Errorf("open the guard: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return nil, fmt.Errorf("open the guard: %w", err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("open the guard: the guard identity is malformed")
	}
	return id, nil
}

// Key is the payload of a guarded environment key. Project, Env and Level
// are inside the encryption, so a keyring edit cannot move a key to another
// environment or lower its guard.
type Key struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	// Level is session or touch.
	Level   string `json:"level"`
	Private string `json:"private"`
}

// Wrap encrypts k to the guard identity's recipient and returns the
// keyring value.
func Wrap(to *age.X25519Recipient, k Key) (string, error) {
	payload, err := json.Marshal(k)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, to)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(payload); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf.Bytes()), nil
}

// Unwrap opens a guarded keyring value with the opened guard identity and
// checks that it holds the private key of pub.
func Unwrap(id *age.X25519Identity, value, pub string, publicOf func(string) (string, error)) (*Key, error) {
	raw, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("malformed guarded key")
	}
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		return nil, fmt.Errorf("open the guarded key: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return nil, err
	}
	var k Key
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, errors.New("malformed guarded key")
	}
	got, err := publicOf(k.Private)
	if err != nil || !strings.EqualFold(got, pub) {
		return nil, errors.New("the guarded key does not belong to its public key")
	}
	return &k, nil
}
