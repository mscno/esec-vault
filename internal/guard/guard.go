// Package guard opens sealed keys that only a person can open: a dialog
// says what is read and who asked, then the security key waits for a
// touch. Guarded environments are sealed (.esec/<env>.age) to their readers'
// security keys (age-plugin-yubikey, age-plugin-se) and recovery keys only,
// so no software key on any machine opens them; one touch opens one
// environment's key.
package guard

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// IdentitiesEnv names a file of age identities that stand in for this
// machine's security keys (one per line: AGE-PLUGIN-… stubs, or
// AGE-SECRET-KEY-1… keys in tests). Their recipients count as the person's
// security keys.
const IdentitiesEnv = "ESEC_VAULT_GUARD_IDENTITIES"

// StandIns returns the identities IdentitiesEnv names, none when unset.
func StandIns(ui *plugin.ClientUI) ([]age.Identity, error) {
	p := os.Getenv(IdentitiesEnv)
	if p == "" {
		return nil, nil
	}
	data, err := os.ReadFile(p) //nolint:gosec // an identity file the person names
	if err != nil {
		return nil, err
	}
	return ParseIdentities(string(data), ui)
}

// StandInRecipients returns the recipients of the software stand-ins, for
// tests and machines without hardware.
func StandInRecipients() ([]string, error) {
	ids, err := StandIns(nil)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	return out, nil
}

// Identities returns the identities that open a seal with this machine's
// security keys: the stand-ins, or else one per plugin among recipients,
// which finds its key by itself (a YubiKey plugged in).
func Identities(recipients []string, ui *plugin.ClientUI) ([]age.Identity, error) {
	if ids, err := StandIns(ui); err != nil || len(ids) > 0 {
		return ids, err
	}
	seen := map[string]bool{}
	var out []age.Identity
	for _, r := range recipients {
		name := PluginName(r)
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
		return nil, errors.New("this seal has no security key to open it with: add one (esec vault security-keys add), or recover with the phrase (esec vault seal recover)")
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

// Open opens a sealed key with ids, checking it is project's env with
// public key pub. With a hardware key this is the moment it blinks and
// waits for a touch.
func Open(data []byte, project, env, pub string, ids ...age.Identity) (*coreseal.Payload, error) {
	p, err := coreseal.Open(data, project, env, pub, ids...)
	if err != nil {
		return nil, fmt.Errorf("open the sealed key of %s %s: %w", project, env, err)
	}
	if p.Guard == "" {
		p.Guard = "touch"
	}
	return p, nil
}
