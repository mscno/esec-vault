// Package guard opens sealed keys that only a person can open: a dialog
// says what is read and who asked, then the security key waits for a
// touch. Guarded environments are sealed (.esec/<env>.age) to their readers'
// security keys (age-plugin-yubikey, age-plugin-se) and recovery keys only,
// so no software key on any machine opens them; one touch opens one
// environment's key.
package guard

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/securitykey"
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
// security keys: the stand-ins, or else, for each plugin among recipients,
// the identities of its keys here (the YubiKeys plugged in).
func Identities(recipients []string, ui *plugin.ClientUI) ([]age.Identity, error) {
	ids, _, err := identities(recipients, ui)
	return ids, err
}

// identities is Identities, with cautions for the dialog about the keys
// used: a YubiKey slot that keeps a touch for a while. A plugin that is
// missing or finds no key here is passed over, so another reader's kind of
// key cannot stop this one's; only when no plugin has a key is that an
// error, with each plugin's reason.
func identities(recipients []string, ui *plugin.ClientUI) ([]age.Identity, []string, error) {
	if ids, err := StandIns(ui); err != nil || len(ids) > 0 {
		return ids, nil, err
	}
	seen := map[string]bool{}
	var out []age.Identity
	var cautions []string
	var reasons []error
	for _, r := range recipients {
		name := PluginName(r)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		path, err := CheckPlugin(name)
		if err != nil {
			reasons = append(reasons, err)
			continue
		}
		ids, c, err := pluginIdentities(name, path, recipients, ui)
		if err != nil {
			reasons = append(reasons, err)
			continue
		}
		out = append(out, ids...)
		cautions = append(cautions, c...)
	}
	if len(out) > 0 {
		return out, cautions, nil
	}
	if len(reasons) > 0 {
		return nil, nil, errors.Join(reasons...)
	}
	return nil, nil, errors.New("this seal has no security key to open it with: add one (esec vault security-keys add), or recover with the phrase (esec vault seal recover)")
}

// pluginIdentities returns the identities of plugin name (installed at
// path) for recipients. age-plugin-yubikey refuses an identity that does
// not say which YubiKey and slot to use, so the YubiKeys plugged in now
// are listed and each one among recipients gets its stub. Other plugins
// find their key by themselves. A slot that never asks for a touch is not
// used: a guarded read would then need only the dialog.
func pluginIdentities(name, path string, recipients []string, ui *plugin.ClientUI) ([]age.Identity, []string, error) {
	if name != "yubikey" {
		id, err := plugin.NewIdentityWithoutData(name, ui)
		if err != nil {
			return nil, nil, err
		}
		return []age.Identity{id}, nil, nil
	}
	list, err := securitykey.Run(context.Background(), path, "--list")
	if err != nil {
		return nil, nil, fmt.Errorf("list the YubiKeys plugged in: %w", err)
	}
	present, err := securitykey.Parse(string(list))
	if err != nil {
		return nil, nil, err
	}
	readers := map[string]bool{}
	for _, r := range recipients {
		readers[strings.ToLower(r)] = true
	}
	var out []age.Identity
	var cautions []string
	var refused []string
	for _, d := range present {
		if !readers[strings.ToLower(d.Recipient)] {
			continue
		}
		switch {
		case strings.EqualFold(d.TouchPolicy, "Never"):
			refused = append(refused, fmt.Sprintf("YubiKey %s slot %s has touch policy Never", d.Serial, d.Slot))
			continue
		case d.TouchPolicy != "" && !d.TouchAlways():
			cautions = append(cautions, fmt.Sprintf("YubiKey %s slot %s keeps a touch for a while (touch policy %s): another read soon after this one needs no touch. For a slot that asks every time: esec vault security-keys setup --serial %s", d.Serial, d.Slot, d.TouchPolicy, d.Serial))
		}
		stub, err := YubiKeyStub(d.Serial, d.Slot, d.Recipient)
		if err != nil {
			return nil, nil, err
		}
		id, err := plugin.NewIdentity(stub, ui)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, id)
	}
	if len(out) == 0 && len(refused) > 0 {
		return nil, nil, fmt.Errorf("%s: a guarded read must wait for a touch. Make a slot that asks every time (esec vault security-keys setup), or recover with the phrase (esec vault seal recover)", strings.Join(refused, "; "))
	}
	if len(out) == 0 {
		return nil, nil, errors.New("no YubiKey plugged in opens this seal: plug in one of its readers' keys (esec vault security-keys), or recover with the phrase (esec vault seal recover)")
	}
	return out, cautions, nil
}

// YubiKeyStub returns the age-plugin-yubikey identity of the key in slot
// (1 to 20) of the YubiKey with serial, whose recipient is recipient: the
// serial (little-endian), the PIV retired slot (R1 is 0x82) and the
// recipient's tag, the first four bytes of the SHA-256 of its compressed
// point. It holds no secret: the plugin uses it to find the YubiKey, the
// slot and the stanza that key opens.
func YubiKeyStub(serial, slot, recipient string) (string, error) {
	sn, err := strconv.ParseUint(serial, 10, 32)
	if err != nil {
		return "", fmt.Errorf("YubiKey serial %q: %w", serial, err)
	}
	if slot == "" {
		slot = "1"
	}
	n, err := strconv.Atoi(slot)
	if err != nil || n < 1 || n > 20 {
		return "", fmt.Errorf("YubiKey slot %q: want 1 to 20", slot)
	}
	name, point, err := plugin.ParseRecipient(recipient)
	if err != nil || name != "yubikey" || len(point) != 33 {
		return "", fmt.Errorf("not a YubiKey recipient: %s", recipient)
	}
	tag := sha256.Sum256(point)
	data := binary.LittleEndian.AppendUint32(nil, uint32(sn))
	data = append(data, byte(0x81+n))
	data = append(data, tag[:4]...)
	return plugin.EncodeIdentity("yubikey", data), nil
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
