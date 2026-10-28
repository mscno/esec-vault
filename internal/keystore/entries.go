package keystore

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/crypto"
)

// Keyring entries come in three kinds:
//
//   - ESEC_PRIVATE_KEY_<PUB>: a private key filed under its public key. This
//     is the record of a key; once written it is never removed or changed,
//     except to replace it by its guarded form.
//   - ESEC_PRIVATE_KEY_<ENV>: a name pointing at an environment's current key.
//     Names may change (a rotation points dev at a new key).
//   - ESEC_GUARD_<PUB>: a private key wrapped to the hardware guard (see
//     package guard), and ESEC_GUARD_ENV_<ENV>, naming the public key of a
//     guarded environment. A guarded key is never kept in the clear.
//
// The default keyring also holds the guard itself: ESEC_GUARD_IDENTITY,
// ESEC_GUARD_RECIPIENT and ESEC_GUARD_HOLDERS.
const (
	privatePrefix = esec.EsecPrivateKey + "_"
	guardPrefix   = "ESEC_GUARD_"
	// GuardEnvPrefix starts the entries naming a guarded environment's key.
	GuardEnvPrefix = "ESEC_GUARD_ENV_"

	// The guard's own entries in the default keyring (package guard).
	guardIdentity  = "ESEC_GUARD_IDENTITY"
	guardRecipient = "ESEC_GUARD_RECIPIENT"
)

var (
	pubEntryRe   = regexp.MustCompile(`^ESEC_PRIVATE_KEY_[0-9A-F]{64}$`)
	guardEntryRe = regexp.MustCompile(`^ESEC_GUARD_[0-9A-F]{64}$`)
)

// PubEntry is the entry filing a private key under its public key.
func PubEntry(pub string) string { return privatePrefix + strings.ToUpper(pub) }

// EnvEntry is the entry naming an environment's key.
func EnvEntry(env string) string {
	return privatePrefix + strings.ToUpper(strings.ReplaceAll(env, ".", "_"))
}

// GuardEntry is the entry holding a guarded private key.
func GuardEntry(pub string) string { return guardPrefix + strings.ToUpper(pub) }

// GuardEnvEntry is the entry naming a guarded environment's public key.
func GuardEnvEntry(env string) string {
	return GuardEnvPrefix + strings.ToUpper(strings.ReplaceAll(env, ".", "_"))
}

// IsPubEntry reports whether name files a key under its public key.
func IsPubEntry(name string) bool { return pubEntryRe.MatchString(name) }

// IsGuardEntry reports whether name holds a guarded key.
func IsGuardEntry(name string) bool { return guardEntryRe.MatchString(name) }

// EnvName turns an ESEC_PRIVATE_KEY_<ENV> or ESEC_GUARD_ENV_<ENV> entry
// into the environment's name ("api.dev"); ok is false for other entries.
func EnvName(name string) (env string, ok bool) {
	rest, isGuard := strings.CutPrefix(name, GuardEnvPrefix)
	if !isGuard {
		var isKey bool
		rest, isKey = strings.CutPrefix(name, privatePrefix)
		if !isKey || IsPubEntry(name) {
			return "", false
		}
	}
	if rest == "" {
		return "", false
	}
	return strings.ToLower(strings.ReplaceAll(rest, "_", ".")), true
}

// PublicHex returns the public key of a hex private key.
func PublicHex(priv string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid stored private key")
	}
	var key [32]byte
	copy(key[:], raw)
	pub, err := crypto.PublicFromPrivate(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub[:]), nil
}

// fileKeys adds the public-key entry of every named key that lacks one, so
// a key never exists only under a name a later change could repoint. It
// returns the entries it added. Values that are not keys are left alone.
func fileKeys(entries map[string]string) []string {
	var added []string
	for name, v := range entries {
		if name != esec.EsecPrivateKey && !strings.HasPrefix(name, privatePrefix) || IsPubEntry(name) {
			continue
		}
		pub, err := PublicHex(v)
		if err != nil {
			continue
		}
		if entries[GuardEntry(pub)] != "" {
			// Guarded: the clear copy is not filed again.
			continue
		}
		if _, ok := entries[PubEntry(pub)]; !ok {
			entries[PubEntry(pub)] = strings.TrimSpace(v)
			added = append(added, PubEntry(pub))
		}
	}
	sort.Strings(added)
	return added
}

// checkKept refuses a write that would lose a key: every public-key or
// guarded entry of old must stay in next unchanged. With guarding set, a
// public-key entry may give way to the guarded entry of the same key.
//
// The guard itself is kept too: once set, its recipient never changes and
// its identity is never removed, since every guarded key is wrapped to it.
// Its identity may be rewrapped (new holders) under the same recipient.
func checkKept(project string, old, next map[string]string, guarding bool) error {
	for name, v := range old {
		switch {
		case IsPubEntry(name):
			if next[name] == v {
				continue
			}
			pub := strings.TrimPrefix(name, privatePrefix)
			if _, present := next[name]; !present && guarding && next[guardPrefix+pub] != "" {
				continue
			}
			return fmt.Errorf("refusing to change or remove key %s… in %s: keys are only ever added", strings.ToLower(pub[:12]), project)
		case IsGuardEntry(name):
			if next[name] != v {
				return fmt.Errorf("refusing to change or remove guarded key %s… in %s: keys are only ever added", strings.ToLower(strings.TrimPrefix(name, guardPrefix)[:12]), project)
			}
		case name == guardRecipient && v != "":
			if next[name] != v {
				return fmt.Errorf("refusing to replace the guard in %s: every guarded key is wrapped to it (a different guard was set up elsewhere? see esec vault guard)", project)
			}
		case name == guardIdentity && v != "":
			if next[name] == "" {
				return fmt.Errorf("refusing to remove the guard in %s: every guarded key is wrapped to it", project)
			}
		}
	}
	return nil
}
