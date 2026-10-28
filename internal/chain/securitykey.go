package chain

// Security keys. A person registers the hardware keys they open guarded
// environments with (a YubiKey's age identity, a Mac's Secure Enclave key)
// in their chain, with a name. Everyone who seals a guarded environment for
// them learns the keys from here: nobody copies a recipient by hand, and the
// server cannot add one of its own, since every link is signed by the
// person's user key.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Security key kinds, by the age plugin that serves them.
const (
	SecurityKeyYubiKey = "yubikey"
	SecurityKeySE      = "se"
)

// Link types for security keys.
const (
	TypeSecurityKeyAdd    = "security_key_add"
	TypeSecurityKeyRemove = "security_key_remove"
)

// MaxSecurityKeys bounds a person's active security keys.
const MaxSecurityKeys = 20

// SecurityKey is a hardware key that can open seals.
type SecurityKey struct {
	// ID names the key: "yubikey:<serial>:<slot>", or the recipient's
	// fingerprint for keys without a serial.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Recipient is its age recipient (age1yubikey1…, age1se1…).
	Recipient string `json:"recipient"`
	// Name is what the person calls it ("blue, on my keychain").
	Name string `json:"name"`
	// Serial is the YubiKey's serial number, to recognise it when plugged
	// in.
	Serial string `json:"serial,omitempty"`
}

// SecurityKeyAddBody registers a security key.
type SecurityKeyAddBody struct {
	Key SecurityKey `json:"key"`
}

// SecurityKeyRemoveBody stops a security key opening new seals.
type SecurityKeyRemoveBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// SecurityKeyState is a security key as seen by the verified chain.
type SecurityKeyState struct {
	SecurityKey

	Active     bool      `json:"active"`
	Added      time.Time `json:"added"`
	AddedSeq   uint64    `json:"added_seq"`
	RemovedSeq uint64    `json:"removed_seq,omitempty"`
}

var (
	securityKeyID        = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,127}$`)
	securityKeyRecipient = regexp.MustCompile(`^age1(yubikey|se|tag|tagpq)1[02-9ac-hj-np-z]{20,}$`)
)

// ValidateSecurityKey checks a security key's fields.
func ValidateSecurityKey(k SecurityKey) error {
	if !securityKeyID.MatchString(k.ID) {
		return fmt.Errorf("invalid security key id %q", k.ID)
	}
	switch k.Kind {
	case SecurityKeyYubiKey, SecurityKeySE:
	default:
		return fmt.Errorf("unknown security key kind %q", k.Kind)
	}
	if len(k.Recipient) > 4096 || !securityKeyRecipient.MatchString(k.Recipient) {
		return fmt.Errorf("not a hardware age recipient: %.24q", k.Recipient)
	}
	if err := ValidDeviceName(k.Name); err != nil {
		return fmt.Errorf("security key name: %w", err)
	}
	if len(k.Serial) > 32 || strings.ContainsAny(k.Serial, " \t\r\n") {
		return fmt.Errorf("invalid serial %q", k.Serial)
	}
	return nil
}

func (s *State) applySecurityKeyAdd(l Link) error {
	var b SecurityKeyAddBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := ValidateSecurityKey(b.Key); err != nil {
		return err
	}
	if _, exists := s.SecurityKeys[b.Key.ID]; exists {
		return fmt.Errorf("security key id reused")
	}
	active := 0
	for _, k := range s.SecurityKeys {
		if k.Recipient == b.Key.Recipient {
			return fmt.Errorf("security key recipient reused")
		}
		if k.Active {
			active++
		}
	}
	if active >= MaxSecurityKeys {
		return fmt.Errorf("at most %d security keys", MaxSecurityKeys)
	}
	s.SecurityKeys[b.Key.ID] = &SecurityKeyState{SecurityKey: b.Key, Active: true, Added: l.CTime, AddedSeq: l.Seq}
	return nil
}

func (s *State) applySecurityKeyRemove(l Link) error {
	var b SecurityKeyRemoveBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	k, ok := s.SecurityKeys[b.ID]
	if !ok || !k.Active {
		return fmt.Errorf("removed security key is not active")
	}
	k.Active, k.RemovedSeq = false, l.Seq
	return nil
}

// ActiveSecurityKeys returns the security keys that open new seals, by
// name.
func (s *State) ActiveSecurityKeys() []SecurityKey {
	var out []SecurityKey
	for _, k := range s.SecurityKeys {
		if k.Active {
			out = append(out, k.SecurityKey)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}
