package chain

// Delegates. A person's devices may let another key sign some changes to
// their shared projects and machine groups for them: a passkey (a security
// key, Touch ID or a phone, used in the browser), or the server's own key.
// A delegate has a scope that bounds what it can sign; the project and group
// chains check it. Delegates never hold the user key, so they can neither
// decrypt anything nor sign anything outside their scope.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/fpwords"
)

// Delegate kinds.
const (
	// DelegatePasskey is a WebAuthn credential, used in the browser.
	DelegatePasskey = "passkey"
	// DelegateServer is the vault server's own signing key.
	DelegateServer = "server"
)

// Delegate scopes.
const (
	// ScopeRemove signs changes that only take access away from people
	// who are not admins, and from machines.
	ScopeRemove = "remove"
	// ScopeManage also signs adding members and changing what members and
	// machine groups read, never making anyone an admin.
	ScopeManage = "manage"
)

// COSE algorithms a passkey may use.
const (
	AlgES256 = -7
	AlgEdDSA = -8
)

// MaxDelegates bounds a person's active delegates.
const MaxDelegates = 20

// Delegate is a key that may sign some changes for a person.
type Delegate struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
	// SignPub is the server's Ed25519 key (hex).
	SignPub string `json:"sign_pub,omitempty"`
	// A passkey's COSE algorithm, public key (SubjectPublicKeyInfo DER),
	// credential id, and the relying party id and origin it signs for.
	Alg          int    `json:"alg,omitempty"`
	PublicKey    []byte `json:"public_key,omitempty"`
	CredentialID []byte `json:"credential_id,omitempty"`
	RPID         string `json:"rp_id,omitempty"`
	Origin       string `json:"origin,omitempty"`
	// Expires, when set, ends the delegate.
	Expires time.Time `json:"expires,omitzero"`
	Created time.Time `json:"created"`
}

// DelegateAddBody adds a delegate.
type DelegateAddBody struct {
	Delegate Delegate `json:"delegate"`
}

// DelegateRemoveBody removes a delegate.
type DelegateRemoveBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// DelegateState is a delegate as the verified chain sees it.
type DelegateState struct {
	Delegate

	Active     bool   `json:"active"`
	AddedSeq   uint64 `json:"added_seq"`
	RemovedSeq uint64 `json:"removed_seq,omitempty"`
}

var (
	delegateIDPattern = regexp.MustCompile(`^dl_[a-z0-9]{8,40}$`)
	rpIDPattern       = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// ValidateDelegate checks a delegate description.
func ValidateDelegate(d Delegate) error { //nolint:gocyclo // every rule in one place
	if !delegateIDPattern.MatchString(d.ID) {
		return fmt.Errorf("invalid delegate id")
	}
	if err := ValidDeviceName(d.Name); err != nil {
		return fmt.Errorf("a delegate's name is 1-64 letters, digits, spaces or ._()'- characters")
	}
	if d.Created.IsZero() {
		return fmt.Errorf("delegate creation time missing")
	}
	// A link's time is its signer's to say, so an expiry would bind only
	// an honest signer: delegates are removed instead.
	if !d.Expires.IsZero() {
		return fmt.Errorf("delegates do not expire; remove one instead")
	}
	switch d.Kind {
	case DelegateServer:
		if d.Scope != ScopeRemove {
			return fmt.Errorf("the server may only sign removals")
		}
		if _, err := ParseSignKey(d.SignPub); err != nil {
			return fmt.Errorf("server key: %w", err)
		}
		if d.Alg != 0 || len(d.PublicKey) > 0 || len(d.CredentialID) > 0 || d.RPID != "" || d.Origin != "" {
			return fmt.Errorf("a server delegate has no passkey fields")
		}
		return nil
	case DelegatePasskey:
	default:
		return fmt.Errorf("unknown delegate kind %q", d.Kind)
	}
	if d.Scope != ScopeRemove && d.Scope != ScopeManage {
		return fmt.Errorf("unknown delegate scope %q", d.Scope)
	}
	if d.SignPub != "" {
		return fmt.Errorf("a passkey has no Ed25519 key field")
	}
	if _, err := PasskeyPublicKey(d.Alg, d.PublicKey); err != nil {
		return err
	}
	if len(d.CredentialID) == 0 || len(d.CredentialID) > 1023 {
		return fmt.Errorf("invalid passkey credential id")
	}
	if !rpIDPattern.MatchString(d.RPID) {
		return fmt.Errorf("invalid passkey relying party")
	}
	host, ok := strings.CutPrefix(d.Origin, "https://")
	if !ok {
		// Plain http only on the loopback, for a server under test.
		host, ok = strings.CutPrefix(d.Origin, "http://")
		if !ok || (d.RPID != "localhost" && d.RPID != "127.0.0.1") {
			return fmt.Errorf("a passkey's origin must be https")
		}
	}
	if h, _, _ := strings.Cut(host, ":"); h != d.RPID && !strings.HasSuffix(h, "."+d.RPID) {
		return fmt.Errorf("a passkey's origin must be on its relying party")
	}
	return nil
}

// PasskeyPublicKey parses a passkey's public key, which must match its
// algorithm: ES256 on P-256, or EdDSA on Ed25519.
func PasskeyPublicKey(alg int, spki []byte) (any, error) {
	if len(spki) == 0 || len(spki) > 512 {
		return nil, fmt.Errorf("invalid passkey public key")
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("invalid passkey public key: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != AlgES256 || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("a passkey's ECDSA key must be ES256 on P-256")
		}
	case ed25519.PublicKey:
		if alg != AlgEdDSA {
			return nil, fmt.Errorf("a passkey's Ed25519 key must be EdDSA")
		}
	default:
		return nil, fmt.Errorf("unsupported passkey key type")
	}
	return pub, nil
}

func (s *State) applyDelegateAdd(l Link) error {
	var b DelegateAddBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	d := b.Delegate
	if err := ValidateDelegate(d); err != nil {
		return err
	}
	if !d.Expires.IsZero() && !d.Expires.After(l.CTime) {
		return fmt.Errorf("a delegate must not expire before it is added")
	}
	if _, exists := s.Delegates[d.ID]; exists {
		return fmt.Errorf("delegate id reused")
	}
	n := 0
	for _, o := range s.Delegates {
		if !o.Active {
			continue
		}
		n++
		if d.Kind == DelegatePasskey && string(o.CredentialID) == string(d.CredentialID) {
			return fmt.Errorf("that passkey is a delegate already")
		}
		if d.Kind == DelegateServer && o.Kind == DelegateServer {
			return fmt.Errorf("the server is a delegate already")
		}
	}
	if n >= MaxDelegates {
		return fmt.Errorf("too many delegates")
	}
	s.Delegates[d.ID] = &DelegateState{Delegate: d, Active: true, AddedSeq: l.Seq}
	return nil
}

func (s *State) applyDelegateRemove(l Link) error {
	var b DelegateRemoveBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	d, ok := s.Delegates[b.ID]
	if !ok || !d.Active {
		return fmt.Errorf("removed delegate is not active")
	}
	d.Active, d.RemovedSeq = false, l.Seq
	return nil
}

// DelegateAt returns delegate id as it was once the chain had seq links:
// added by then and not removed (nor dropped by a new user key) yet.
func (s *State) DelegateAt(id string, seq uint64) (*DelegateState, bool) {
	d, ok := s.Delegates[id]
	if !ok || seq == 0 || seq > s.Seq || d.AddedSeq > seq || (d.RemovedSeq != 0 && d.RemovedSeq <= seq) {
		return nil, false
	}
	return d, true
}

// ActiveDelegates returns the active delegates.
func (s *State) ActiveDelegates() []*DelegateState {
	var out []*DelegateState
	for _, d := range s.Delegates {
		if d.Active {
			out = append(out, d)
		}
	}
	return out
}

// DelegateAllows reports whether a delegate's scope covers scope want.
func DelegateAllows(scope, want string) bool {
	return scope == want || (scope == ScopeManage && want == ScopeRemove)
}

// DelegateWords are a passkey's fingerprint: the page that registers it
// shows them, and devices before they add it.
func DelegateWords(d Delegate) string {
	return fpwords.Words(fpwords.DeviceWords, "esec-vault passkey v1", d.PublicKey, d.CredentialID, []byte(d.Origin))
}
