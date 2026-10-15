// Package envelope implements signed envelopes: a kind, the exact JSON body
// bytes that were signed, and one or more Ed25519 signatures.
//
// The signed message is
//
//	"esec-vault/" + kind + "/v1\n" + body
//
// so a signature made for one kind can never be accepted as another. The body
// is transported as the bytes that were signed; nothing is re-encoded into a
// canonical form before verification.
//
// An envelope's hash covers the kind and body only. Signatures can therefore
// be added later (countersigning) without changing the hash that a hash chain
// refers to.
package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Version is the envelope format version.
const Version = 1

// MaxBody bounds an envelope body to keep parsing cheap.
const MaxBody = 64 << 10

// Signature is one Ed25519 signature over the envelope message.
type Signature struct {
	// Key is the hex-encoded Ed25519 public key.
	Key string `json:"key"`
	// Sig is the signature.
	Sig []byte `json:"sig"`
}

// Envelope is a signed object.
type Envelope struct {
	V    int         `json:"v"`
	Kind string      `json:"kind"`
	Body []byte      `json:"body"`
	Sigs []Signature `json:"sigs"`
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ErrBadSignature is returned when a required signature is missing or invalid.
var ErrBadSignature = errors.New("envelope signature missing or invalid")

func message(kind string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("esec-vault/")
	b.WriteString(kind)
	b.WriteString("/v1\n")
	b.Write(body)
	return b.Bytes()
}

// New marshals body and signs it with every key.
func New(kind string, body any, keys ...ed25519.PrivateKey) (*Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return NewRaw(kind, raw, keys...)
}

// NewRaw signs exact body bytes.
func NewRaw(kind string, body []byte, keys ...ed25519.PrivateKey) (*Envelope, error) {
	if !kindPattern.MatchString(kind) {
		return nil, fmt.Errorf("invalid envelope kind %q", kind)
	}
	if len(body) > MaxBody {
		return nil, fmt.Errorf("envelope body too large")
	}
	e := &Envelope{V: Version, Kind: kind, Body: bytes.Clone(body)}
	for _, k := range keys {
		e.AddSignature(k)
	}
	return e, nil
}

// AddSignature appends a signature by key.
func (e *Envelope) AddSignature(key ed25519.PrivateKey) {
	pub, _ := key.Public().(ed25519.PublicKey)
	e.Sigs = append(e.Sigs, Signature{Key: hex.EncodeToString(pub), Sig: ed25519.Sign(key, message(e.Kind, e.Body))})
}

// Check validates structure: version, kind and body size.
func (e *Envelope) Check() error {
	if e == nil {
		return fmt.Errorf("missing envelope")
	}
	if e.V != Version {
		return fmt.Errorf("unsupported envelope version %d", e.V)
	}
	if !kindPattern.MatchString(e.Kind) {
		return fmt.Errorf("invalid envelope kind")
	}
	if len(e.Body) == 0 || len(e.Body) > MaxBody {
		return fmt.Errorf("invalid envelope body size")
	}
	if len(e.Sigs) > 8 {
		return fmt.Errorf("too many envelope signatures")
	}
	return nil
}

// VerifiedBy reports whether pub produced a valid signature over e.
func (e *Envelope) VerifiedBy(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	want := hex.EncodeToString(pub)
	msg := message(e.Kind, e.Body)
	for _, s := range e.Sigs {
		if s.Key == want && ed25519.Verify(pub, msg, s.Sig) {
			return true
		}
	}
	return false
}

// Require checks e's structure, its kind, and a valid signature by every key.
func (e *Envelope) Require(kind string, keys ...ed25519.PublicKey) error {
	if err := e.Check(); err != nil {
		return err
	}
	if e.Kind != kind {
		return fmt.Errorf("expected %s envelope, got %s", kind, e.Kind)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no signer required", ErrBadSignature)
	}
	for _, k := range keys {
		if !e.VerifiedBy(k) {
			return fmt.Errorf("%w: %s", ErrBadSignature, e.Kind)
		}
	}
	return nil
}

// Decode unmarshals the body into v, rejecting unknown fields.
func (e *Envelope) Decode(v any) error {
	d := json.NewDecoder(bytes.NewReader(e.Body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid %s body: %w", e.Kind, err)
	}
	if d.More() {
		return fmt.Errorf("invalid %s body: trailing data", e.Kind)
	}
	return nil
}

// Hash is the hex SHA-256 of the signed message (kind and body).
func (e *Envelope) Hash() string {
	sum := sha256.Sum256(message(e.Kind, e.Body))
	return hex.EncodeToString(sum[:])
}
