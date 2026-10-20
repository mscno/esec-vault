// Package passkeytest is a software passkey for tests: it makes the
// WebAuthn assertions a browser and authenticator would.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
)

// Authenticator is a software ES256 passkey for one site.
type Authenticator struct {
	RPID   string
	Origin string
	Key    *ecdsa.PrivateKey
	CredID []byte
	// Flags are the authenticator data flags (user present and verified).
	Flags byte
}

// New creates a passkey for the site at origin, whose relying party is
// rpID.
func New(rpID, origin string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Authenticator{RPID: rpID, Origin: origin, Key: k, CredID: id, Flags: 0x05}
}

// PublicKey returns the passkey's SubjectPublicKeyInfo DER, as a browser's
// getPublicKey() does.
func (a *Authenticator) PublicKey() []byte {
	der, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}

// Delegate describes the passkey as a delegate.
func (a *Authenticator) Delegate(id, name, scope string, now time.Time) chain.Delegate {
	return chain.Delegate{ID: id, Kind: chain.DelegatePasskey, Name: name, Scope: scope, Alg: chain.AlgES256, PublicKey: a.PublicKey(), CredentialID: a.CredID, RPID: a.RPID, Origin: a.Origin, Created: now.UTC().Truncate(time.Second)}
}

// Assert signs challenge as a browser on Origin would.
func (a *Authenticator) Assert(challenge []byte) *envelope.Assertion {
	cd, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": a.Origin, "crossOrigin": false})
	if err != nil {
		panic(err)
	}
	rp := sha256.Sum256([]byte(a.RPID))
	ad := append(append([]byte(nil), rp[:]...), a.Flags, 0, 0, 0, 1)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		panic(err)
	}
	return &envelope.Assertion{CredentialID: a.CredID, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

// Sign adds an assertion over e.
func (a *Authenticator) Sign(e *envelope.Envelope) {
	e.Passkey = a.Assert(e.Challenge())
}
