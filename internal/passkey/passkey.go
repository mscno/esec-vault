// Package passkey verifies WebAuthn assertions: signatures a passkey (a
// security key, Touch ID, a phone) makes in a browser. A person's devices
// register a passkey as a delegate in their user chain, with the origin and
// relying party it signs for; the passkey then signs envelopes whose
// challenge is the envelope's hash.
//
// What is checked, as WebAuthn says: the client data is a "webauthn.get"
// for that challenge from that origin, not cross-origin; the authenticator
// data is for that relying party with the user present; and the signature
// over the authenticator data and the client data's hash verifies with the
// passkey's key. Signature counters are not checked: passkeys synced between
// devices do not keep them.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
)

// Flags of the authenticator data.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// ErrInvalid is returned for an assertion that does not verify.
var ErrInvalid = errors.New("the passkey signature does not verify")

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// Verify checks a's signature over challenge by delegate d, a passkey.
func Verify(a *envelope.Assertion, d *chain.Delegate, challenge []byte) error {
	if a == nil || d == nil || d.Kind != chain.DelegatePasskey {
		return fmt.Errorf("%w: not a passkey signature", ErrInvalid)
	}
	if !bytes.Equal(a.CredentialID, d.CredentialID) {
		return fmt.Errorf("%w: made by another passkey", ErrInvalid)
	}
	var cd clientData
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return fmt.Errorf("%w: invalid client data", ErrInvalid)
	}
	if cd.Type != "webauthn.get" || cd.CrossOrigin || cd.Origin != d.Origin {
		return fmt.Errorf("%w: not a signature made on %s", ErrInvalid, d.Origin)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || !bytes.Equal(got, challenge) {
		return fmt.Errorf("%w: it signs something else", ErrInvalid)
	}
	ad := a.AuthenticatorData
	if len(ad) < 37 {
		return fmt.Errorf("%w: invalid authenticator data", ErrInvalid)
	}
	rp := sha256.Sum256([]byte(d.RPID))
	if !bytes.Equal(ad[:32], rp[:]) {
		return fmt.Errorf("%w: made for another site", ErrInvalid)
	}
	if ad[32]&flagUserPresent == 0 {
		return fmt.Errorf("%w: nobody touched the passkey", ErrInvalid)
	}
	cdHash := sha256.Sum256(a.ClientDataJSON)
	signed := append(append([]byte(nil), ad...), cdHash[:]...)
	pub, err := chain.PasskeyPublicKey(d.Alg, d.PublicKey)
	if err != nil {
		return err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(k, digest[:], a.Signature) {
			return ErrInvalid
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, a.Signature) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// UserVerified reports whether the authenticator verified the person (a PIN
// or biometrics), not only their presence.
func UserVerified(a *envelope.Assertion) bool {
	return len(a.AuthenticatorData) > 32 && a.AuthenticatorData[32]&flagUserVerified != 0
}
