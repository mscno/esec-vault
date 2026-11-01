// Package passkeyguard opens age identities with WebAuthn PRF, through
// Apple's native AuthenticationServices sheet. Public recipients contain
// only credential metadata and a PRF-encrypted age identity; no local
// plaintext key or software "approved" flag can bypass the passkey.
package passkeyguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Credential is public, including the encrypted age identity. The format
// and AEAD associated data bind the RP, credential, salt and public key.
type Credential struct {
	Version   int    `json:"v"`
	RPID      string `json:"rp"`
	ID        []byte `json:"id"`
	Salt      []byte `json:"salt"`
	Recipient string `json:"recipient"`
	Wrapped   []byte `json:"wrapped,omitempty"`
}

// Decode validates a recipient or identity's payload before using it.
func Decode(data []byte) (Credential, error) {
	var c Credential
	if len(data) > 2400 {
		return c, errors.New("passkey credential is too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing passkey credential data")
	}
	return c, c.validate()
}

// ParseRecipient decodes a public age passkey recipient.
func ParseRecipient(s string) (Credential, error) {
	name, data, err := plugin.ParseRecipient(s)
	if err != nil || name != "passkey" {
		return Credential{}, errors.New("not a passkey recipient")
	}
	return Decode(data)
}

// EncodeRecipient encodes public metadata and the encrypted identity.
func (c Credential) EncodeRecipient() string {
	data, _ := json.Marshal(c) //nolint:errchkjson // Credential contains only primitive JSON types.
	return plugin.EncodeRecipient("passkey", data)
}

func (c Credential) validate() error {
	if c.Version != 1 || len(c.RPID) < 1 || len(c.RPID) > 253 || strings.Trim(c.RPID, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" || strings.Contains(c.RPID, "..") || strings.HasPrefix(c.RPID, ".") || strings.HasSuffix(c.RPID, ".") {
		return errors.New("invalid passkey relying party or format version")
	}
	if len(c.ID) < 1 || len(c.ID) > 1024 || len(c.Salt) != 32 || len(c.Wrapped) < 24+16 || len(c.Wrapped) > 512 {
		return errors.New("invalid passkey credential, salt or encrypted identity")
	}
	_, err := age.ParseX25519Recipient(c.Recipient)
	return err
}

func (c Credential) keyID() string {
	h := sha256.Sum256([]byte(c.Recipient))
	return hex.EncodeToString(h[:])
}

func (c Credential) aad() []byte {
	c.Wrapped = nil
	b, _ := json.Marshal(c) //nolint:errchkjson // Credential contains only primitive JSON types.
	return b
}

func (c Credential) wrappingKey(prf []byte) ([]byte, error) {
	if len(prf) != 32 {
		return nil, errors.New("this passkey provider did not return a PRF encryption secret")
	}
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf.New(sha256.New, prf, c.Salt, []byte("esec/passkey/age-identity/v1")), key)
	return key, err
}

// Enroll creates a passkey with the system sheet and encrypts a fresh age
// identity with its PRF output. No registry or existing seal is changed.
func Enroll(ctx context.Context, rp, name, provider string) (Credential, error) {
	salt, userID := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return Credential{}, err
	}
	if _, err := rand.Read(userID); err != nil {
		return Credential{}, err
	}
	response, err := Native(ctx, Request{Operation: "register", RPID: rp, Name: name, Provider: provider, UserID: userID, Salt: salt})
	if err != nil {
		return Credential{}, err
	}
	defer clear(response.PRF)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Credential{}, err
	}
	c := Credential{Version: 1, RPID: rp, ID: response.CredentialID, Salt: salt, Recipient: id.Recipient().String()}
	key, err := c.wrappingKey(response.PRF)
	if err != nil {
		return Credential{}, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Credential{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Credential{}, err
	}
	plaintext := []byte(id.String())
	defer clear(plaintext)
	c.Wrapped = aead.Seal(nonce, nonce, plaintext, c.aad())
	return c, c.validate()
}

func (c Credential) open(prf []byte) (age.Identity, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	key, err := c.wrappingKey(prf)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	plaintext, err := aead.Open(nil, c.Wrapped[:n], c.Wrapped[n:], c.aad())
	if err != nil {
		return nil, errors.New("the passkey could not decrypt this identity")
	}
	defer clear(plaintext)
	id, err := age.ParseX25519Identity(string(plaintext))
	if err != nil {
		return nil, err
	}
	if id.Recipient().String() != c.Recipient {
		return nil, fmt.Errorf("passkey identity does not match its public key")
	}
	return id, nil
}
