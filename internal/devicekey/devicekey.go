// Package devicekey manages this machine's device keypair: an X25519 key that
// receives the user key from other devices, and an Ed25519 key that signs API
// requests and the device's own proof. Both private halves live only in the
// local secret store and never leave the machine.
package devicekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/fpwords"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/wire"
)

// Secret store entries.
const (
	EncName  = "device-enc-private"
	SignName = "device-sign-private"
)

// ErrNotFound is returned when this machine has no device key yet.
var ErrNotFound = errors.New("no device key on this machine")

// Key is a device keypair.
type Key struct {
	EncPub  [32]byte
	EncPriv [32]byte
	Sign    ed25519.PrivateKey
}

// Generate creates a new device key without storing it.
func Generate() (*Key, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{EncPub: *pub, EncPriv: *priv, Sign: sign}, nil
}

// Load reads the device key from kr.
func Load(kr keyring.Keyring) (*Key, error) {
	encHex, err := kr.Get(EncName)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	signHex, err := kr.Get(SignName)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("device signing key missing from the secret store")
	}
	if err != nil {
		return nil, err
	}
	enc, err := hex.DecodeString(strings.TrimSpace(encHex))
	if err != nil || len(enc) != 32 {
		return nil, fmt.Errorf("malformed device encryption key")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(signHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("malformed device signing key")
	}
	k := &Key{Sign: ed25519.NewKeyFromSeed(seed)}
	copy(k.EncPriv[:], enc)
	k.EncPub = identity.PublicFromPrivate(k.EncPriv)
	return k, nil
}

// Save stores k in kr.
func (k *Key) Save(kr keyring.Keyring) error {
	if err := kr.Set(EncName, hex.EncodeToString(k.EncPriv[:])); err != nil {
		return err
	}
	if err := kr.Set(SignName, hex.EncodeToString(k.Sign.Seed())); err != nil {
		return errors.Join(err, kr.Delete(EncName))
	}
	return nil
}

// Delete removes the device key from kr.
func Delete(kr keyring.Keyring) error {
	return errors.Join(kr.Delete(EncName), kr.Delete(SignName))
}

// LoadOrCreate returns the stored device key, creating one if absent.
func LoadOrCreate(kr keyring.Keyring) (*Key, bool, error) {
	k, err := Load(kr)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	k, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := k.Save(kr); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// SignPub returns the Ed25519 public key.
func (k *Key) SignPub() ed25519.PublicKey {
	pub, _ := k.Sign.Public().(ed25519.PublicKey)
	return pub
}

// EncPubHex returns the hex X25519 public key.
func (k *Key) EncPubHex() string { return hex.EncodeToString(k.EncPub[:]) }

// SignPubHex returns the hex Ed25519 public key.
func (k *Key) SignPubHex() string { return hex.EncodeToString(k.SignPub()) }

// Words returns this device's fingerprint words.
func (k *Key) Words() string { return Words(k.EncPubHex(), k.SignPubHex()) }

// Words returns the fingerprint words for a device's public keys, given as
// hex. Both sides of an approval compute them independently.
func Words(encPubHex, signPubHex string) string {
	return fpwords.Words(fpwords.DeviceWords, fpwords.DomainDevice, []byte(strings.ToLower(encPubHex)), []byte(strings.ToLower(signPubHex)))
}

// Registration builds a signed registration request for this device.
func (k *Key) Registration(name, platform string, now time.Time) wire.DeviceRegisterRequest {
	r := wire.DeviceRegisterRequest{Name: name, Platform: platform, EncPub: k.EncPubHex(), SignPub: k.SignPubHex(), Timestamp: now.Unix()}
	r.Sig = ed25519.Sign(k.Sign, wire.RegistrationMessage(&r))
	return r
}

// Proof signs a device proof binding this key to user and device d.
func (k *Key) Proof(user string, d chain.Device) (*envelope.Envelope, error) {
	if d.EncPub != k.EncPubHex() || d.SignPub != k.SignPubHex() {
		return nil, fmt.Errorf("device description does not match this device key")
	}
	if err := chain.ValidUser(user); err != nil {
		return nil, err
	}
	if err := chain.ValidateDevice(d); err != nil {
		return nil, err
	}
	return envelope.New(chain.KindDeviceProof, chain.DeviceProof{User: user, Device: d}, k.Sign)
}
