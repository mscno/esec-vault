// Package kms unwraps keys with an external key management service, for
// workloads that hold no secret of their own.
//
// A group's private key is wrapped, on an admin's device, with the public
// half of an asymmetric KMS key (RSA-OAEP with SHA-256, which Google Cloud
// KMS, AWS KMS and Azure Key Vault all offer): no cloud credential is
// needed for that. Only the unwrapping goes to the KMS, by a workload that
// proves who it is with an OIDC token (from Fly.io, GitHub Actions or its
// cloud), which the KMS's own identity federation exchanges for the right
// to decrypt with that one key. The vault server never holds a key that
// opens anything; the KMS never sees a secret, only the wrapped group key.
//
// Providers implement Provider; Key names a key of one of them.
package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
)

// Key names an asymmetric decryption key of a KMS and how a workload
// reaches it. It is recorded in the group chain, signed by an admin, so a
// workload uses only the key and federation its admins chose.
type Key struct {
	// Provider names the KMS, such as "gcp".
	Provider string `json:"provider"`
	// Name is the key (version) in the provider's own terms, such as
	// projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1.
	Name string `json:"name"`
	// Audience is the audience of the OIDC token the provider's identity
	// federation accepts, such as a GCP workload identity provider.
	Audience string `json:"audience"`
	// PublicKey is the key's public half, base64 DER (PKIX).
	PublicKey string `json:"public_key"`
	// Principal, when set, is a provider-specific identity the federated
	// token acts as, such as a GCP service account to impersonate.
	Principal string `json:"principal,omitempty"`
}

// Provider unwraps with one KMS.
type Provider interface {
	// Validate checks a key's names in the provider's terms.
	Validate(k Key) error
	// Unwrap decrypts ciphertext with k, as the workload whose OIDC token
	// for k.Audience token returns.
	Unwrap(ctx context.Context, k Key, ciphertext []byte, token TokenSource) ([]byte, error)
}

// TokenSource returns an OIDC token of the running workload for audience.
type TokenSource func(ctx context.Context, audience string) (string, error)

var (
	mu        sync.RWMutex
	providers = map[string]Provider{"gcp": &GCP{}, "openbao": &OpenBao{}}
	// namePattern bounds what a key's names may hold.
	namePattern = regexp.MustCompile(`^[A-Za-z0-9:/._@+-]{1,512}$`)
)

// Register makes a provider available under name.
func Register(name string, p Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers[name] = p
}

// Providers lists the registered providers.
func Providers() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(providers))
	for n := range providers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func provider(name string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown KMS provider %q (this esec-vault knows %v)", name, Providers())
	}
	return p, nil
}

// MinKeyBits is the smallest RSA key accepted.
const MinKeyBits = 2048

// Validate checks a key: a known provider, sane names, and an RSA public
// key of at least MinKeyBits.
func (k Key) Validate() error {
	p, err := provider(k.Provider)
	if err != nil {
		return err
	}
	if !namePattern.MatchString(k.Name) || !namePattern.MatchString(k.Audience) || (k.Principal != "" && !namePattern.MatchString(k.Principal)) {
		return errors.New("invalid KMS key, audience or principal name")
	}
	if _, err := k.RSA(); err != nil {
		return err
	}
	return p.Validate(k)
}

// RSA returns the key's public half.
func (k Key) RSA() (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return nil, errors.New("the KMS public key is not base64 DER")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("the KMS public key does not parse: %w", err)
	}
	r, ok := pub.(*rsa.PublicKey)
	if !ok || r.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("the KMS key must be RSA of at least %d bits", MinKeyBits)
	}
	return r, nil
}

// Fingerprint identifies the key's public half: what a key grant to it
// names as the key it is sealed to.
func (k Key) Fingerprint() string {
	sum := sha256.Sum256([]byte(k.Provider + "\n" + k.Name + "\n" + k.PublicKey))
	return "kms:" + hex.EncodeToString(sum[:])
}

// Wrap encrypts plaintext to the key's public half, locally.
func (k Key) Wrap(plaintext []byte) ([]byte, error) {
	pub, err := k.RSA()
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// Unwrap asks the key's provider to decrypt ciphertext, as the workload
// whose OIDC token the token source returns.
func (k Key) Unwrap(ctx context.Context, ciphertext []byte, token TokenSource) ([]byte, error) {
	p, err := provider(k.Provider)
	if err != nil {
		return nil, err
	}
	return p.Unwrap(ctx, k, ciphertext, token)
}

// PublicKeyFromPEM turns a PEM public key (as KMS consoles and CLIs print
// it) into Key.PublicKey's form.
func PublicKeyFromPEM(pemText []byte) (string, error) {
	der, err := pemDER(pemText)
	if err != nil {
		return "", err
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return "", fmt.Errorf("not a public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
