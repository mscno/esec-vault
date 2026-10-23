package kms

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

var gcpKeyVersion = regexp.MustCompile(`^projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/([^/]+)$`)

// FetchPublicKey reads a key's public half (PEM) from its KMS, as the
// person running this: with gcloud for Google Cloud KMS, and with BAO_TOKEN
// (or VAULT_TOKEN) for OpenBao. Reading it here, rather than taking it from
// anyone else, is what makes the key the one its name says.
func FetchPublicKey(ctx context.Context, k Key) ([]byte, error) {
	// Check the names first: they may come from a change the server
	// proposed, and go to gcloud or carry a token.
	if err := k.ValidateNames(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	switch k.Provider {
	case "openbao":
		token := os.Getenv("BAO_TOKEN")
		if token == "" {
			token = os.Getenv("VAULT_TOKEN")
		}
		if token == "" {
			return nil, errors.New("set BAO_TOKEN to a token that may read the key, and BAO_ADDR to its OpenBao, or pass its public key (--public-key FILE)")
		}
		if err := sameOpenBao(k.Name); err != nil {
			return nil, err
		}
		return OpenBaoPublicKey(ctx, k.Name, token)
	case "gcp":
		m := gcpKeyVersion.FindStringSubmatch(k.Name)
		if m == nil || slices.ContainsFunc(m[1:], func(p string) bool { return strings.HasPrefix(p, "-") }) {
			return nil, errors.New("a Cloud KMS key is a key version: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N")
		}
		out, err := exec.CommandContext(ctx, "gcloud", "kms", "keys", "versions", "get-public-key", m[5], "--key", m[4], "--keyring", m[3], "--location", m[2], "--project", m[1], "--output-file", "-").Output()
		if err != nil {
			return nil, fmt.Errorf("ask gcloud for the key's public key (gcloud must be installed and signed in; or pass --public-key FILE): %w", err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown KMS provider %q", k.Provider)
}

// sameOpenBao refuses to send the OpenBao token to any server but the one
// BAO_ADDR (or VAULT_ADDR) names.
func sameOpenBao(name string) error {
	addr := os.Getenv("BAO_ADDR")
	if addr == "" {
		addr = os.Getenv("VAULT_ADDR")
	}
	want, err := url.Parse(addr)
	if addr == "" || err != nil || want.Host == "" {
		return errors.New("set BAO_ADDR to your OpenBao's address: the token goes only there")
	}
	got, err := url.Parse(name)
	if err != nil || !strings.EqualFold(got.Host, want.Host) || got.Scheme != want.Scheme {
		return fmt.Errorf("the key is on %s, not on BAO_ADDR (%s): not sending your token there", got.Host, want.Host)
	}
	return nil
}

// WithPublicKey returns k with its public half read from its KMS.
func WithPublicKey(ctx context.Context, k Key) (Key, error) {
	pemText, err := FetchPublicKey(ctx, k)
	if err != nil {
		return k, err
	}
	if k.PublicKey, err = PublicKeyFromPEM(pemText); err != nil {
		return k, err
	}
	return k, k.Validate()
}
