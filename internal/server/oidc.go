package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/team"
)

// GitHub Actions' OIDC issuer.
const (
	githubIssuer = "https://token.actions.githubusercontent.com"
	githubJWKS   = githubIssuer + "/.well-known/jwks"
)

// oidcVerifier checks OIDC ID tokens (RS256 JWTs) from one issuer. It caches
// the issuer's signing keys and fetches them again, at most once a minute,
// when a token names a key it does not know.
type oidcVerifier struct {
	issuer, jwksURL string
	http            *http.Client

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	tried   time.Time
}

func newOIDCVerifier(issuer, jwksURL string, client *http.Client) *oidcVerifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &oidcVerifier{issuer: issuer, jwksURL: jwksURL, http: client}
}

// oidcIssuers holds a verifier per issuer a policy may name: GitHub
// Actions', and each Fly.io organisation's (https://oidc.fly.io/ORG). The
// issuer follows from the policy in the signed chain, never from a token,
// and Fly.io's are all under one host.
type oidcIssuers struct {
	github  *oidcVerifier
	flyBase string

	mu  sync.Mutex
	fly map[string]*oidcVerifier
}

func newOIDCIssuers() *oidcIssuers {
	return &oidcIssuers{github: newOIDCVerifier(githubIssuer, githubJWKS, nil), flyBase: team.FlyIssuerBase, fly: map[string]*oidcVerifier{}}
}

// Verify checks token against the issuer p names, and p itself.
func (o *oidcIssuers) Verify(ctx context.Context, p *team.OIDCPolicy, token, audience string, now time.Time) (*team.Claims, error) {
	v := o.github
	if p.Provider == team.ProviderFly {
		o.mu.Lock()
		if v = o.fly[p.FlyOrg]; v == nil {
			issuer := o.flyBase + "/" + p.FlyOrg
			v = newOIDCVerifier(issuer, issuer+"/.well-known/jwks", nil)
			o.fly[p.FlyOrg] = v
		}
		o.mu.Unlock()
	}
	return v.Verify(ctx, token, audience, now)
}

// WithOIDCIssuer replaces GitHub Actions' OIDC issuer and key URL (tests).
func WithOIDCIssuer(issuer, jwksURL string) Option {
	return func(s *Server) { s.oidc.github = newOIDCVerifier(issuer, jwksURL, nil) }
}

// WithFlyOIDCBase replaces https://oidc.fly.io, where Fly.io's issuers are
// (tests).
func WithFlyOIDCBase(base string) Option { return func(s *Server) { s.oidc.flyBase = base } }

// errOIDC marks a token that is refused; the message is safe to return.
var errOIDC = errors.New("OIDC token refused")

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jwtClaims are the standard claims plus GitHub's.
type jwtClaims struct {
	team.Claims

	Iss string          `json:"iss"`
	Aud json.RawMessage `json:"aud"`
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Iat int64           `json:"iat"`
}

// Verify checks token's signature, issuer, audience and lifetime, and
// returns its claims.
func (v *oidcVerifier) Verify(ctx context.Context, token, audience string, now time.Time) (*team.Claims, error) {
	parts := strings.Split(token, ".")
	if len(token) > 16<<10 || len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWT", errOIDC)
	}
	var h jwtHeader
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, fmt.Errorf("%w: bad header", errOIDC)
	}
	if h.Alg != "RS256" {
		return nil, fmt.Errorf("%w: algorithm %q is not RS256", errOIDC, h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", errOIDC)
	}
	key, err := v.key(ctx, h.Kid, now)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("%w: bad signature", errOIDC)
	}
	var c jwtClaims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, fmt.Errorf("%w: bad claims", errOIDC)
	}
	if c.Iss != v.issuer {
		return nil, fmt.Errorf("%w: issuer %q", errOIDC, c.Iss)
	}
	if !audienceHas(c.Aud, audience) {
		return nil, fmt.Errorf("%w: the token's audience is not %s (request it with audience=%s)", errOIDC, audience, audience)
	}
	const skew = 60
	t := now.Unix()
	if c.Exp == 0 || t > c.Exp+skew || (c.Nbf != 0 && t < c.Nbf-skew) || (c.Iat != 0 && t < c.Iat-skew) {
		return nil, fmt.Errorf("%w: expired or not yet valid", errOIDC)
	}
	return &c.Claims, nil
}

func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// key returns the issuer's key kid, fetching the key set when needed.
func (v *oidcVerifier) key(ctx context.Context, kid string, now time.Time) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && now.Sub(v.fetched) < 24*time.Hour {
		return k, nil
	}
	if now.Sub(v.tried) < time.Minute && v.keys != nil {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("%w: unknown signing key", errOIDC)
	}
	v.tried = now
	keys, err := v.fetch(ctx)
	if err != nil {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("fetch the OIDC signing keys: %w", err)
	}
	v.keys, v.fetched = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown signing key", errOIDC)
}

func (v *oidcVerifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, transportError("OIDC", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the OIDC key set returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 || len(n) < 256 {
			continue
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	if len(out) == 0 {
		return nil, errors.New("the OIDC key set has no RSA keys")
	}
	return out, nil
}
