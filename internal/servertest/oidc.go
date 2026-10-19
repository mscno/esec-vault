package servertest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// FakeOIDC is an OIDC issuer like GitHub Actions': it serves its key set,
// signs tokens, and answers a job's token requests.
type FakeOIDC struct {
	URL    string
	key    *rsa.PrivateKey
	mu     sync.Mutex
	claims map[string]any
}

// NewFakeOIDC starts an issuer.
func NewFakeOIDC(t *testing.T) *FakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeOIDC{key: key, claims: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		e := big.NewInt(int64(key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	// The job's token request, as ACTIONS_ID_TOKEN_REQUEST_URL serves it.
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer job-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims := map[string]any{}
		f.mu.Lock()
		for k, v := range f.claims {
			claims[k] = v
		}
		f.mu.Unlock()
		claims["aud"] = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": f.Token(claims)})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.URL = ts.URL
	return f
}

// SetClaims sets the job's claims (repository, ref, ...) that its token
// requests get; the token endpoint adds iss, aud and times.
func (f *FakeOIDC) SetClaims(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = claims
}

// JWKS is the key set URL.
func (f *FakeOIDC) JWKS() string { return f.URL + "/.well-known/jwks" }

// JobEnv returns the environment of a GitHub Actions job allowed to request
// tokens from this issuer.
func (f *FakeOIDC) JobEnv() []string {
	return []string{"ACTIONS_ID_TOKEN_REQUEST_URL=" + f.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=job-token"}
}

// Token signs claims, adding the issuer and times unless set.
func (f *FakeOIDC) Token(claims map[string]any) string {
	now := time.Now().Unix()
	full := map[string]any{"iss": f.URL, "iat": now, "nbf": now, "exp": now + 300}
	for k, v := range claims {
		full[k] = v
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	if err != nil {
		panic(err)
	}
	body, err := json.Marshal(full)
	if err != nil {
		panic(err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}
