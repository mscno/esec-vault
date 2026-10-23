package servertest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// FakeOpenBao is OpenBao's JWT login and Transit decrypt, enough for a
// workload's unwrap, with one RSA key and one role.
type FakeOpenBao struct {
	URL string
	// Key is the Transit key name, Role the JWT role, Audience its bound
	// audience.
	Key, Role, Audience string
	key                 *rsa.PrivateKey

	mu       sync.Mutex
	claims   map[string]any // bound claims
	tokens   map[string]bool
	decrypts int
}

// NewFakeOpenBao starts the fake; the role binds the given claims.
func NewFakeOpenBao(t *testing.T, bound map[string]any) *FakeOpenBao {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeOpenBao{key: key, Key: "esec-store", Role: "fly-store", Audience: "esec-openbao", claims: bound, tokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		c := jwtClaims(req.JWT)
		f.mu.Lock()
		defer f.mu.Unlock()
		ok := req.Role == f.Role && c != nil && c["aud"] == f.Audience
		for k, v := range f.claims {
			ok = ok && c[k] == v
		}
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"error validating claims: claim \"app_name\" does not match any associated bound claim values"}})
			return
		}
		tok := "s.fake" + strings.Repeat("x", len(f.tokens))
		f.tokens[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": tok}})
	})
	mux.HandleFunc("POST /v1/transit/decrypt/{key}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		ok := f.tokens[r.Header.Get("X-Vault-Token")]
		f.decrypts++
		f.mu.Unlock()
		if !ok || r.PathValue("key") != f.Key {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		b64, found := strings.CutPrefix(req.Ciphertext, "vault:v1:")
		ct, err := base64.StdEncoding.DecodeString(b64)
		plain, derr := rsa.DecryptOAEP(sha256.New(), nil, f.key, ct, nil)
		if !found || err != nil || derr != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid ciphertext"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain)}})
	})
	mux.HandleFunc("GET /v1/transit/keys/{key}", func(w http.ResponseWriter, r *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "rsa-2048", "keys": map[string]any{"1": map[string]any{"public_key": string(p)}}}})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.URL = ts.URL
	return f
}

// KeyName is the key version as esec-vault names it.
func (f *FakeOpenBao) KeyName() string { return f.URL + "/transit/" + f.Key + "/1" }

// Decrypts counts the decrypt calls so far.
func (f *FakeOpenBao) Decrypts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decrypts
}
