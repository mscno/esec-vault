package servertest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// FakeFly is Fly.io's OIDC side: issuers under one base URL, one per
// organisation (BASE/ORG, with its key set at BASE/ORG/.well-known/jwks),
// and a Machine's API socket that hands out tokens, like /.fly/api.
type FakeFly struct {
	// URL replaces https://oidc.fly.io (server.WithFlyOIDCBase).
	URL string
	// Socket is the Machines API socket (machine.FlyAPIEnv).
	Socket string
	signer *FakeOIDC
	mu     sync.Mutex
	org    string
	claims map[string]any
}

// NewFakeFly starts Fly.io's issuers and a Machine of org running app.
func NewFakeFly(t *testing.T, org, app string) *FakeFly {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeFly{signer: &FakeOIDC{key: key}, org: org, claims: map[string]any{"org_name": org, "app_name": app, "machine_id": "148e21ea7e46e8", "machine_name": "quiet-bird", "region": "fra"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{org}/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		e := big.NewInt(int64(key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.URL = ts.URL

	dir, err := os.MkdirTemp("/tmp", "fly") //nolint:usetesting // unix socket paths must stay short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.Socket = filepath.Join(dir, "api")
	l, err := net.Listen("unix", f.Socket)
	if err != nil {
		t.Fatal(err)
	}
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/tokens/oidc", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Aud string `json:"aud"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(f.Token(req.Aud)))
	})
	srv := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

// SetMachine changes the Machine's org and app as its tokens name them.
func (f *FakeFly) SetMachine(org, app string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.org = org
	f.claims["org_name"], f.claims["app_name"] = org, app
}

// Token signs a token of the Machine for audience, issued by its org's
// issuer.
func (f *FakeFly) Token(audience string) string {
	f.mu.Lock()
	claims := map[string]any{"aud": audience, "iss": strings.TrimRight(f.URL, "/") + "/" + f.org}
	for k, v := range f.claims {
		claims[k] = v
	}
	claims["sub"] = fmt.Sprintf("%s:%v:%v", f.org, claims["app_name"], claims["machine_name"])
	f.mu.Unlock()
	return f.signer.Token(claims)
}
