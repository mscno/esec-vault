package servertest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// FakeGCP is Google's Security Token Service and Cloud KMS, enough for a
// workload's unwrap: it exchanges an OIDC token whose claims pass Allow for
// an access token, and decrypts with one asymmetric key for that token.
type FakeGCP struct {
	URL string
	// KeyName is the key version, Provider the workload identity provider,
	// PublicKey the key's public half (base64 DER).
	KeyName, Provider, PublicKey string
	key                          *rsa.PrivateKey

	mu sync.Mutex
	// Allow is the provider's attribute condition on the token's claims.
	allow     func(claims map[string]any) bool
	tokens    map[string]bool
	decrypts  int
	exchanges int
}

// NewFakeGCP starts the fake with a 2048-bit key.
func NewFakeGCP(t *testing.T) *FakeGCP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeGCP{
		key:       key,
		KeyName:   "projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/workloads/cryptoKeyVersions/1",
		Provider:  "projects/123456789/locations/global/workloadIdentityPools/esec-fly/providers/fly-acme",
		PublicKey: base64.StdEncoding.EncodeToString(der),
		allow:     func(map[string]any) bool { return true },
		tokens:    map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sts", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("audience") != "//iam.googleapis.com/"+f.Provider {
			http.Error(w, `{"error":"invalid_target","error_description":"wrong audience"}`, http.StatusBadRequest)
			return
		}
		claims := jwtClaims(r.PostForm.Get("subject_token"))
		f.mu.Lock()
		defer f.mu.Unlock()
		f.exchanges++
		if claims == nil || claims["aud"] != "https://iam.googleapis.com/"+f.Provider || !f.allow(claims) {
			http.Error(w, `{"error":"unauthorized_client","error_description":"The given credential is rejected by the attribute condition."}`, http.StatusForbidden)
			return
		}
		tok := fmt.Sprintf("ya29.fake-%d", len(f.tokens))
		f.tokens[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("POST /kms/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		f.decrypts++
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":{"message":"Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied"}}`, http.StatusForbidden)
			return
		}
		if strings.TrimPrefix(r.URL.Path, "/kms/") != f.KeyName+":asymmetricDecrypt" {
			http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
			return
		}
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
		plain, err := rsa.DecryptOAEP(sha256.New(), nil, f.key, ct, nil)
		if err != nil {
			http.Error(w, `{"error":{"message":"Decryption failed"}}`, http.StatusBadRequest)
			return
		}
		table := crc32.MakeTable(crc32.Castagnoli)
		_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain), "plaintextCrc32c": fmt.Sprint(crc32.Checksum(plain, table)), "verifiedCiphertextCrc32c": true})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.URL = ts.URL
	return f
}

// Decrypts counts the decrypt calls so far.
func (f *FakeGCP) Decrypts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decrypts
}

// Env points esec-vault's GCP provider at the fake.
func (f *FakeGCP) Env() []string {
	return []string{"ESEC_VAULT_GCP_STS_URL=" + f.URL + "/sts", "ESEC_VAULT_GCP_KMS_URL=" + f.URL + "/kms"}
}

// SetAllow replaces the provider's attribute condition.
func (f *FakeGCP) SetAllow(allow func(claims map[string]any) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow = allow
}

// PublicKeyPEM is the key's public half as gcloud prints it.
func (f *FakeGCP) PublicKeyPEM() string {
	return "-----BEGIN PUBLIC KEY-----\n" + f.PublicKey + "\n-----END PUBLIC KEY-----\n"
}

func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}
