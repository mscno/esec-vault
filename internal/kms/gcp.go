package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// GCP is Google Cloud KMS, reached with workload identity federation: the
// workload's OIDC token (from Fly.io, GitHub Actions, ...) is exchanged at
// Google's Security Token Service for a short-lived access token, which the
// KMS key's IAM policy lets decrypt (cloudkms.cryptoKeyVersions.useToDecrypt,
// in roles/cloudkms.cryptoKeyDecrypter). Plain REST, no SDK.
//
// Key.Name is the key version, Key.Audience the workload identity
// provider (projects/NUMBER/locations/global/workloadIdentityPools/POOL/
// providers/PROVIDER), and Key.Principal, when set, a service account the
// federated identity impersonates instead of being granted the key itself.
type GCP struct {
	// STS, IAMCredentials and KMS replace Google's endpoints (tests set
	// them, or ESEC_VAULT_GCP_STS_URL and friends).
	STS, IAMCredentials, KMS string
	HTTP                     *http.Client
}

const (
	gcpSTS            = "https://sts.googleapis.com/v1/token"
	gcpIAMCredentials = "https://iamcredentials.googleapis.com/v1" //nolint:gosec // an endpoint, not a credential
	gcpKMS            = "https://cloudkms.googleapis.com/v1"
)

var (
	gcpVersion  = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]{1,64}/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}/cryptoKeyVersions/[0-9]{1,10}$`)
	gcpProvider = regexp.MustCompile(`^projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	gcpAccount  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
)

// Validate checks a GCP key's names.
func (g *GCP) Validate(k Key) error {
	if !gcpVersion.MatchString(k.Name) {
		return errors.New("a GCP KMS key is a key version: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N")
	}
	if !gcpProvider.MatchString(k.Audience) {
		return errors.New("a GCP audience is a workload identity provider: projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER")
	}
	if k.Principal != "" && !gcpAccount.MatchString(k.Principal) {
		return errors.New("a GCP principal is a service account email")
	}
	return nil
}

// TokenAudience is the audience of the OIDC token a GCP workload identity
// provider accepts by default.
func (g *GCP) TokenAudience(k Key) string { return "https://iam.googleapis.com/" + k.Audience }

// Unwrap exchanges the workload's token for an access token and asks Cloud
// KMS to decrypt.
func (g *GCP) Unwrap(ctx context.Context, k Key, ciphertext []byte, token TokenSource) ([]byte, error) {
	idToken, err := token(ctx, g.TokenAudience(k))
	if err != nil {
		return nil, err
	}
	if idToken == "" {
		return nil, errors.New("no OIDC token: this runs where no workload identity is available (a Fly.io Machine, a GitHub Actions job)")
	}
	access, err := g.exchange(ctx, k, idToken)
	if err != nil {
		return nil, err
	}
	if k.Principal != "" {
		if access, err = g.impersonate(ctx, k.Principal, access); err != nil {
			return nil, err
		}
	}
	return g.decrypt(ctx, k, ciphertext, access)
}

func (g *GCP) endpoint(field, env, def string) string {
	if field != "" {
		return field
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

func (g *GCP) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// exchange trades the workload's OIDC token for a federated access token.
func (g *GCP) exchange(ctx context.Context, k Key, idToken string) (string, error) {
	body := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {"//iam.googleapis.com/" + k.Audience},
		"scope":                {"https://www.googleapis.com/auth/cloud-platform"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":        {idToken},
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := g.post(ctx, g.endpoint(g.STS, "ESEC_VAULT_GCP_STS_URL", gcpSTS), "", "application/x-www-form-urlencoded", strings.NewReader(body.Encode()), &out); err != nil {
		return "", fmt.Errorf("google's token exchange refused the workload's OIDC token: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("google's token exchange returned no access token")
	}
	return out.AccessToken, nil
}

// impersonate trades a federated token for a service account's.
func (g *GCP) impersonate(ctx context.Context, account, access string) (string, error) {
	raw, err := json.Marshal(map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}, "lifetime": "600s"})
	if err != nil {
		return "", err
	}
	u := g.endpoint(g.IAMCredentials, "ESEC_VAULT_GCP_IAMCREDENTIALS_URL", gcpIAMCredentials) + "/projects/-/serviceAccounts/" + url.PathEscape(account) + ":generateAccessToken"
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := g.post(ctx, u, access, "application/json", bytes.NewReader(raw), &out); err != nil {
		return "", fmt.Errorf("impersonate %s: %w", account, err)
	}
	return out.AccessToken, nil
}

// decrypt asks Cloud KMS to decrypt, checking the CRC32C checksums both
// ways as Google recommends.
func (g *GCP) decrypt(ctx context.Context, k Key, ciphertext []byte, access string) ([]byte, error) {
	table := crc32.MakeTable(crc32.Castagnoli)
	raw, err := json.Marshal(map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext), "ciphertextCrc32c": fmt.Sprint(crc32.Checksum(ciphertext, table))})
	if err != nil {
		return nil, err
	}
	var out struct {
		Plaintext       string `json:"plaintext"`
		PlaintextCrc32c string `json:"plaintextCrc32c"`
		Verified        bool   `json:"verifiedCiphertextCrc32c"`
	}
	u := g.endpoint(g.KMS, "ESEC_VAULT_GCP_KMS_URL", gcpKMS) + "/" + k.Name + ":asymmetricDecrypt"
	if err := g.post(ctx, u, access, "application/json", bytes.NewReader(raw), &out); err != nil {
		return nil, fmt.Errorf("cloud KMS refused to decrypt with %s: %w", k.Name, err)
	}
	plain, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil || !out.Verified || out.PlaintextCrc32c != fmt.Sprint(crc32.Checksum(plain, table)) {
		return nil, errors.New("the answer from Cloud KMS was damaged in transit")
	}
	return plain, nil
}

func (g *GCP) post(ctx context.Context, u, bearer, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error            any    `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.ErrorDescription
		if msg == "" {
			if m, ok := e.Error.(map[string]any); ok {
				msg, _ = m["message"].(string)
			}
		}
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(msg))
	}
	return json.Unmarshal(raw, out)
}

func pemDER(pemText []byte) ([]byte, error) {
	b, _ := pem.Decode(pemText)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key (BEGIN PUBLIC KEY)")
	}
	return b.Bytes, nil
}
