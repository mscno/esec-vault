package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OpenBao is a self-hosted OpenBao (or HashiCorp Vault) with the Transit
// engine holding an RSA key (rsa-2048, rsa-3072 or rsa-4096), which
// decrypts RSA-OAEP with SHA-256, and the JWT auth method trusting the
// workload's OIDC issuer (such as https://oidc.fly.io/ORG).
//
// Key.Name is BASE/MOUNT/KEY/VERSION, such as
// https://bao.example.com/transit/esec-store/1; Key.Audience the audience
// the JWT role binds (bound_audiences); Key.Principal the JWT auth mount
// and role, such as jwt/fly-store.
type OpenBao struct {
	HTTP *http.Client
}

var (
	baoSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	baoVersion = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

// baoKey is a parsed OpenBao key name.
type baoKey struct {
	base                 string
	mount, name, version string
	authMount, authRole  string
}

func parseBao(k Key) (*baoKey, error) {
	u, err := url.Parse(k.Name)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("an OpenBao key is https://HOST[/PREFIX]/MOUNT/KEY/VERSION")
	}
	loopback := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return nil, errors.New("an OpenBao key is reached over https")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 3 {
		return nil, errors.New("an OpenBao key is https://HOST[/PREFIX]/MOUNT/KEY/VERSION")
	}
	n := len(parts)
	out := &baoKey{mount: parts[n-3], name: parts[n-2], version: parts[n-1]}
	for _, s := range parts[:n-1] {
		if !baoSegment.MatchString(s) {
			return nil, errors.New("invalid OpenBao key path")
		}
	}
	if !baoVersion.MatchString(out.version) {
		return nil, errors.New("an OpenBao key names its version, such as .../transit/esec-store/1")
	}
	prefix := ""
	if n > 3 {
		prefix = "/" + strings.Join(parts[:n-3], "/")
	}
	out.base = u.Scheme + "://" + u.Host + prefix
	authMount, role, ok := strings.Cut(k.Principal, "/")
	if !ok || !baoSegment.MatchString(authMount) || !baoSegment.MatchString(role) {
		return nil, errors.New("an OpenBao principal is the JWT auth mount and role, such as jwt/fly-store")
	}
	out.authMount, out.authRole = authMount, role
	return out, nil
}

// Validate checks an OpenBao key's names.
func (o *OpenBao) Validate(k Key) error {
	_, err := parseBao(k)
	return err
}

// Unwrap logs in with the workload's OIDC token and asks Transit to
// decrypt.
func (o *OpenBao) Unwrap(ctx context.Context, k Key, ciphertext []byte, token TokenSource) ([]byte, error) {
	b, err := parseBao(k)
	if err != nil {
		return nil, err
	}
	jwt, err := token(ctx, k.Audience)
	if err != nil {
		return nil, err
	}
	if jwt == "" {
		return nil, errors.New("no OIDC token: this runs where no workload identity is available (a Fly.io Machine, a GitHub Actions job)")
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := o.call(ctx, b.base+"/v1/auth/"+b.authMount+"/login", "", map[string]string{"role": b.authRole, "jwt": jwt}, &login); err != nil {
		return nil, fmt.Errorf("OpenBao refused the workload's OIDC token: %w", err)
	}
	if login.Auth.ClientToken == "" {
		return nil, errors.New("OpenBao returned no token")
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	ct := "vault:v" + b.version + ":" + base64.StdEncoding.EncodeToString(ciphertext)
	if err := o.call(ctx, b.base+"/v1/"+b.mount+"/decrypt/"+b.name, login.Auth.ClientToken, map[string]string{"ciphertext": ct}, &out); err != nil {
		return nil, fmt.Errorf("OpenBao refused to decrypt with %s: %w", b.name, err)
	}
	plain, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("OpenBao's answer is damaged")
	}
	return plain, nil
}

// OpenBaoPublicKey reads an OpenBao key version's public key (PEM), with an
// OpenBao token that may read the key.
func OpenBaoPublicKey(ctx context.Context, name, token string) ([]byte, error) {
	b, err := parseBao(Key{Name: name, Principal: "jwt/x"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+"/v1/"+b.mount+"/keys/"+b.name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenBao answered HTTP %d reading the key", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out.Data.Type, "rsa-") {
		return nil, fmt.Errorf("the OpenBao key is %s, not RSA", out.Data.Type)
	}
	v, ok := out.Data.Keys[b.version]
	if !ok || v.PublicKey == "" {
		return nil, fmt.Errorf("the OpenBao key has no version %s", b.version)
	}
	return []byte(v.PublicKey), nil
}

func (o *OpenBao) call(ctx context.Context, u, token string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	c := o.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return json.Unmarshal(data, out)
}
