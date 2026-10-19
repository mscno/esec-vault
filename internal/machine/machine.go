// Package machine is the client side of machine identities: a CI job or a
// deployed app holds one machine key (ESEC_VAULT_MACHINE_KEY) and fetches its
// project's environment keys with it. It verifies what the server returns
// from the project chain's first link, which the machine key names, so a
// server cannot hand it keys the project's admins did not grant.
package machine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// KeyEnv is the environment variable that holds a machine key.
const KeyEnv = "ESEC_VAULT_MACHINE_KEY"

// Keys are a machine's environment keys.
type Keys struct {
	Project string
	Machine string
	Name    string
	// Keys maps environment names to hex private keys.
	Keys map[string]string
}

// Load reads the machine key from KeyEnv, or from the file it names when it
// starts with "@" (for example @/run/secrets/esec).
func Load() (*team.MachineKey, error) {
	v := strings.TrimSpace(os.Getenv(KeyEnv))
	if v == "" {
		return nil, fmt.Errorf("%s is not set; store the key 'esec vault machine create' printed as this job's secret", KeyEnv)
	}
	if path, ok := strings.CutPrefix(v, "@"); ok {
		data, err := os.ReadFile(path) //nolint:gosec // the operator names the file
		if err != nil {
			return nil, err
		}
		v = strings.TrimSpace(string(data))
	}
	return team.ParseToken(v)
}

// Fetch gets the machine's keys from its server and verifies them.
// oidcToken proves the workload when the machine's policy requires it.
func Fetch(ctx context.Context, key *team.MachineKey, oidcToken string) (*Keys, error) {
	c, err := client.New(key.Server)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req := wire.MachineKeysRequest{Machine: key.ID, Project: key.Project, Timestamp: time.Now().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce), OIDCToken: oidcToken}
	hash := ""
	if oidcToken != "" {
		sum := sha256.Sum256([]byte(oidcToken))
		hash = hex.EncodeToString(sum[:])
	}
	req.Sig = ed25519.Sign(key.Sign(), team.KeysMessage(req.Machine, req.Project, req.Timestamp, req.Nonce, hash))
	resp, err := c.MachineKeys(ctx, req)
	if err != nil {
		return nil, err
	}
	return Verify(key, resp)
}

// Verify checks a server response against the machine key: the project
// chain must start at the key's root, the machine must be active in it, and
// the grant must come from an admin and carry the chain's current keys.
func Verify(key *team.MachineKey, resp *wire.MachineKeys) (*Keys, error) {
	verified := map[string]*chain.State{}
	chains := func(user string) (*chain.State, error) {
		if st, ok := verified[user]; ok {
			return st, nil
		}
		links, ok := resp.Chains[user]
		if !ok {
			return nil, fmt.Errorf("the server sent no user chain for %s", user)
		}
		st, err := chain.Verify(user, links)
		if err != nil {
			return nil, err
		}
		verified[user] = st
		return st, nil
	}
	if len(resp.Links) == 0 || resp.Links[0].Hash() != key.Root {
		return nil, errors.New("the server's project chain does not start where this machine key's does; refusing it")
	}
	st, err := team.Verify(key.Project, resp.Links, chains)
	if err != nil {
		return nil, fmt.Errorf("the project chain does not verify: %w", err)
	}
	m, ok := st.Machine(key.ID)
	if !ok || !key.Matches(m.Machine) {
		return nil, errors.New("this machine is no longer part of the project")
	}
	if resp.Grant == nil {
		return nil, errors.New("the server sent no keys")
	}
	pub, priv := key.Keys()
	_, keys, err := team.Open(resp.Grant, st, chains, team.Recipient{ID: key.ID, EncPub: pub}, priv)
	if err != nil {
		return nil, fmt.Errorf("the machine's keys do not verify: %w", err)
	}
	return &Keys{Project: key.Project, Machine: key.ID, Name: m.Name, Keys: keys}, nil
}

// GitHubToken returns a GitHub Actions OIDC token for audience, or "" when
// this is not a GitHub Actions job allowed to request one (the job needs
// 'permissions: id-token: write').
func GitHubToken(ctx context.Context, audience string) (string, error) {
	reqURL, token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || token == "" {
		return "", nil
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("invalid ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec // GitHub Actions' own token endpoint, from the runner's environment
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req) //nolint:gosec // see above
	if err != nil {
		return "", fmt.Errorf("request a GitHub Actions OIDC token: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions refused an OIDC token: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Value == "" {
		return "", errors.New("GitHub Actions returned no OIDC token")
	}
	return out.Value, nil
}

// Environ returns env with the keys added as ESEC_PRIVATE_KEY_<ENV>
// variables, limited to only when it is not empty.
func (k *Keys) Environ(env []string, only []string) ([]string, error) {
	out := append([]string(nil), env...)
	for _, n := range only {
		if _, ok := k.Keys[n]; !ok {
			return nil, fmt.Errorf("this machine cannot read %s (it reads %s)", n, strings.Join(k.Names(), ", "))
		}
	}
	for _, n := range k.Names() {
		if len(only) > 0 && !contains(only, n) {
			continue
		}
		out = append(out, team.EnvKey(n)+"="+k.Keys[n])
	}
	return out, nil
}

// Names lists the environments, sorted.
func (k *Keys) Names() []string {
	out := make([]string, 0, len(k.Keys))
	for n := range k.Keys {
		out = append(out, n)
	}
	return team.SortEnvs(out)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
