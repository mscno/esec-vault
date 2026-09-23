package share

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/pelletier/go-toml/v2"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
)

// MembersDirName is the committed directory holding member proofs.
const MembersDirName = ".esec/members"

// VaultDirName is the committed directory holding per-member sealed blobs.
const VaultDirName = ".esec/vault"

// TrustedEntry records a TOFU-pinned member identity key.
type TrustedEntry struct {
	PublicKey   string    `toml:"pubkey"`
	Fingerprint string    `toml:"fingerprint"`
	FirstSeen   time.Time `toml:"first_seen"`
}

// TrustStore is the contents of trusted.toml.
type TrustStore struct {
	Members map[string]TrustedEntry `toml:"members"`
}

// LoadTrust reads the trust store; a missing file yields an empty store.
func LoadTrust() (*TrustStore, error) {
	data, err := os.ReadFile(paths.TrustedPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &TrustStore{Members: map[string]TrustedEntry{}}, nil
		}
		return nil, err
	}
	var ts TrustStore
	if err := toml.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("invalid trust store: %w", err)
	}
	if ts.Members == nil {
		ts.Members = map[string]TrustedEntry{}
	}
	return &ts, nil
}

// Save writes the trust store (0600).
func (ts *TrustStore) Save() error {
	if err := paths.EnsureHome(); err != nil {
		return err
	}
	data, err := toml.Marshal(ts)
	if err != nil {
		return err
	}
	return os.WriteFile(paths.TrustedPath(), data, 0600)
}

// ErrUntrusted is returned when a member has no TOFU pin.
var ErrUntrusted = errors.New("member is not trusted")

// ErrKeyChanged is returned when a pinned member presents a different key.
var ErrKeyChanged = errors.New("member key has changed since first trust")

// CheckTrust verifies a member's pin. Unknown members yield ErrUntrusted;
// pinned members presenting a new key yield ErrKeyChanged (hard failure —
// someone is re-keying; re-trust explicitly if expected).
func (ts *TrustStore) CheckTrust(login string, proof *Proof) error {
	entry, ok := ts.Members[login]
	if !ok {
		return fmt.Errorf("%w: %s (run 'esec-vault members trust %s' after verifying the fingerprint out-of-band)", ErrUntrusted, login, login)
	}
	pubBytes, err := hex.DecodeString(proof.EsecPubkey)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid pubkey in proof for %s", login)
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	fp := identity.Fingerprint(pub)
	if entry.Fingerprint != fp || entry.PublicKey != proof.EsecPubkey {
		return fmt.Errorf("%w: %s (pinned %s, now %s)", ErrKeyChanged, login, entry.Fingerprint, fp)
	}
	return nil
}

// Trust records a member's pin from a verified proof.
func (ts *TrustStore) Trust(login string, proof *Proof) error {
	pubBytes, err := hex.DecodeString(proof.EsecPubkey)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid pubkey in proof")
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	ts.Members[login] = TrustedEntry{
		PublicKey:   proof.EsecPubkey,
		Fingerprint: identity.Fingerprint(pub),
		FirstSeen:   time.Now().UTC(),
	}
	return nil
}

// blob is the committed per-member sealed keyring share.
type blob struct {
	Version         int    `json:"version"`
	FromFingerprint string `json:"from_fingerprint"`
	Timestamp       time.Time `json:"ts"`
	Payload         string `json:"payload"` // base64 sealed box
}

type sharePayload struct {
	Project string            `json:"project"`
	Entries map[string]string `json:"entries"`
	SHA256  string            `json:"sha256"`
}

func canonicalEntries(entries map[string]string) []byte {
	// Sorted-key JSON is canonical for our purposes.
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(entries[k])
		b.Write(kb)
		b.WriteString(":")
		b.Write(vb)
	}
	b.WriteString("}")
	return []byte(b.String())
}

// Share seals the project's keyring entries to each given member and writes
// committed blobs under .esec/vault/. Proofs are verified against GitHub and
// the TOFU trust store. If envs is empty, all entries are shared.
func Share(repoDir string, ks *keystore.Store, from *identity.Identity, logins []string, envs []string, httpClient *http.Client, githubBaseURL string) ([]string, error) {
	project, err := projectfile.ReadProjectFile(repoDir)
	if err != nil {
		return nil, err
	}
	entries, err := ks.Read(project)
	if err != nil {
		return nil, fmt.Errorf("no keyring in global store for %s; run 'esec-vault keyring migrate' first: %w", project, err)
	}
	if len(envs) > 0 {
		filtered := map[string]string{}
		for _, env := range envs {
			name := esec.EsecPrivateKey
			if env != "" {
				name = esec.EsecPrivateKey + "_" + strings.ToUpper(env)
			}
			if v, ok := entries[name]; ok {
				filtered[name] = v
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("none of the requested environments exist in the keyring")
		}
		entries = filtered
	}

	trust, err := LoadTrust()
	if err != nil {
		return nil, err
	}

	var written []string
	for _, login := range logins {
		proofPath := filepath.Join(repoDir, MembersDirName, login+".proof")
		data, err := os.ReadFile(proofPath) //nolint:gosec // repoDir is user-provided
		if err != nil {
			return written, fmt.Errorf("no proof for %s at %s (member must commit it)", login, proofPath)
		}
		proof, err := ParseProof(data)
		if err != nil {
			return written, fmt.Errorf("%s: %w", login, err)
		}
		if proof.Login != login {
			return written, fmt.Errorf("proof login %q does not match %q", proof.Login, login)
		}
		keys, err := FetchGitHubKeys(login, httpClient, githubBaseURL)
		if err != nil {
			return written, err
		}
		if err := VerifyProof(proof, keys); err != nil {
			return written, fmt.Errorf("proof verification failed for %s: %w", login, err)
		}
		if err := trust.CheckTrust(login, proof); err != nil {
			return written, err
		}

		pubBytes, _ := hex.DecodeString(proof.EsecPubkey)
		var pub [32]byte
		copy(pub[:], pubBytes)

		sum := sha256.Sum256(canonicalEntries(entries))
		payload, err := json.Marshal(sharePayload{Project: project, Entries: entries, SHA256: hex.EncodeToString(sum[:])})
		if err != nil {
			return written, err
		}
		sealed, err := crypto.SealAnonymous(payload, &pub)
		if err != nil {
			return written, err
		}
		b := blob{
			Version:         1,
			FromFingerprint: from.Fingerprint(),
			Timestamp:       time.Now().UTC(),
			Payload:         base64.StdEncoding.EncodeToString(sealed),
		}
		out, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return written, err
		}
		dir := filepath.Join(repoDir, VaultDirName)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return written, err
		}
		path := filepath.Join(dir, login+".esec")
		if err := os.WriteFile(path, out, 0644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// Sync opens the caller's committed share blobs in the repo and merges them
// into the global keyring store. It tries every blob; the ones sealed to this
// identity open, the rest fail decryption and are skipped.
func Sync(repoDir string, ks *keystore.Store, me *identity.Identity, confirm func(question string) bool) ([]string, error) {
	dir := filepath.Join(repoDir, VaultDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no shared secrets found in %s", dir)
		}
		return nil, err
	}

	var synced []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".esec") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // within repoDir
		if err != nil {
			continue
		}
		var b blob
		if err := json.Unmarshal(data, &b); err != nil || b.Version != 1 {
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(b.Payload)
		if err != nil {
			continue
		}
		plain, err := crypto.OpenAnonymous(sealed, &me.Public, &me.Private)
		if err != nil {
			continue // sealed to someone else
		}
		var p sharePayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, fmt.Errorf("%s: corrupt payload: %w", e.Name(), err)
		}
		sum := sha256.Sum256(canonicalEntries(p.Entries))
		if hex.EncodeToString(sum[:]) != p.SHA256 {
			return nil, fmt.Errorf("%s: payload integrity check failed", e.Name())
		}

		existing, readErr := ks.Read(p.Project)
		if readErr == nil {
			conflicts := []string{}
			for k, v := range p.Entries {
				if ev, ok := existing[k]; ok && ev != v {
					conflicts = append(conflicts, k)
				}
			}
			if len(conflicts) > 0 {
				if confirm == nil || !confirm(fmt.Sprintf("keyring for %s has conflicting values for %s; overwrite?", p.Project, strings.Join(conflicts, ", "))) {
					continue
				}
			}
			for k, v := range p.Entries {
				existing[k] = v
			}
			if err := ks.Write(p.Project, existing, true); err != nil {
				return synced, err
			}
		} else {
			if err := ks.Write(p.Project, p.Entries, false); err != nil {
				return synced, err
			}
		}
		synced = append(synced, fmt.Sprintf("%s (from %s)", p.Project, strings.TrimSuffix(e.Name(), ".esec")))
	}
	if len(synced) == 0 {
		return nil, fmt.Errorf("no share blobs in %s could be opened with your identity", dir)
	}
	return synced, nil
}
