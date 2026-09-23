// Package share implements git-native team sharing: per-member sealed keyring
// blobs committed into the repository, with member identity rooted in GitHub.
//
// X25519 (NaCl box) keys cannot sign, so proof of key ownership uses the
// member's GitHub-registered SSH key: a proof is an SSHSIG signature over a
// canonical statement, verified against https://github.com/<login>.keys.
// Verification results are pinned (TOFU) in ~/.config/esec/trusted.toml.
package share

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ProofNamespace is the SSHSIG namespace proofs are signed in.
const ProofNamespace = "esec-vault"

// ProofVersion is the current proof file version.
const ProofVersion = 1

// Proof binds a GitHub login to an esec identity public key.
type Proof struct {
	Version    int    `json:"version"`
	Login      string `json:"login"`
	EsecPubkey string `json:"esec_pubkey"` // hex
	Signature  string `json:"signature"`   // armored SSHSIG
}

// Statement returns the canonical bytes members sign.
func Statement(login, pubkeyHex string) []byte {
	return []byte(fmt.Sprintf("esec-vault v1\n%s\n%s\n", login, pubkeyHex))
}

// Prove signs the statement with the given SSH private key using ssh-keygen
// and returns a Proof. ssh-keygen is required because private SSH keys are
// frequently passphrase-protected or agent-held; shelling out keeps key
// handling in OpenSSH.
func Prove(login, pubkeyHex, sshKeyPath string) (*Proof, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return nil, fmt.Errorf("ssh-keygen not found: %w", err)
	}
	dir, err := os.MkdirTemp("", "esec-proof-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	stmtPath := filepath.Join(dir, "statement")
	if err := os.WriteFile(stmtPath, Statement(login, pubkeyHex), 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", ProofNamespace, "-f", sshKeyPath, stmtPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh-keygen sign failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sig, err := os.ReadFile(stmtPath + ".sig")
	if err != nil {
		return nil, fmt.Errorf("signature not produced: %w", err)
	}
	return &Proof{
		Version:    ProofVersion,
		Login:      login,
		EsecPubkey: pubkeyHex,
		Signature:  string(sig),
	}, nil
}

// Marshal serializes a proof for committing.
func (p *Proof) Marshal() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ParseProof parses a committed proof file.
func ParseProof(data []byte) (*Proof, error) {
	var p Proof
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	if p.Version != ProofVersion {
		return nil, fmt.Errorf("unsupported proof version %d", p.Version)
	}
	if p.Login == "" || p.EsecPubkey == "" || p.Signature == "" {
		return nil, fmt.Errorf("incomplete proof")
	}
	return &p, nil
}

// sshsig is the parsed SSHSIG file payload (PROTOCOL.sshsig).
type sshsig struct {
	pubkey   []byte
	ns       string
	hashAlg  string
	sig      []byte
}

const sshsigMagic = "SSHSIG"

func readSSHString(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("short ssh string")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < n {
		return nil, nil, errors.New("short ssh string payload")
	}
	return b[:n], b[n:], nil
}

// parseSSHSIG parses an armored SSHSIG file.
func parseSSHSIG(armored []byte) (*sshsig, error) {
	const begin = "-----BEGIN SSH SIGNATURE-----"
	const end = "-----END SSH SIGNATURE-----"
	s := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(s, begin) || !strings.HasSuffix(s, end) {
		return nil, errors.New("not an armored SSH signature")
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, begin), end))
	body = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, body)
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding: %w", err)
	}
	if len(raw) < 6+4 || string(raw[:6]) != sshsigMagic {
		return nil, errors.New("bad signature magic")
	}
	raw = raw[6:]
	if v := binary.BigEndian.Uint32(raw[:4]); v != 1 {
		return nil, fmt.Errorf("unsupported signature version %d", v)
	}
	raw = raw[4:]

	var out sshsig
	if out.pubkey, raw, err = readSSHString(raw); err != nil {
		return nil, err
	}
	var ns []byte
	if ns, raw, err = readSSHString(raw); err != nil {
		return nil, err
	}
	out.ns = string(ns)
	if _, raw, err = readSSHString(raw); err != nil { // reserved
		return nil, err
	}
	var hashAlg []byte
	if hashAlg, raw, err = readSSHString(raw); err != nil {
		return nil, err
	}
	out.hashAlg = string(hashAlg)
	if out.sig, raw, err = readSSHString(raw); err != nil {
		return nil, err
	}
	return &out, nil
}

// signedData reconstructs the SSHSIG signed message.
func (s *sshsig) signedData(message []byte) ([]byte, error) {
	var hash []byte
	switch s.hashAlg {
	case "sha256":
		h := sha256.Sum256(message)
		hash = h[:]
	case "sha512":
		h := sha512.Sum512(message)
		hash = h[:]
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", s.hashAlg)
	}
	var buf bytes.Buffer
	buf.WriteString(sshsigMagic)
	writeSSHString(&buf, []byte(s.ns))
	writeSSHString(&buf, nil) // reserved
	writeSSHString(&buf, []byte(s.hashAlg))
	writeSSHString(&buf, hash)
	return buf.Bytes(), nil
}

func writeSSHString(buf *bytes.Buffer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}

// VerifyProof checks that the proof's signature is a valid SSHSIG over the
// canonical statement, made by one of the given GitHub keys. The statement
// binds the login and esec pubkey, so a valid proof proves GitHub-account
// control over the claimed identity key.
func VerifyProof(p *Proof, githubKeys []ssh.PublicKey) error {
	sig, err := parseSSHSIG([]byte(p.Signature))
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	if sig.ns != ProofNamespace {
		return fmt.Errorf("unexpected signature namespace %q", sig.ns)
	}

	signer, err := ssh.ParsePublicKey(sig.pubkey)
	if err != nil {
		return fmt.Errorf("invalid signer key: %w", err)
	}
	found := false
	for _, k := range githubKeys {
		if bytes.Equal(k.Marshal(), signer.Marshal()) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("signing key is not registered on GitHub for %s", p.Login)
	}

	// The signature blob is SSH wire format: string algorithm, string sig.
	alg, rest, err := readSSHString(sig.sig)
	if err != nil {
		return fmt.Errorf("invalid signature blob: %w", err)
	}
	sigBlob, _, err := readSSHString(rest)
	if err != nil {
		return fmt.Errorf("invalid signature blob: %w", err)
	}
	parsed := &ssh.Signature{Format: string(alg), Blob: sigBlob}
	signedData, err := sig.signedData(Statement(p.Login, p.EsecPubkey))
	if err != nil {
		return err
	}
	if err := signer.Verify(signedData, parsed); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// FetchGitHubKeys retrieves the SSH public keys registered on a GitHub
// account. baseURL is injectable for testing (pass "" for the default).
func FetchGitHubKeys(login string, client *http.Client, baseURL string) ([]ssh.PublicKey, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if baseURL == "" {
		baseURL = "https://github.com"
	}
	resp, err := client.Get(baseURL + "/" + login + ".keys")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %d for %s.keys", resp.StatusCode, login)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for len(bytes.TrimSpace(data)) > 0 {
		k, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GitHub keys: %w", err)
		}
		keys = append(keys, k)
		data = rest
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH keys registered on GitHub for %s", login)
	}
	return keys, nil
}
