// Package share proves that a key belongs to a GitHub account.
//
// X25519 (NaCl box) keys cannot sign, so proof of key ownership uses the
// member's GitHub-registered SSH key: a proof is an SSHSIG signature over a
// canonical statement, verified against https://github.com/<login>.keys.
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
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	sig, err := SignWithKeyFile(sshKeyPath, ProofNamespace, Statement(login, pubkeyHex))
	if err != nil {
		return nil, err
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
	pubkey  []byte
	ns      string
	hashAlg string
	sig     []byte
}

const sshsigMagic = "SSHSIG"

func readSSHString(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("short ssh string")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if int64(n) > int64(len(b)) {
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
	if out.sig, _, err = readSSHString(raw); err != nil {
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
	if len(b) > math.MaxUint32 {
		return // cannot happen for SSHSIG fields
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b))) //nolint:gosec // length checked above
	buf.Write(n[:])
	buf.Write(b)
}

// VerifyProof checks that the proof's signature is a valid SSHSIG over the
// canonical statement, made by one of the given GitHub keys. The statement
// binds the login and esec pubkey, so a valid proof proves GitHub-account
// control over the claimed identity key.
func VerifyProof(p *Proof, githubKeys []ssh.PublicKey) error {
	if err := VerifySSHSIG([]byte(p.Signature), ProofNamespace, Statement(p.Login, p.EsecPubkey), githubKeys); err != nil {
		if errors.Is(err, ErrUnknownSigner) {
			return fmt.Errorf("signing key is not registered on GitHub for %s", p.Login)
		}
		return err
	}
	return nil
}

// ErrUnknownSigner is returned when an SSH signature is valid in form but
// made by none of the expected keys.
var ErrUnknownSigner = errors.New("the signing key is not one of the expected keys")

// VerifySSHSIG checks that armored is an SSHSIG over message in namespace,
// made by one of keys.
func VerifySSHSIG(armored []byte, namespace string, message []byte, keys []ssh.PublicKey) error {
	sig, err := parseSSHSIG(armored)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	if sig.ns != namespace {
		return fmt.Errorf("unexpected signature namespace %q", sig.ns)
	}
	signer, err := ssh.ParsePublicKey(sig.pubkey)
	if err != nil {
		return fmt.Errorf("invalid signer key: %w", err)
	}
	found := false
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), signer.Marshal()) {
			found = true
			break
		}
	}
	if !found {
		return ErrUnknownSigner
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
	signedData, err := sig.signedData(message)
	if err != nil {
		return err
	}
	if err := signer.Verify(signedData, parsed); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// ArmorSSHSIG encodes a signature over the SHA-512 SSHSIG data of a message
// in namespace (as an SSH agent makes it) as an armored SSHSIG, the format
// of 'ssh-keygen -Y sign'.
func ArmorSSHSIG(pub ssh.PublicKey, namespace string, sig *ssh.Signature) []byte {
	var blob bytes.Buffer
	writeSSHString(&blob, []byte(sig.Format))
	writeSSHString(&blob, sig.Blob)
	var raw bytes.Buffer
	raw.WriteString(sshsigMagic)
	raw.Write([]byte{0, 0, 0, 1})
	writeSSHString(&raw, pub.Marshal())
	writeSSHString(&raw, []byte(namespace))
	writeSSHString(&raw, nil)
	writeSSHString(&raw, []byte("sha512"))
	writeSSHString(&raw, blob.Bytes())
	enc := base64.StdEncoding.EncodeToString(raw.Bytes())
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}

// SignWithKeyFile signs message in namespace with an SSH key file (or the
// agent key it names) through ssh-keygen, and returns the armored SSHSIG.
func SignWithKeyFile(sshKeyPath, namespace string, message []byte) ([]byte, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return nil, fmt.Errorf("ssh-keygen not found: %w", err)
	}
	dir, err := os.MkdirTemp("", "esec-proof-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	msgPath := filepath.Join(dir, "statement")
	if err := os.WriteFile(msgPath, message, 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", namespace, "-f", sshKeyPath, msgPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh-keygen sign failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sig, err := os.ReadFile(msgPath + ".sig") //nolint:gosec // our own temp file
	if err != nil {
		return nil, fmt.Errorf("signature not produced: %w", err)
	}
	return sig, nil
}

var githubLogin = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// GitHubURL is the GitHub web origin keys are fetched from:
// ESEC_VAULT_GITHUB_URL (for GitHub Enterprise and tests), else github.com.
func GitHubURL() string {
	if u := strings.TrimRight(os.Getenv("ESEC_VAULT_GITHUB_URL"), "/"); u != "" {
		return u
	}
	return "https://github.com"
}

// FetchGitHubKeys retrieves the SSH public keys registered on a GitHub
// account. baseURL is injectable for testing (pass "" for the default).
func FetchGitHubKeys(login string, client *http.Client, baseURL string) ([]ssh.PublicKey, error) {
	// The login goes into the URL, and may come from a server or a file in
	// a repository: anything but a GitHub login could point the request at
	// another page.
	if !githubLogin.MatchString(login) || strings.Contains(login, "--") || strings.HasSuffix(login, "-") {
		return nil, fmt.Errorf("invalid GitHub login %q", login)
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// github.com/LOGIN.keys never redirects; refuse a redirect elsewhere.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &c
	if baseURL == "" {
		baseURL = GitHubURL()
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
