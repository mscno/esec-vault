// Package sshagent derives unlock secrets from an SSH agent's signatures.
//
// An agent never reveals a private key, but for some key types the signature
// over a fixed message is itself fixed: Ed25519 (RFC 8032) and RSA PKCS#1
// v1.5 signatures are deterministic. Such a signature can serve as key
// material. ECDSA signatures are randomized, FIDO (sk-*) signatures include a
// counter, and Secure Enclave agents use ECDSA, so those keys are refused.
// Determinism is also checked at enrollment by signing twice.
package sshagent

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrNoAgent is returned when SSH_AUTH_SOCK is unset or unreachable.
var ErrNoAgent = errors.New("no SSH agent available (SSH_AUTH_SOCK is not set or not reachable)")

// ErrUnsupportedKey is returned for key types whose signatures vary.
var ErrUnsupportedKey = errors.New("only ssh-ed25519 and ssh-rsa keys produce repeatable signatures; ECDSA, FIDO (sk-*) and Secure Enclave keys cannot unlock a slot")

// Agent wraps an agent connection.
type Agent struct {
	client agent.ExtendedAgent
	conn   net.Conn
}

// Key is a public key held by the agent.
type Key struct {
	Public      ssh.PublicKey
	Comment     string
	Fingerprint string
}

// Dial connects to the agent at SSH_AUTH_SOCK.
func Dial() (*Agent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, ErrNoAgent
	}
	return DialPath(sock)
}

// DialPath connects to the agent socket at path.
func DialPath(path string) (*Agent, error) {
	conn, err := net.DialTimeout("unix", path, 3*time.Second) //nolint:gosec // the user's own SSH_AUTH_SOCK
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoAgent, err)
	}
	return &Agent{client: agent.NewClient(conn), conn: conn}, nil
}

// Close closes the connection.
func (a *Agent) Close() error { return a.conn.Close() }

// Keys lists the agent's keys.
func (a *Agent) Keys() ([]Key, error) {
	list, err := a.client.List()
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(list))
	for _, k := range list {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		out = append(out, Key{Public: pub, Comment: k.Comment, Fingerprint: ssh.FingerprintSHA256(pub)})
	}
	return out, nil
}

// Find returns the agent key with fingerprint fp.
func (a *Agent) Find(fp string) (*Key, error) {
	keys, err := a.Keys()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Fingerprint == fp {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("the SSH agent does not hold key %s", fp)
}

// Supported reports whether a key type yields deterministic signatures.
func Supported(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA:
		return nil
	}
	return fmt.Errorf("%w (got %s)", ErrUnsupportedKey, pub.Type())
}

// SignedData returns the SSHSIG "signed data" structure (PROTOCOL.sshsig)
// for message in namespace, with SHA-512 as the message hash.
func SignedData(namespace string, message []byte) []byte {
	h := sha512.Sum512(message)
	var b bytes.Buffer
	b.WriteString("SSHSIG")
	writeString(&b, []byte(namespace))
	writeString(&b, nil)
	writeString(&b, []byte("sha512"))
	writeString(&b, h[:])
	return b.Bytes()
}

func writeString(b *bytes.Buffer, s []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s))) //nolint:gosec // short protocol strings
	b.Write(l[:])
	b.Write(s)
}

// Sign signs the SSHSIG data of message in namespace and checks the result.
func (a *Agent) Sign(key *Key, namespace string, message []byte) (*ssh.Signature, error) {
	if err := Supported(key.Public); err != nil {
		return nil, err
	}
	data := SignedData(namespace, message)
	var flags agent.SignatureFlags
	if key.Public.Type() == ssh.KeyAlgoRSA {
		flags = agent.SignatureFlagRsaSha512
	}
	sig, err := a.client.SignWithFlags(key.Public, data, flags)
	if err != nil {
		return nil, fmt.Errorf("SSH agent refused to sign: %w", err)
	}
	if err := key.Public.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("SSH agent returned an invalid signature: %w", err)
	}
	if key.Public.Type() == ssh.KeyAlgoRSA && sig.Format != ssh.KeyAlgoRSASHA512 {
		return nil, fmt.Errorf("SSH agent signed with %s instead of rsa-sha2-512", sig.Format)
	}
	return sig, nil
}

// Secret signs message in namespace with key and returns key material: the
// signature format and blob, length-prefixed.
func (a *Agent) Secret(key *Key, namespace string, message []byte) ([]byte, error) {
	sig, err := a.Sign(key, namespace, message)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeString(&b, []byte(sig.Format))
	writeString(&b, sig.Blob)
	return b.Bytes(), nil
}

// CheckDeterministic signs twice and requires identical results.
func (a *Agent) CheckDeterministic(key *Key, namespace string, message []byte) ([]byte, error) {
	first, err := a.Secret(key, namespace, message)
	if err != nil {
		return nil, err
	}
	second, err := a.Secret(key, namespace, message)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, fmt.Errorf("SSH agent signatures for %s differ between calls; this agent cannot unlock a slot", key.Fingerprint)
	}
	return first, nil
}

// ParseAuthorizedKey reads a public key from authorized_keys/.pub text and
// returns its SHA256 fingerprint.
func ParseAuthorizedKey(text []byte) (ssh.PublicKey, string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(text) //nolint:dogsled // only the key is needed
	if err != nil {
		return nil, "", fmt.Errorf("not an SSH public key: %w", err)
	}
	return pub, ssh.FingerprintSHA256(pub), nil
}

// NormalizeFingerprint accepts "SHA256:..." with or without the prefix.
func NormalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if !strings.HasPrefix(fp, "SHA256:") {
		fp = "SHA256:" + fp
	}
	return fp
}
