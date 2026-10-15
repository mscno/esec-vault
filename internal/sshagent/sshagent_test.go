package sshagent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func serve(t *testing.T, keys ...any) *Agent {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "esa") //nolint:usetesting // unix socket paths must stay short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	a, err := DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestDeterministicKeys(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := serve(t, ed, rsaKey)
	keys, err := a.Keys()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys: %v", err)
	}
	for _, k := range keys {
		s1, err := a.CheckDeterministic(&k, "esec-vault-unlock", []byte("challenge"))
		if err != nil {
			t.Fatalf("%s: %v", k.Public.Type(), err)
		}
		s2, _ := a.Secret(&k, "esec-vault-unlock", []byte("other challenge"))
		s3, _ := a.Secret(&k, "another-namespace", []byte("challenge"))
		if string(s1) == string(s2) || string(s1) == string(s3) {
			t.Fatalf("%s: secret must depend on message and namespace", k.Public.Type())
		}
		found, err := a.Find(k.Fingerprint)
		if err != nil || found.Fingerprint != k.Fingerprint {
			t.Fatal("find by fingerprint")
		}
	}
}

func TestRefusesRandomizedKeys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := serve(t, ec)
	keys, _ := a.Keys()
	if err := Supported(keys[0].Public); err == nil {
		t.Fatal("ECDSA accepted")
	}
	if _, err := a.Secret(&keys[0], "ns", []byte("m")); err == nil {
		t.Fatal("ECDSA secret derived")
	}
	if _, err := a.Find("SHA256:nope"); err == nil {
		t.Fatal("unknown fingerprint found")
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(ed.Public())
	_, fp, err := ParseAuthorizedKey(ssh.MarshalAuthorizedKey(pub))
	if err != nil || fp != ssh.FingerprintSHA256(pub) {
		t.Fatalf("parse: %v", err)
	}
	if NormalizeFingerprint("abc") != "SHA256:abc" || NormalizeFingerprint("SHA256:abc") != "SHA256:abc" {
		t.Fatal("normalize")
	}
}
