package share

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/crypto"
	"golang.org/x/crypto/ssh"

	"github.com/mscno/esec-vault/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		t.Fatal(err)
	}
	return &identity.Identity{Public: kp.Public, Private: kp.Private}
}

// sshKeyFixture generates an ed25519 SSH keypair and returns the private key
// path (OpenSSH format) plus the authorized_keys public line.
func sshKeyFixture(t *testing.T) (privPath, pubLine string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return privPath, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// fakeGitHub serves <login>.keys endpoints.
func fakeGitHub(t *testing.T, keys map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		login := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".keys")
		if k, ok := keys[login]; ok {
			if _, err := w.Write([]byte(k + "\n")); err != nil {
				panic(err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProveAndVerify(t *testing.T) {
	privPath, pubLine := sshKeyFixture(t)
	id := testIdentity(t)

	proof, err := Prove("alice", id.PublicHex(), privPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProof(data)
	if err != nil {
		t.Fatal(err)
	}

	gh := fakeGitHub(t, map[string]string{"alice": pubLine})
	keys, err := FetchGitHubKeys("alice", gh.Client(), gh.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(parsed, keys); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	// A proof for a different esec key must fail (statement binding).
	other := testIdentity(t)
	tampered := *parsed
	tampered.EsecPubkey = other.PublicHex()
	if err := VerifyProof(&tampered, keys); err == nil {
		t.Fatal("tampered proof accepted")
	}

	// A key not registered on GitHub must fail.
	gh2 := fakeGitHub(t, map[string]string{})
	if _, err := FetchGitHubKeys("alice", gh2.Client(), gh2.URL); err == nil {
		t.Fatal("expected 404 handling")
	}
}
