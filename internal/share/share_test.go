package share

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/projectfile"
	"golang.org/x/crypto/ssh"

	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
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
			w.Write([]byte(k + "\n"))
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

func TestTrustStore(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	id := testIdentity(t)
	proof := &Proof{Version: 1, Login: "alice", EsecPubkey: id.PublicHex()}

	ts, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.CheckTrust("alice", proof); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("expected ErrUntrusted, got %v", err)
	}
	if err := ts.Trust("alice", proof); err != nil {
		t.Fatal(err)
	}
	if err := ts.Save(); err != nil {
		t.Fatal(err)
	}

	ts2, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts2.CheckTrust("alice", proof); err != nil {
		t.Fatalf("trusted member rejected: %v", err)
	}

	other := testIdentity(t)
	changed := &Proof{Version: 1, Login: "alice", EsecPubkey: other.PublicHex()}
	if err := ts2.CheckTrust("alice", changed); !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("expected ErrKeyChanged, got %v", err)
	}
}

func TestShareSyncRoundTrip(t *testing.T) {
	privPath, pubLine := sshKeyFixture(t)

	// Owner with a project keyring in the global store.
	owner := testIdentity(t)
	ksDir := t.TempDir()
	ks := &keystore.Store{Dir: ksDir}
	if err := ks.Write("org/repo", map[string]string{"ESEC_PRIVATE_KEY_DEV": "deadbeef"}, false); err != nil {
		t.Fatal(err)
	}

	// Member bob proves ownership of his identity key.
	bob := testIdentity(t)
	proof, err := Prove("bob", bob.PublicHex(), privPath)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, MembersDirName), 0755); err != nil {
		t.Fatal(err)
	}
	data, _ := proof.Marshal()
	if err := os.WriteFile(filepath.Join(repo, MembersDirName, "bob.proof"), data, 0644); err != nil {
		t.Fatal(err)
	}

	// Trust bob (TOFU), then share.
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	trust, _ := LoadTrust()
	if err := trust.Trust("bob", proof); err != nil {
		t.Fatal(err)
	}
	if err := trust.Save(); err != nil {
		t.Fatal(err)
	}

	gh := fakeGitHub(t, map[string]string{"bob": pubLine})
	written, err := Share(repo, ks, owner, []string{"bob"}, nil, gh.Client(), gh.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 blob, got %v", written)
	}

	// Bob syncs into his own (empty) store.
	bobStore := &keystore.Store{Dir: t.TempDir()}
	synced, err := Sync(repo, bobStore, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 {
		t.Fatalf("unexpected sync result: %v", synced)
	}
	entries, err := bobStore.Read("org/repo")
	if err != nil {
		t.Fatal(err)
	}
	if entries["ESEC_PRIVATE_KEY_DEV"] != "deadbeef" {
		t.Fatalf("synced keyring wrong: %v", entries)
	}

	// A third party cannot open bob's blob.
	eve := testIdentity(t)
	eveStore := &keystore.Store{Dir: t.TempDir()}
	if _, err := Sync(repo, eveStore, eve, nil); err == nil {
		t.Fatal("eve should not be able to sync bob's blob")
	}
}

func TestShareRejectsUntrusted(t *testing.T) {
	privPath, pubLine := sshKeyFixture(t)
	owner := testIdentity(t)
	bob := testIdentity(t)

	ks := &keystore.Store{Dir: t.TempDir()}
	if err := ks.Write("org/repo", map[string]string{"ESEC_PRIVATE_KEY_DEV": "deadbeef"}, false); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	proof, err := Prove("bob", bob.PublicHex(), privPath)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := proof.Marshal()
	if err := os.MkdirAll(filepath.Join(repo, MembersDirName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, MembersDirName, "bob.proof"), data, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ESEC_VAULT_HOME", t.TempDir()) // empty trust store
	gh := fakeGitHub(t, map[string]string{"bob": pubLine})
	if _, err := Share(repo, ks, owner, []string{"bob"}, nil, gh.Client(), gh.URL); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("expected ErrUntrusted, got %v", err)
	}
}
