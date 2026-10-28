package cli_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// fakeYubiKey returns an age-plugin-yubikey recipient, as a YubiKey's
// would be: sealing to it needs no hardware.
func fakeYubiKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	compressed := append([]byte{2 + pub[64]&1}, pub[1:33]...)
	return plugin.EncodeRecipient("yubikey", compressed)
}

// TestSealedSharingEndToEnd shares environments by GitHub login: the key
// reaches a colleague through the repository alone, pinned to their
// GitHub id; a guarded environment reaches only their security key; a
// person with no account yet is sealed in when they come.
func TestSealedSharingEndToEnd(t *testing.T) { //nolint:gocyclo // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343, 2002, 2004)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	h.GitHub.AddUser(2004, "dave")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL

	// The owner's stand-in YubiKey, a software key its seals count as one.
	yubi, _ := age.GenerateX25519Identity()
	ids := filepath.Join(t.TempDir(), "yubi.txt")
	if err := os.WriteFile(ids, []byte(yubi.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := newMachine(t, bin, "owner").with(gh, "ESEC_VAULT_GUARD_IDENTITIES="+ids, "ESEC_VAULT_DIALOGS=off")
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	pf, err := projectfile.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := pf.Env["dev"].Readers; len(got) != 1 || got[0] != "mscno (gh:53101343)" {
		t.Fatalf("the owner is not a reader by GitHub id: %v", got)
	}

	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")
	alice.run("", "projects", "add", repo)
	if ok, _ := decrypts(alice, repo, "dev"); ok {
		t.Fatal("alice reads dev before it is shared")
	}

	// --- Shared by login; alice reads it from the repository. ---
	if out := owner.run("", "share", "dev", "--with", "alice", "--project", "acme/store"); !strings.Contains(out, "shared with alice") {
		t.Fatalf("share:\n%s", out)
	}
	pf, _ = projectfile.Load(repo)
	if !strings.Contains(strings.Join(pf.Env["dev"].Readers, ","), "alice (gh:2002)") {
		t.Fatalf("alice not pinned by id: %v", pf.Env["dev"].Readers)
	}
	if out := alice.run("", "seal", "sync", "--project", "acme/store"); !strings.Contains(out, "Opened 1 key") {
		t.Fatalf("alice's seal sync:\n%s", out)
	}
	if ok, out := decrypts(alice, repo, "dev"); !ok || !strings.Contains(out, "postgres://db-dev") {
		t.Fatalf("alice cannot read dev:\n%s", out)
	}
	if ok, _ := decrypts(alice, repo, "prod"); ok {
		t.Fatal("alice reads prod, which is not shared with her")
	}

	// --- Guarded prod: sealed to people's security keys only. Sealing to a
	// YubiKey's recipient needs age-plugin-yubikey (no hardware). ---
	plug, perr := exec.LookPath("age-plugin-yubikey")
	if perr != nil {
		t.Log("age-plugin-yubikey not installed: skipping the guarded sharing")
		return
	}
	owner = owner.with("PATH=" + bin + string(os.PathListSeparator) + filepath.Dir(plug) + string(os.PathListSeparator) + "/usr/bin:/bin")
	owner.run("", "guard", "enable", "--env", "prod", "--project", "acme/store")
	out := owner.run("", "share", "prod", "--with", "alice", "--project", "acme/store")
	if !strings.Contains(out, "alice") {
		t.Fatalf("share prod:\n%s", out)
	}
	recs, _ := seal.LoadRecords(repo)
	if pending := pendingOf(recs["prod"], "gh:2002"); !strings.Contains(pending, "security key") {
		t.Fatalf("alice has no security key: she should be pending, got %q", pending)
	}
	// alice registers her YubiKey; the owner's sync seals her in.
	yk := fakeYubiKey(t)
	alice.run("", "security-keys", "add", "--recipient", yk, "--kind", "yubikey", "--name", "blue")
	if out := owner.run("", "seal", "sync", "--project", "acme/store"); !strings.Contains(out, "prod sealed again") {
		t.Fatalf("owner's sync after alice's new key:\n%s", out)
	}
	recs, _ = seal.LoadRecords(repo)
	if !sealedTo(recs["prod"], "gh:2002", yk) {
		t.Fatalf("prod not sealed to alice's YubiKey: %+v", recs["prod"].Readers)
	}
	// Her user key does not open it: a guarded read needs her touch.
	if out := alice.run("", "seal", "sync", "--project", "acme/store"); strings.Contains(out, "Opened") {
		t.Fatalf("alice opened guarded prod without a touch:\n%s", out)
	}

	// --- Someone with no account yet: pinned by GitHub id, pending. ---
	out = owner.run("", "share", "dev", "--with", "dave", "--project", "acme/store")
	if !strings.Contains(out, "no esec vault account yet") {
		t.Fatalf("share with dave:\n%s", out)
	}
	pf, _ = projectfile.Load(repo)
	if !strings.Contains(strings.Join(pf.Env["dev"].Readers, ","), "dave (gh:2004)") {
		t.Fatalf("dave not pinned by id: %v", pf.Env["dev"].Readers)
	}

	// --- The seals check out, and a hand-added reader does not. ---
	if out := owner.run("", "seal", "status", "--project", "acme/store"); !strings.Contains(out, "alice") || !strings.Contains(out, "dave (pending)") {
		t.Fatalf("seal status:\n%s", out)
	}
	data, _ := os.ReadFile(filepath.Join(repo, "esec.toml")) //nolint:gosec // a test checkout
	sneaky := strings.Replace(string(data), `"alice (gh:2002)"`, `"alice (gh:2002)", "eve (gh:666)"`, 1)
	if err := os.WriteFile(filepath.Join(repo, "esec.toml"), []byte(sneaky), 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}
	c := owner.cmd(repo, "", "esec-vault", "seal", "check")
	if got, err := c.CombinedOutput(); err == nil || !strings.Contains(string(got), "readers") {
		t.Fatalf("a hand-added reader passed the check: %v\n%s", err, got)
	}
	if err := os.WriteFile(filepath.Join(repo, "esec.toml"), data, 0o600); err != nil { //nolint:gosec // a test checkout
		t.Fatal(err)
	}

	// --- Unshared: alice's next checkout cannot open dev. ---
	owner.run("", "unshare", "dev", "--with", "alice", "--project", "acme/store")
	fresh := newMachine(t, bin, "alice-laptop").with(gh, "SSH_AUTH_SOCK="+sock)
	fresh.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	pf, _ = projectfile.Load(repo)
	if strings.Contains(strings.Join(pf.Env["dev"].Readers, ","), "alice") {
		t.Fatalf("alice still a reader: %v", pf.Env["dev"].Readers)
	}
}

func pendingOf(rec *seal.Record, user string) string {
	for _, r := range rec.Readers {
		if strings.Contains(r.Reader, "("+user+")") {
			return r.Pending
		}
	}
	return ""
}

func sealedTo(rec *seal.Record, user, recipient string) bool {
	for _, r := range rec.Readers {
		if strings.Contains(r.Reader, "("+user+")") {
			for _, x := range r.Recipients {
				if x == recipient {
					return true
				}
			}
		}
	}
	return false
}
