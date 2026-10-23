package cli_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	vaultmachine "github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// failsWith runs a command that must fail with output containing want.
func failsWith(t *testing.T, m *machine, want string, args ...string) {
	t.Helper()
	out, err := m.cmd(m.home, "", "esec-vault", args...).CombinedOutput()
	if err == nil || !strings.Contains(string(out), want) {
		t.Fatalf("%s: esec-vault %s: want a failure with %q, got %v:\n%s", m.name, strings.Join(args, " "), want, err, out)
	}
}

// TestOrgEndToEnd sets up an organisation: its chain claims the name, its
// roster decides who may join its projects, its approved KMS keys are the
// only ones a workload's key is wrapped with, a Fly.io app is set up in
// one command, and removing someone from it takes them out of the
// projects and groups of every admin, through their devices.
func TestOrgEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	gcp := servertest.NewFakeGCP(t)
	gcp.SetAllow(func(c map[string]any) bool { return c["org_name"] == "acme" && c["app_name"] == "store" })
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithFlyOIDCBase(fly.URL)}, 53101343, 2002, 2003, 2004)
	h.GitHub.AddUser(53101343, "mscno")
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "create", p)

	person := func(id int64, login string) *machine {
		h.GitHub.AddUser(id, login)
		sock, _, key := testAgentKey(t)
		h.GitHub.AddKey(login, key)
		m := newMachine(t, bin, login).with(gh, "SSH_AUTH_SOCK="+sock)
		m.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
		loginAs(t, h, login, m.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, id)), "").wait(true)
		m.run("", "access", "prove")
		return m
	}
	alice, carol, dave := person(2002, "alice"), person(2003, "carol"), person(2004, "dave")

	// --- Claiming acme: only an admin of what is named after it may. ---
	failsWith(t, carol, "only an admin of acme/store", "org", "create", "acme")
	if out := owner.run("", "org", "create", "acme"); !strings.Contains(out, "Created the organisation acme") || !strings.Contains(out, "Fingerprint:") {
		t.Fatalf("org create:\n%s", out)
	}
	failsWith(t, carol, "exists already", "org", "create", "acme")
	// Now only its people create projects and groups named acme/...
	failsWith(t, carol, "you are not in it", "group", "create", "acme/carols")

	// --- The roster, and a members-only rule. ---
	if out := owner.run("", "org", "add", "acme", "alice"); !strings.Contains(out, "Added alice to acme as a member") {
		t.Fatalf("org add:\n%s", out)
	}
	owner.run("", "org", "add", "acme", "dave")
	if out := owner.run("", "org", "set", "acme", "--members-only", "--fly-org", "acme"); !strings.Contains(out, "only its people join") {
		t.Fatalf("org set:\n%s", out)
	}
	failsWith(t, owner, "lets only its people", "access", "grant", "carol", "--env", "dev", p)
	owner.run("", "access", "grant", "alice", "--env", "dev", p)
	owner.run("", "group", "create", "acme/backend")
	owner.run("", "group", "add", "acme/backend", "alice")
	owner.run("", "access", "grant", "acme/backend", "--env", "dev", p)

	// Dave runs a project of his own, which alice reads too.
	daveRepo := t.TempDir()
	dave.run("", "project", "init", "acme/tools", "--dir", daveRepo, "--env", "dev", "--format", "env")
	dave.run("", "access", "create", "--project=acme/tools")
	dave.run("", "access", "grant", "alice", "--env", "dev", "--project=acme/tools")
	// Until her device confirms acme's fingerprint, it cannot vouch for
	// whose projects they are.
	if out := alice.run("n\nn\nn\n", "access", "sync"); !strings.Contains(out, "has not confirmed") {
		t.Fatalf("alice's sync before confirming acme:\n%s", out)
	}
	var fp struct {
		Words string `json:"fingerprint"`
	}
	owner.runJSON(&fp, "org", "acme")
	alice.run("", "org", "trust", "acme", "--fingerprint", fp.Words)
	if out := alice.run("y\ny\ny\n", "access", "sync"); !strings.Contains(out, "belongs to the organisation acme") {
		t.Fatalf("alice's sync does not say the projects are acme's:\n%s", out)
	}

	// --- Approved KMS keys: the only ones a workload's key is wrapped with. ---
	pemFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(pemFile, []byte(gcp.PublicKeyPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	otherPEM := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherPEM, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	failsWith(t, owner, "has not approved that KMS key", "group", "workload", "acme/backend", "store", "--fly-org", "acme", "--fly-app", "store",
		"--gcp-key", gcp.KeyName, "--gcp-provider", gcp.Provider, "--public-key", otherPEM)
	if out := owner.run("", "org", "kms", "add", "acme", "gcp-prod", "--gcp-key", gcp.KeyName, "--gcp-provider", gcp.Provider, "--public-key", pemFile, "--default"); !strings.Contains(out, "approved the KMS key gcp-prod") || !strings.Contains(out, "by default") {
		t.Fatalf("org kms add:\n%s", out)
	}
	// The same name with another public key is not the approved key.
	failsWith(t, owner, "has not approved that KMS key", "group", "workload", "acme/backend", "store", "--fly-org", "acme", "--fly-app", "store",
		"--gcp-key", gcp.KeyName, "--gcp-provider", gcp.Provider, "--public-key", otherPEM)

	// --- A Fly.io app in one command, with no secret anywhere. ---
	out := owner.run("", "org", "fly-app", "acme", "store", "--read", "acme/store:prod")
	if !strings.Contains(out, "Created the group acme/store") || !strings.Contains(out, "acme/store reads acme/store prod") {
		t.Fatalf("org fly-app:\n%s", out)
	}
	desc := regexpFind(t, out, `ESEC_VAULT_WORKLOAD = "(esecw1_[A-Za-z0-9_-]+)"`)
	app := newMachine(t, bin, "app").with(append(gcp.Env(), vaultmachine.WorkloadEnv+"="+desc, vaultmachine.FlyAPIEnv+"="+fly.Socket)...)
	if o, err := app.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput(); err != nil || !strings.Contains(string(o), "postgres://db-prod") {
		t.Fatalf("the Fly.io app: %v\n%s", err, o)
	}
	// Running it again finds the workload there already.
	if out := owner.run("", "org", "fly-app", "acme", "store", "--read", "acme/store:prod"); strings.Contains(out, "Created the group") || !strings.Contains(out, desc) {
		t.Fatalf("org fly-app again:\n%s", out)
	}

	var shown struct {
		Signed  bool                `json:"signed"`
		Members []string            `json:"members"`
		Admins  []string            `json:"admins"`
		Left    map[string][]string `json:"left"`
	}
	owner.runJSON(&shown, "org", "acme")
	if !shown.Signed || strings.Join(shown.Admins, ",") != "mscno" || strings.Join(shown.Members, ",") != "alice,dave" {
		t.Fatalf("org --json: %+v", shown)
	}

	// --- Removing alice takes her out of everything of acme. ---
	out = owner.run("", "org", "remove", "acme", "alice", "--yes")
	if !strings.Contains(out, "Took alice out of acme/store") || !strings.Contains(out, "Took alice out of acme/backend") || !strings.Contains(out, "rotate acme/store dev") {
		t.Fatalf("org remove:\n%s", out)
	}
	// What a device can see: dave's shows his project, still to do.
	dave.runJSON(&shown, "org", "acme")
	if strings.Join(shown.Left["alice"], ",") != "acme/tools" {
		t.Fatalf("org --json after removing alice: %+v", shown)
	}
	// Dave's device applies nothing until he confirms acme's fingerprint.
	if out := dave.run("", "access", "sync"); strings.Contains(out, "Took alice out") || !strings.Contains(out, "has not confirmed") {
		t.Fatalf("dave's sync before confirming acme:\n%s", out)
	}
	failsWith(t, dave, "not the fingerprint words", "org", "trust", "acme", "--fingerprint", "wrong-words")
	dave.run("", "org", "trust", "acme", "--fingerprint", fp.Words)
	// Then his device takes her out of his project on its next sync.
	if out := dave.run("", "access", "sync"); !strings.Contains(out, "Took alice out of acme/tools") {
		t.Fatalf("dave's sync:\n%s", out)
	}
	if out := dave.run("", "access", "show", "--project=acme/tools"); strings.Contains(out, "alice") && !strings.Contains(out, "rotate") {
		t.Fatalf("alice still in acme/tools:\n%s", out)
	}
	shown.Left = nil
	dave.runJSON(&shown, "org", "acme")
	if len(shown.Left) != 0 {
		t.Fatalf("org --json after dave's sync: %+v", shown)
	}
	// Someone added again later is added on purpose: nobody takes them out.
	owner.run("", "org", "add", "acme", "alice")
	dave.run("", "access", "grant", "alice", "--env", "dev", "--project=acme/tools")
	owner.run("", "org", "remove", "acme", "alice", "--yes")
	owner.run("", "org", "add", "acme", "alice")
	if out := dave.run("", "access", "sync"); strings.Contains(out, "Took alice out") {
		t.Fatalf("dave's device took out someone who is back:\n%s", out)
	}
}
