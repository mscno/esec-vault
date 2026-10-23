package cli_test

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	vaultmachine "github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestOrgWebEndToEnd runs an organisation from its web pages: each form
// proposes a change, the admin's device signs it, and the pages show the
// result, down to a Fly.io app reading its keys through OpenBao with the
// descriptor the Workloads page shows.
func TestOrgWebEndToEnd(t *testing.T) { //nolint:gocyclo // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	bao := servertest.NewFakeOpenBao(t, map[string]any{"org_name": "acme", "app_name": "store"})
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000), server.WithFlyOIDCBase(fly.URL)}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh, "BAO_TOKEN=root", "BAO_ADDR="+bao.URL)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "access", "create", p)
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")

	b := h.Browser("mscno")
	if _, _, err := b.Get("/account"); err != nil {
		t.Fatal(err)
	}
	get := func(path string, want ...string) string {
		t.Helper()
		code, page, err := b.Get(path)
		if err != nil || code != http.StatusOK {
			t.Fatalf("GET %s: %d %v\n%s", path, code, err, page)
		}
		for _, w := range want {
			if !strings.Contains(page, w) {
				t.Fatalf("GET %s lacks %q:\n%s", path, w, page)
			}
		}
		return page
	}
	post := func(page, path string, form url.Values, want string) string {
		t.Helper()
		code, out, err := b.Post(path, servertest.CSRF(page), form)
		if err != nil || code != http.StatusOK || !strings.Contains(out, want) {
			t.Fatalf("POST %s: %d %v; want %q in:\n%s", path, code, err, want, out)
		}
		return out
	}
	sign := func(want ...string) {
		t.Helper()
		out := owner.run("y\ny\ny\ny\n", "changes")
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Fatalf("changes lacks %q:\n%s", w, out)
			}
		}
	}

	// --- Set up acme from its page. ---
	page := get("/orgs/acme", "Set up acme")
	post(page, "/orgs/acme/claim", nil, "You asked to set it up")
	sign("CREATE the organisation acme", "Created the organisation acme")
	get("/orgs/acme", "Fingerprint", "People", "Workloads", "Approve a KMS key")
	get("/orgs", "acme", "signed")

	// --- People. ---
	page = get("/orgs/acme/people", "Add a person")
	post(page, "/orgs/acme/people", url.Values{"login": {"alice"}, "role": {"member"}}, "add alice")
	sign("acme: add alice as a member", "Added alice to acme as a member")
	get("/orgs/acme/people", "alice", "reads nothing yet")

	// --- A KMS key: the device reads its public half from OpenBao. ---
	page = get("/orgs/acme/settings", "Approve a key")
	post(page, "/orgs/acme/kms", url.Values{"name": {"bao-store"}, "provider": {"openbao"}, "key": {bao.KeyName()}, "audience": {bao.Audience}, "principal": {"jwt/" + bao.Role}}, "approve the KMS key bao-store")
	sign("APPROVE the KMS key", bao.KeyName(), "Approved the KMS key bao-store")
	// A key whose names do not parse is refused on the page already.
	if code, out, _ := b.Post("/orgs/acme/kms", servertest.CSRF(page), url.Values{"name": {"bad"}, "provider": {"gcp"}, "key": {"nope"}, "audience": {"x"}}); code == http.StatusOK && !strings.Contains(out, "key version") {
		t.Fatalf("a bad key was proposed:\n%s", out)
	}

	// --- Rules and defaults. ---
	page = get("/orgs/acme/settings", "bao-store")
	post(page, "/orgs/acme/settings", url.Values{"members_only": {"on"}, "fly_org": {"acme"}, "default_kms": {"bao-store"}, "max_token_days": {"30"}}, "change the rules and defaults")
	sign("only its people join its projects and groups", "Set the settings of acme")
	get("/orgs/acme/settings", `name="members_only" checked`, `<option value="bao-store" selected>`)

	// --- A Fly.io app, from one form. ---
	page = get("/orgs/acme/workloads", "Add a Fly.io app", `value="acme/store prod"`)
	post(page, "/orgs/acme/fly-apps", url.Values{"app": {"store"}, "read": {"acme/store prod"}}, "set up the Fly.io app store")
	sign("let the Fly.io app store", "Created the group acme/store", "acme/store reads acme/store prod")
	page = get("/orgs/acme/workloads", "bao-store", "acme/store prod")
	desc := regexpFind(t, page, `data-copy="(esecw1_[A-Za-z0-9_-]+)"`)
	app := newMachine(t, bin, "app").with(vaultmachine.WorkloadEnv+"="+desc, vaultmachine.FlyAPIEnv+"="+fly.Socket)
	if o, err := app.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput(); err != nil || !strings.Contains(string(o), "postgres://db-prod") {
		t.Fatalf("the Fly.io app: %v\n%s", err, o)
	}
	if code, body, err := b.Get("/orgs/acme/export"); err != nil || code != http.StatusOK || !strings.Contains(body, desc) || !strings.Contains(body, `"kms":"bao-store"`) {
		t.Fatalf("export: %d %v\n%s", code, err, body)
	}

	// --- Offboarding from the page: the owner's device signs it unasked
	// (changes --yes signs removals of members), and takes her out. ---
	owner.run("", "access", "grant", "alice", "--env", "dev", p)
	page = get("/orgs/acme/people", "acme/store: dev")
	post(page, "/orgs/acme/people/remove", url.Values{"login": {"alice"}}, "remove alice, and take them out")
	if out := owner.run("", "changes", "--yes"); !strings.Contains(out, "Removed alice from acme") || !strings.Contains(out, "Took alice out of acme/store") {
		t.Fatalf("changes --yes:\n%s", out)
	}
	if page := get("/orgs/acme/people"); strings.Contains(page, ">alice<") {
		t.Fatalf("alice is still listed:\n%s", page)
	}
	// Someone outside cannot be added now, on the page either.
	page = get("/teams/acme/store")
	if code, out, _ := b.Post("/teams/acme/store/members", servertest.CSRF(page), url.Values{"login": {"alice"}, "env": {"dev"}}); code == http.StatusOK && !strings.Contains(out, "only its people") {
		if out := owner.run("y\n", "changes"); !strings.Contains(out, "only its people") {
			t.Fatalf("someone outside acme was added:\n%s", out)
		}
	}
}
