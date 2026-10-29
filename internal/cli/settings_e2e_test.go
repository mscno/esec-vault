package cli_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestSettingsEndToEnd starts project settings and device changes on the
// web and signs them on a device: leaving a project, archiving it, moving it
// to a new id (members follow it), deleting it, and approving, renaming and
// revoking a device.
func TestSettingsEndToEnd(t *testing.T) { //nolint:gocyclo // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343, 2002)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"

	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")
	owner.run("", "access", "create", p)
	owner.run("", "access", "grant", "alice", "--env", "dev", p)
	alice.run("y\n", "access", "sync")

	browser := func(login string) (*servertest.Browser, string) {
		t.Helper()
		b := h.Browser(login)
		_, page, err := b.Get("/account")
		if err != nil {
			t.Fatal(err)
		}
		return b, servertest.CSRF(page)
	}
	post := func(b *servertest.Browser, csrf, path string, form url.Values) {
		t.Helper()
		if status, _, err := b.Post(path, csrf, form); err != nil || status != http.StatusOK {
			t.Fatalf("POST %s: %d %v", path, status, err)
		}
	}
	ob, ocsrf := browser("mscno")
	ab, acsrf := browser("alice")

	// --- Alice leaves on the web; her device signs it. ---
	post(ab, acsrf, "/teams/acme/store/leave", url.Values{})
	if out := alice.run("", "changes", "--list"); !strings.Contains(out, "leave the project acme/store") {
		t.Fatalf("alice's changes:\n%s", out)
	}
	if out := alice.run("y\n", "changes"); !strings.Contains(out, "Left acme/store") {
		t.Fatalf("alice signs leaving:\n%s", out)
	}
	if out := owner.run("", "access", "show", p); strings.Contains(out, "alice") && !strings.Contains(out, "needs a new key") {
		t.Fatalf("alice is still a member:\n%s", out)
	}

	// --- Archive on the web, signed on a device; nothing is sent. ---
	owner.run("", "access", "grant", "alice", "--env", "dev", p)
	post(ob, ocsrf, "/teams/acme/store/archive", url.Values{})
	if out := owner.run("y\n", "changes"); !strings.Contains(out, "Archived acme/store") {
		t.Fatalf("sign the archive:\n%s", out)
	}
	if out := owner.run("", "access"); !strings.Contains(out, "archived") {
		t.Fatalf("access list after archiving:\n%s", out)
	}
	if out, err := owner.cmd(owner.home, "", "esec-vault", "access", "revoke", "alice", "--env", "dev", "--yes", p).CombinedOutput(); err == nil || !strings.Contains(string(out), "archived") {
		t.Fatalf("a change to an archived project: %v\n%s", err, out)
	}
	owner.run("", "access", "archive", "--undo", p)

	// --- Move it to a new id; alice's device follows without asking. ---
	if out := owner.run("", "access", "move", "acme/shop", "--yes", p); !strings.Contains(out, "Moved acme/store to acme/shop, with 1 member(s)") || !strings.Contains(out, `project = "acme/shop"`) {
		t.Fatalf("access move:\n%s", out)
	}
	if out := alice.run("", "access", "sync"); !strings.Contains(out, "+ acme/shop dev") {
		t.Fatalf("alice follows the move:\n%s", out)
	}
	if out := owner.run("", "access"); !strings.Contains(out, "moved to acme/shop") {
		t.Fatalf("access list after the move:\n%s", out)
	}
	if out := owner.run("", "access", "delete", "--yes", p); !strings.Contains(out, "Deleted acme/store from the server") {
		t.Fatalf("access delete:\n%s", out)
	}
	alice.run("", "access", "sync")
	if out := alice.run("", "access"); strings.Contains(out, "acme/store") {
		t.Fatalf("alice still lists the deleted project:\n%s", out)
	}

	// --- Transfer across personal/work tenants without copying Alice. ---
	owner.run("", "org", "create", "mscno")
	if out := owner.run("", "org", "mscno", "--json"); !strings.Contains(out, `"kind": "personal"`) {
		t.Fatalf("personal tenant kind:\n%s", out)
	}
	if out := owner.run("", "access", "move", "mscno/shop", "--yes", "--project=acme/shop"); !strings.Contains(out, "Cross-tenant transfer") || !strings.Contains(out, "alice") {
		t.Fatalf("cross-tenant transfer:\n%s", out)
	}
	var readers int
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM project_members WHERE project = 'mscno/shop' AND active = 1`).Scan(&readers); err != nil || readers != 1 {
		t.Fatalf("source collaborators copied across tenants: %d %v", readers, err)
	}
	owner.run("", "org", "create", "acme")
	owner.run("", "access", "move", "acme/final", "--yes", "--project=mscno/shop")
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM project_members WHERE project = 'acme/final' AND active = 1`).Scan(&readers); err != nil || readers != 1 {
		t.Fatalf("work tenant transfer: %d %v", readers, err)
	}

	// --- A new device: approved through a web change, typing its words. ---
	accountKey := regexpFind(t, owner.run("", "status"), `Account key: ([a-z-]+)`)
	vm := newMachine(t, bin, "vm")
	pl := login(t, h, vm, "", "--account-key", accountKey)
	words := pl.waitFor(`Check that it shows this fingerprint: (\S+)`)
	var list struct {
		Devices []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"devices"`
	}
	raw := owner.run("", "devices", "list", "--json")
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("devices list --json: %v\n%s", err, raw)
	}
	var vmID string
	for _, d := range list.Devices {
		if d.Name == "vm" {
			vmID = d.ID
		}
	}
	if vmID == "" {
		t.Fatalf("no pending vm:\n%s", raw)
	}
	post(ob, ocsrf, "/devices/"+vmID+"/approve", url.Values{})
	if out := owner.run("wrong words\n", "changes"); !strings.Contains(out, "not the words") {
		t.Fatalf("approval with wrong words:\n%s", out)
	}
	if out := owner.run(words+"\n", "changes"); !strings.Contains(out, "Approved vm") {
		t.Fatalf("approval with the device's words:\n%s", out)
	}
	pl.wait(true)

	// --- Rename it, then retire it, from the web. ---
	post(ob, ocsrf, "/devices/"+vmID+"/rename", url.Values{"name": {"build box"}})
	if out := owner.run("y\n", "changes"); !strings.Contains(out, `Renamed `+vmID+` to "build box"`) {
		t.Fatalf("sign the rename:\n%s", out)
	}
	post(ob, ocsrf, "/devices/"+vmID+"/revoke", url.Values{})
	if out := owner.run("y\n", "changes"); !strings.Contains(out, "Revoked build box") {
		t.Fatalf("sign the revocation:\n%s", out)
	}
}
