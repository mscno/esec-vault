package cli_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestPeopleGroupsEndToEnd gives a team of people access through a group:
// a member's devices take in the project's keys through the group, more
// access reaches them, offboarding takes everything away and lists the
// keys to rotate, and a member who leaves by themselves makes the admin's
// next sync give the group a new key.
func TestPeopleGroupsEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343, 2002, 2003)
	h.GitHub.AddUser(53101343, "mscno")
	h.GitHub.AddUser(2002, "alice")
	h.GitHub.AddUser(2003, "carol")
	sock, _, aliceKey := testAgentKey(t)
	h.GitHub.AddKey("alice", aliceKey)
	gh := "ESEC_VAULT_GITHUB_URL=" + h.GitHub.URL
	const p = "--project=acme/store"
	const g = "acme/backend"

	owner := newMachine(t, bin, "owner").with(gh)
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	repo := t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", repo, "--env", "dev,prod", "--format", "env")
	writeSecret(t, owner, repo, "dev", "DATABASE_URL=postgres://db-dev")
	writeSecret(t, owner, repo, "prod", "DATABASE_URL=postgres://db-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)

	alice := newMachine(t, bin, "alice").with(gh, "SSH_AUTH_SOCK="+sock)
	alice.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "alice", alice.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2002)), "").wait(true)
	alice.run("", "access", "prove")

	// --- The owner makes a team and lets it read dev. ---
	owner.run("", "access", "create", p)
	owner.run("", "group", "create", g)
	if out := owner.run("", "group", "add", g, "alice"); !strings.Contains(out, "Added alice to "+g) || !strings.Contains(out, "reads nothing yet") {
		t.Fatalf("group add:\n%s", out)
	}
	if out := owner.run("", "access", "grant", g, "--env", "dev", p); !strings.Contains(out, g+" reads dev of acme/store") || !strings.Contains(out, "Sent the keys of dev") {
		t.Fatalf("access grant to the group:\n%s", out)
	}
	if out := owner.run("", "access", "show", p); !strings.Contains(out, "people: alice") {
		t.Fatalf("access show lacks the group's people:\n%s", out)
	}

	// --- Alice's device asks once, then takes in dev through the group. ---
	if out := alice.run("n\n", "access", "sync"); !strings.Contains(out, "mscno added you to the group "+g+", which reads dev of the shared project acme/store") || strings.Contains(out, "+ acme/store") {
		t.Fatalf("alice sync, declined:\n%s", out)
	}
	if out := alice.run("y\n", "access", "sync"); !strings.Contains(out, "+ acme/store dev") {
		t.Fatalf("alice sync:\n%s", out)
	}
	if ok, out := decrypts(alice, repo, "dev"); !ok || !strings.Contains(out, "postgres://db-dev") {
		t.Fatalf("alice cannot decrypt dev:\n%s", out)
	}
	if ok, _ := decrypts(alice, repo, "prod"); ok {
		t.Fatal("alice decrypted prod through the group")
	}
	if out := alice.run("", "group"); !strings.Contains(out, g) || !strings.Contains(out, "member") {
		t.Fatalf("alice's group list:\n%s", out)
	}
	// A member changes nothing of the group.
	if out, err := alice.cmd(alice.home, "", "esec-vault", "group", "add", g, "mscno").CombinedOutput(); err == nil || !strings.Contains(string(out), "only an admin") {
		t.Fatalf("a member added someone: %v\n%s", err, out)
	}

	// --- More access reaches her too. ---
	if out := owner.run("", "access", "grant", g, "--env", "prod", p, "--json"); !strings.Contains(out, `"reads": [`) || !strings.Contains(out, `"prod"`) {
		t.Fatalf("access grant --json:\n%s", out)
	}
	if out := alice.run("", "access", "sync"); !strings.Contains(out, "+ acme/store prod") {
		t.Fatalf("alice sync after more access:\n%s", out)
	}
	if ok, out := decrypts(alice, repo, "prod"); !ok || !strings.Contains(out, "postgres://db-prod") {
		t.Fatalf("alice cannot decrypt prod:\n%s", out)
	}

	// --- Offboarding lists, then takes away, everything she reads. ---
	if out := owner.run("", "access", "offboard", "alice", "--dry-run"); !strings.Contains(out, "member of the group "+g+", which reads acme/store dev, acme/store prod") {
		t.Fatalf("offboard --dry-run:\n%s", out)
	}
	raw := owner.run("", "access", "offboard", "alice", "--yes", "--json")
	var off struct {
		Removed []string            `json:"removed"`
		Rotate  map[string][]string `json:"rotate"`
		Errors  []string            `json:"errors"`
	}
	if err := json.Unmarshal([]byte(raw), &off); err != nil {
		t.Fatalf("offboard --json: %v\n%s", err, raw)
	}
	if !slices.Equal(off.Removed, []string{g}) || !slices.Equal(off.Rotate["acme/store"], []string{"dev", "prod"}) || len(off.Errors) != 0 {
		t.Fatalf("offboard: %+v", off)
	}
	if out := owner.run("", "group", "show", g); strings.Contains(out, "Members") {
		t.Fatalf("group show after offboarding:\n%s", out)
	}
	if out := owner.run("", "access", "show", p); !strings.Contains(out, "member alice") {
		t.Fatalf("access show lacks the rotation to-do:\n%s", out)
	}

	// --- A member who leaves by themselves: the admin's sync rotates. ---
	owner.run("", "group", "add", g, "alice")
	alice.run("", "access", "sync")
	if out := alice.run("", "group", "leave", g, "--yes"); !strings.Contains(out, "Left "+g) {
		t.Fatalf("group leave:\n%s", out)
	}
	if out := owner.run("", "access", "sync"); !strings.Contains(out, "a new group key, since alice left") {
		t.Fatalf("owner sync after alice left:\n%s", out)
	}

	// --- People are granted and revoked directly with the same command. ---
	if out := owner.run("", "access", "grant", "alice", "--env", "dev", p); !strings.Contains(out, "alice reads dev of acme/store") {
		t.Fatalf("access grant to a person:\n%s", out)
	}
	if out := owner.run("", "access", "grant", "alice", "--env", "prod", p); !strings.Contains(out, "alice reads dev, prod of acme/store") {
		t.Fatalf("access grant more:\n%s", out)
	}
	if out := owner.run("", "access", "revoke", "alice", "--env", "prod", "--yes", p); !strings.Contains(out, "alice reads dev of acme/store") || !strings.Contains(out, "esec vault env rotate prod") {
		t.Fatalf("access revoke an environment:\n%s", out)
	}
	if out := owner.run("", "team", "revoke", "alice", "--yes", p); !strings.Contains(out, "alice reads nothing of acme/store") || !strings.Contains(out, "esec vault env rotate dev") {
		t.Fatalf("revoke through the old name:\n%s", out)
	}

	// --- The web: who reads what, one person, and offboarding. ---
	owner.run("", "group", "add", g, "alice")
	b := h.Browser("mscno")
	if _, _, err := b.Get("/account"); err != nil { // signs in
		t.Fatal(err)
	}
	_, page, err := b.Get("/access")
	if err != nil || !strings.Contains(page, "/people/alice") || !strings.Contains(page, "through <a href=\"/groups/"+g) {
		t.Fatalf("access page: %v\n%s", err, page)
	}
	_, page, err = b.Get("/people/alice")
	if err != nil || !strings.Contains(page, "Offboard alice") {
		t.Fatalf("person page: %v\n%s", err, page)
	}
	csrf := servertest.CSRF(page)
	if status, _, err := b.Post("/people/alice/offboard", csrf, url.Values{}); err != nil || status != http.StatusOK {
		t.Fatalf("offboard on the web: %d %v", status, err)
	}
	if out := owner.run("", "changes", "--yes"); !strings.Contains(out, "Removed alice from "+g) {
		t.Fatalf("sign the web offboarding:\n%s", out)
	}
	if out := owner.run("", "group", "show", g); strings.Contains(out, "Members") {
		t.Fatalf("alice is still in the group:\n%s", out)
	}

	// --- Someone without an account is invited; the invite waits. ---
	_, page, _ = b.Get("/teams/acme/store")
	csrf = servertest.CSRF(page)
	if status, _, err := b.Post("/teams/acme/store/members", csrf, url.Values{"login": {"carol"}, "env": {"dev"}}); err != nil || status != http.StatusOK {
		t.Fatalf("invite carol: %d %v", status, err)
	}
	if _, page, _ = b.Get("/teams/acme/store"); !strings.Contains(page, "waiting for their vault account") || !strings.Contains(page, "carol") {
		t.Fatalf("project page lacks the invite:\n%s", page)
	}
	carol := newMachine(t, bin, "carol").with(gh)
	carol.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	loginAs(t, h, "carol", carol.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+server.UserBootstrapToken(servertest.BootstrapSecret, 2003)), "").wait(true)
	if out := owner.run("", "changes", "--list"); !strings.Contains(out, "acme/store: add carol, who reads dev") {
		t.Fatalf("the invite did not become a change:\n%s", out)
	}

	// --- Exports. ---
	if _, out, err := b.Get("/teams/acme/store/export"); err != nil || !strings.HasPrefix(out, "time,source,actor,action,detail,ip,device") || !strings.Contains(out, "member_add") {
		t.Fatalf("project export: %v\n%s", err, out)
	}
	if _, out, err := b.Get("/groups/" + g + "/export?format=json"); err != nil || !strings.Contains(out, `"source": "chain"`) {
		t.Fatalf("group export: %v\n%s", err, out)
	}
	if _, out, err := b.Get("/activity/export"); err != nil || !strings.HasPrefix(out, "time,source") {
		t.Fatalf("activity export: %v\n%s", err, out)
	}
}
