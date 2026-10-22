package cli_test

import (
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// TestMachineGroupsEndToEnd runs a fleet: a group that reads prod of two
// projects, a CI job using a token directly, a host enrolled with the
// token, a host let in after comparing words, and a removal that rotates
// the group key and leaves the others working.
func TestMachineGroupsEndToEnd(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story with explicit checks
	if testing.Short() {
		t.Skip("builds binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	bin := buildBinaries(t)
	h := servertest.StartWith(t, []server.Option{server.WithRegistrationLimits(100, 1000)}, 53101343)
	h.GitHub.AddUser(53101343, "mscno")
	const g = "acme/production"

	// --- The owner has two projects, both with a prod environment. ---
	owner := newMachine(t, bin, "owner")
	owner.run("", "identity", "init", "--no-passphrase", "--skip-confirm")
	store, api := t.TempDir(), t.TempDir()
	owner.run("", "project", "init", "acme/store", "--dir", store, "--env", "dev,prod", "--format", "env")
	owner.run("", "project", "init", "acme/api", "--dir", api, "--env", "prod", "--format", "env")
	writeSecret(t, owner, store, "prod", "DATABASE_URL=postgres://store-prod")
	writeSecret(t, owner, store, "dev", "DATABASE_URL=postgres://store-dev")
	writeSecret(t, owner, api, "prod", "DATABASE_URL=postgres://api-prod")
	login(t, h, owner.with("ESEC_VAULT_BOOTSTRAP_TOKEN="+servertest.BootstrapToken), "").wait(true)
	owner.run("", "team", "create", "--project=acme/store")
	owner.run("", "team", "create", "--project=acme/api")

	// --- A group reads prod of both. ---
	if out := owner.run("", "group", "create", g); !strings.Contains(out, "Created the group "+g) {
		t.Fatalf("group create:\n%s", out)
	}
	for _, p := range []string{"acme/store", "acme/api"} {
		out := owner.run("", "group", "grant", g, "--env", "prod", "--project", p)
		if !strings.Contains(out, g+" reads prod of "+p) || !strings.Contains(out, "Sealed the keys to the group") {
			t.Fatalf("group grant %s:\n%s", p, out)
		}
	}

	// --- A CI job uses a token directly; each checkout gets its project's key. ---
	token, err := owner.cmd(owner.home, "", "esec-vault", "group", "token", g, "autoscale", "--expires", "30d", "--out", "-").Output()
	if err != nil || !strings.HasPrefix(string(token), "esecg1_") {
		t.Fatalf("group token: %v %q", err, token)
	}
	tok := strings.TrimSpace(string(token))
	ci := newMachine(t, bin, "ci").with("ESEC_VAULT_MACHINE_KEY=" + tok)
	decryptAs := func(m *machine, repo string) (bool, string) {
		out, err := m.cmd(repo, "", "esec-vault", "machine", "run", "--", "esec", "decrypt", ".env.prod").CombinedOutput()
		return err == nil, string(out)
	}
	if ok, out := decryptAs(ci, store); !ok || !strings.Contains(out, "postgres://store-prod") {
		t.Fatalf("ci in store:\n%s", out)
	}
	if ok, out := decryptAs(ci, api); !ok || !strings.Contains(out, "postgres://api-prod") {
		t.Fatalf("ci in api:\n%s", out)
	}
	if out, err := ci.cmd(store, "", "esec", "decrypt", ".env.dev").CombinedOutput(); err == nil {
		t.Fatalf("ci read dev:\n%s", out)
	}

	// --- A host enrolls with the token and keeps its own key. ---
	web1 := newMachine(t, bin, "web-1")
	out := web1.with("ESEC_VAULT_ENROLL_TOKEN="+tok).run("", "machine", "join", "--name", "web-1")
	if !strings.Contains(out, "This machine is web-1") || !strings.Contains(out, filepath.Join(web1.home, "machine.key")) {
		t.Fatalf("machine join with a token:\n%s", out)
	}
	if out := web1.run("", "machine", "whoami"); !strings.Contains(out, "machine of the group "+g) || !strings.Contains(out, "acme/api") || !strings.Contains(out, "acme/store") {
		t.Fatalf("whoami:\n%s", out)
	}
	var who struct {
		Name  string              `json:"name"`
		Kind  string              `json:"kind"`
		Group string              `json:"group"`
		Reads map[string][]string `json:"reads"`
	}
	raw := web1.runJSON(&who, "machine", "whoami")
	if who.Name != "web-1" || who.Kind != "machine" || who.Group != g || len(who.Reads["acme/api"]) == 0 || len(who.Reads["acme/store"]) == 0 {
		t.Fatalf("whoami --json:\n%s", raw)
	}
	if regexp.MustCompile(`[0-9a-f]{64}`).MatchString(raw) {
		t.Fatalf("whoami --json prints a key:\n%s", raw)
	}
	if ok, out := decryptAs(web1, store); !ok || !strings.Contains(out, "postgres://store-prod") {
		t.Fatalf("web-1:\n%s", out)
	}

	// --- A host asks to join; the owner compares its words and lets it in. ---
	web2 := newMachine(t, bin, "web-2")
	joining := web2.start("", "machine", "join", g, "--server", h.URL, "--name", "web-2")
	words := joining.waitFor(`\n  ([a-z]+(?:-[a-z]+){5})\n`)
	if out := owner.run("", "group", "show", g); !strings.Contains(out, "wait for approval") {
		t.Fatalf("group show with a join waiting:\n%s", out)
	}
	if out := owner.run("wrong-words-here-and-there\n", "group", "approve", g); !strings.Contains(out, "Those are not its words") {
		t.Fatalf("approve with wrong words:\n%s", out)
	}
	if out := owner.run(strings.ReplaceAll(words, "-", " ")+"\n", "group", "approve", g); !strings.Contains(out, "Let web-2 in") {
		t.Fatalf("approve:\n%s", out)
	}
	if out := joining.wait(true); !strings.Contains(out, "This machine is web-2") {
		t.Fatalf("join:\n%s", out)
	}
	if ok, out := decryptAs(web2, api); !ok || !strings.Contains(out, "postgres://api-prod") {
		t.Fatalf("web-2:\n%s", out)
	}

	out = owner.run("", "group", "show", g)
	for _, want := range []string{"web-1", "web-2", "autoscale", "enrolled with autoscale", "acme/api", "acme/store"} {
		if !strings.Contains(out, want) {
			t.Fatalf("group show lacks %q:\n%s", want, out)
		}
	}

	var shown struct {
		Group    string `json:"group"`
		Machines []struct {
			Name         string `json:"name"`
			EnrolledWith string `json:"enrolled_with"`
		} `json:"machines"`
		Tokens   []struct{ Name string } `json:"tokens"`
		Projects []struct {
			Project string   `json:"project"`
			Envs    []string `json:"envs"`
		} `json:"projects"`
	}
	raw = owner.runJSON(&shown, "group", "show", g)
	if shown.Group != g || len(shown.Machines) != 2 || shown.Machines[0].EnrolledWith == "" && shown.Machines[1].EnrolledWith == "" || len(shown.Tokens) != 1 || len(shown.Projects) != 2 {
		t.Fatalf("group show --json:\n%s", raw)
	}
	var groups []struct {
		ID       string `json:"id"`
		Machines int    `json:"machines"`
	}
	if raw := owner.runJSON(&groups, "group", "list"); len(groups) != 1 || groups[0].ID != g || groups[0].Machines != 2 {
		t.Fatalf("group list --json:\n%s", raw)
	}

	// --- Removing web-1 gives the group a new key; the others keep working. ---
	out = owner.run("", "group", "remove", g, "web-1", "--yes")
	if !strings.Contains(out, "has a new group key") || !strings.Contains(out, "It could read prod of acme/api") || !strings.Contains(out, "It could read prod of acme/store") {
		t.Fatalf("group remove:\n%s", out)
	}
	if ok, out := decryptAs(web1, store); ok {
		t.Fatalf("a removed machine still decrypted:\n%s", out)
	}
	for _, m := range []*machine{web2, ci} {
		if ok, out := decryptAs(m, store); !ok || !strings.Contains(out, "postgres://store-prod") {
			t.Fatalf("%s after the removal:\n%s", m.name, out)
		}
	}
	if out := owner.run("", "team", "show", "--project=acme/store"); !strings.Contains(out, g) {
		t.Fatalf("team show lacks the group:\n%s", out)
	}
	var team struct {
		Project string `json:"project"`
		Groups  []struct {
			Group string   `json:"group"`
			Envs  []string `json:"envs"`
		} `json:"groups"`
		Rotate []struct {
			Env     string `json:"env"`
			Command string `json:"command"`
		} `json:"rotate"`
	}
	var projects []struct {
		ID    string `json:"id"`
		Admin bool   `json:"admin"`
	}
	if raw := owner.runJSON(&projects, "team", "list"); len(projects) != 2 || !projects[0].Admin {
		t.Fatalf("team list --json:\n%s", raw)
	}
	raw = owner.runJSON(&team, "team", "show", "--project=acme/store")
	if team.Project != "acme/store" || len(team.Groups) != 1 || team.Groups[0].Group != g || len(team.Rotate) != 1 || team.Rotate[0].Command != "esec vault env rotate prod" {
		t.Fatalf("team show --json:\n%s", raw)
	}
	// The rotation to-do clears with a new prod key, which reaches the group.
	if out := owner.run("", "team", "sync"); !strings.Contains(out, "acme/store: prod need(s) a new key") {
		t.Fatalf("team sync after the removal:\n%s", out)
	}
	out = owner.run("", "env", "rotate", "prod", "--project=acme/store", "--dir", store, "--yes")
	if !strings.Contains(out, "group "+g) {
		t.Fatalf("env rotate did not reach the group:\n%s", out)
	}
	if ok, out := decryptAs(web2, store); !ok || !strings.Contains(out, "postgres://store-prod") {
		t.Fatalf("web-2 after the rotation:\n%s", out)
	}
	if out := owner.run("", "team", "sync"); strings.Contains(out, "acme/store: prod need(s)") {
		t.Fatalf("rotation to-do left after the rotation:\n%s", out)
	}

	// --- Revoking a project stops the group reading it. ---
	owner.run("", "group", "revoke", g, "--project", "acme/api")
	if ok, out := decryptAs(web2, api); ok {
		t.Fatalf("read a revoked project:\n%s", out)
	}
	status, page, err := h.Browser("mscno").Get("/groups/" + g)
	if err != nil || status != http.StatusOK || !strings.Contains(page, "web-2") || !strings.Contains(page, "removed the machine web-1") {
		t.Fatalf("group page: %d %v\n%s", status, err, page)
	}
}
