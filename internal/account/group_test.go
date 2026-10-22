package account_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const group = "acme/production"

func fetchDev(ctx context.Context, t *testing.T, k *team.CredKey) string {
	t.Helper()
	keys, err := machine.FetchGroup(ctx, k, "")
	if err != nil {
		t.Fatalf("fetch as %s: %v", k.ID, err)
	}
	if len(keys.Problems) > 0 {
		t.Fatalf("problems: %v", keys.Problems)
	}
	return keys.Projects[project]["dev"]
}

func TestMachineGroups(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story
	oidc := servertest.NewFakeOIDC(t)
	h, a := setupWith(t, []server.Option{server.WithOIDCIssuer(oidc.URL, oidc.JWKS())})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	devPriv := strings.Repeat("ab", 32)

	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err == nil {
		t.Fatal("created a group twice")
	}
	res, err := a.GrantGroup(ctx, group, project, []string{"dev"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Trusted || !res.Granted || !res.Sent {
		t.Fatalf("grant: %+v", res)
	}

	// A token works directly, as a CI job's secret.
	tok, err := a.NewCred(ctx, group, team.KindToken, "autoscale", time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := team.ParseCredKey(tok.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := fetchDev(ctx, t, parsed); got != devPriv {
		t.Fatal("token did not get the key")
	}

	// A machine enrolls with the token, without an admin.
	web1, err := machine.Join(ctx, machine.JoinOptions{Token: parsed, Name: "web-1"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got := fetchDev(ctx, t, web1); got != devPriv {
		t.Fatal("enrolled machine did not get the key")
	}

	// A machine asks to join; the admin compares its words and lets it in.
	wordsCh := make(chan string, 1)
	type joined struct {
		key *team.CredKey
		err error
	}
	done := make(chan joined, 1)
	go func() {
		sent := false
		k, err := machine.Join(ctx, machine.JoinOptions{Server: h.URL, Group: group, Name: "web-2", Poll: 50 * time.Millisecond, Wait: func(w string) bool {
			if !sent {
				wordsCh <- w
				sent = true
			}
			return true
		}})
		done <- joined{k, err}
	}()
	words := <-wordsCh
	root, joins, err := a.PendingJoins(ctx, group)
	if err != nil || len(joins) != 1 {
		t.Fatalf("pending joins: %v %v", joins, err)
	}
	j := joins[0]
	if team.JoinWords(group, root, team.Credential{ID: j.Machine, Name: j.Name, EncPub: j.EncPub, SignPub: j.SignPub}) != words {
		t.Fatal("the admin's words differ from the machine's")
	}
	if err := a.ApproveJoin(ctx, group, j); err != nil {
		t.Fatal(err)
	}
	jr := <-done
	if jr.err != nil {
		t.Fatalf("join: %v", jr.err)
	}
	web2 := jr.key
	if got := fetchDev(ctx, t, web2); got != devPriv {
		t.Fatal("joined machine did not get the key")
	}
	if err := a.ApproveJoin(ctx, group, j); err == nil {
		t.Fatal("approved a join twice")
	}

	// A machine that pins the group's fingerprint refuses a look-alike.
	if _, err := machine.Join(ctx, machine.JoinOptions{Server: h.URL, Group: group, Name: "web-3", Fingerprint: team.GroupWords(group, strings.Repeat("f", 64))}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("join with a wrong fingerprint: %v", err)
	}
	// The last admin cannot leave.
	if _, err := a.RemoveGroupAdmin(ctx, group, a.State.Login); err == nil {
		t.Fatal("the last admin left")
	}

	// A machine set up by hand.
	db1, err := a.NewCred(ctx, group, team.KindMachine, "db-1", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fetchDev(ctx, t, db1); got != devPriv {
		t.Fatal("hand-made machine did not get the key")
	}

	// The group key sent to a machine is restored by an admin's sync.
	exec(t, h, `DELETE FROM group_key_grants WHERE to_id = ?`, db1.ID)
	if _, err := machine.FetchGroup(ctx, db1, ""); !client.IsCode(err, wire.ErrNotFound) {
		t.Fatalf("fetch without a key grant: %v", err)
	}
	sync, err := a.TeamSync(ctx, account.TeamSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(sync.Sent, func(s string) bool { return strings.Contains(s, "the group key") }) {
		t.Fatalf("sync did not resend the group key: %+v", sync)
	}
	if got := fetchDev(ctx, t, db1); got != devPriv {
		t.Fatal("machine did not get the key after sync")
	}

	// Removing a machine rotates the group key and re-seals the project;
	// the others keep working, the removed one stops.
	gone, err := a.RemoveCred(ctx, group, "web-1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !gone.Rotated || !slices.Contains(gone.Resealed, project) || !slices.Equal(gone.Exposed[project], []string{"dev"}) {
		t.Fatalf("remove: %+v", gone)
	}
	if _, err := machine.FetchGroup(ctx, web1, ""); err == nil {
		t.Fatal("removed machine still fetched keys")
	}
	for _, k := range []*team.CredKey{web2, db1, parsed} {
		if got := fetchDev(ctx, t, k); got != devPriv {
			t.Fatalf("%s lost its key after the rotation", k.ID)
		}
	}
	sync, err = a.TeamSync(ctx, account.TeamSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sync.Rotations[project], "dev") {
		t.Fatalf("no rotation to-do after removing a machine: %+v", sync.Rotations)
	}
	// A destroyed machine needs nothing rotated.
	gone, err = a.RemoveCred(ctx, group, "db-1", "VM deleted", true)
	if err != nil || gone.Rotated {
		t.Fatalf("remove destroyed: %+v %v", gone, err)
	}

	// A token removed as destroyed leaves the machines it enrolled working:
	// their group key is sealed again by the admin.
	tok2, err := a.NewCred(ctx, group, team.KindToken, "batch", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	batch1, err := machine.Join(ctx, machine.JoinOptions{Token: tok2, Name: "batch-1"})
	if err != nil {
		t.Fatal(err)
	}
	if gone, err := a.RemoveCred(ctx, group, "batch", "", true); err != nil || gone.Rotated {
		t.Fatalf("remove destroyed token: %+v %v", gone, err)
	}
	if got := fetchDev(ctx, t, batch1); got != devPriv {
		t.Fatal("a machine lost its key with the token that enrolled it")
	}
	if _, err := machine.FetchGroup(ctx, tok2, ""); err == nil {
		t.Fatal("removed token still fetched keys")
	}

	// A removal asked for on the web blocks the machine at once, and an
	// admin's device signs it.
	exec(t, h, `UPDATE group_creds SET suspended_at = 1 WHERE id = ?`, web2.ID)
	exec(t, h, `INSERT INTO changes (scope, target, kind, subject, created_by, created_at) VALUES ('group', ?, 'remove', ?, ?, 1)`, group, web2.ID, a.State.User)
	if _, err := machine.FetchGroup(ctx, web2, ""); err == nil {
		t.Fatal("blocked machine fetched keys")
	}
	props, err := a.Changes(ctx)
	if err != nil || len(props) != 1 || props[0].Name != "web-2" {
		t.Fatalf("changes: %+v %v", props, err)
	}
	if _, err := a.RemoveCred(ctx, group, props[0].Subject, "removed on the web", false); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseChange(ctx, props[0].ID, true); err != nil {
		t.Fatal(err)
	}

	// The server cannot hand a machine keys of a project the group does
	// not trust: the machine checks the group chain.
	n := "nonce-for-a-raw-request-1"
	req := wire.GroupKeysRequest{Group: group, ID: parsed.ID, Timestamp: time.Now().Unix(), Nonce: n}
	req.Sig = ed25519.Sign(parsed.Sign(), team.GroupKeysMessage(req.Group, req.ID, req.Timestamp, req.Nonce, ""))
	c, _ := client.New(h.URL)
	resp, err := c.FleetKeys(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	evil := resp.Projects[0]
	evil.Project = "acme/other"
	resp.Projects = append(resp.Projects, evil)
	keys, err := machine.VerifyGroup(parsed, resp, time.Now())
	if err != nil || len(keys.Projects) != 1 || len(keys.Problems) != 1 {
		t.Fatalf("untrusted project: %+v %v", keys, err)
	}

	// Taking the group's access away stops it reading the project.
	if _, err := a.GrantGroup(ctx, group, project, nil); err != nil {
		t.Fatal(err)
	}
	keys, err = machine.FetchGroup(ctx, parsed, "")
	if err != nil || len(keys.Projects) != 0 {
		t.Fatalf("after revoke: %+v %v", keys, err)
	}

	view, err := a.Group(ctx, group)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.State.ActiveCreds(team.KindMachine)) != 1 || len(view.State.ActiveCreds(team.KindToken)) != 1 {
		t.Fatalf("view: %+v", view.State.Creds)
	}
}

func TestGroupTokenWithOIDC(t *testing.T) {
	oidc := servertest.NewFakeOIDC(t)
	_, a := setupWith(t, []server.Option{server.WithOIDCIssuer(oidc.URL, oidc.JWKS())})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GrantGroup(ctx, group, project, []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	policy := &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: "acme/store"}
	tok, err := a.NewCred(ctx, group, team.KindToken, "deploy", time.Time{}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.FetchGroup(ctx, tok, ""); !client.IsCode(err, wire.ErrForbidden) {
		t.Fatalf("token without an OIDC token: %v", err)
	}
	tokenFor := func(repo string) string {
		return oidc.Token(map[string]any{"aud": a.State.Server, "repository": repo, "repository_id": "1", "ref": "refs/heads/main"})
	}
	if _, err := machine.FetchGroup(ctx, tok, tokenFor("acme/other")); !client.IsCode(err, wire.ErrForbidden) {
		t.Fatalf("token from another repository: %v", err)
	}
	keys, err := machine.FetchGroup(ctx, tok, tokenFor("acme/store"))
	if err != nil || keys.Projects[project]["dev"] == "" {
		t.Fatalf("token with a matching OIDC token: %+v %v", keys, err)
	}
	// A machine it enrolls inherits the policy.
	if _, err := machine.Join(ctx, machine.JoinOptions{Token: tok, Name: "runner"}); !client.IsCode(err, wire.ErrForbidden) {
		t.Fatalf("enroll without an OIDC token: %v", err)
	}
	m, err := machine.Join(ctx, machine.JoinOptions{Token: tok, Name: "runner", OIDCToken: tokenFor("acme/store")})
	if err != nil {
		t.Fatalf("enroll with an OIDC token: %v", err)
	}
	if _, err := machine.FetchGroup(ctx, m, ""); !client.IsCode(err, wire.ErrForbidden) {
		t.Fatalf("enrolled machine without an OIDC token: %v", err)
	}
}

// getPage fetches a page and fails unless it rendered in full.
func getPage(t *testing.T, b *servertest.Browser, path string, want ...string) string {
	t.Helper()
	status, page, err := b.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || !strings.Contains(page, "The server stores only ciphertext.") {
		t.Fatalf("%s: HTTP %d\n%s", path, status, page)
	}
	for _, w := range want {
		if !strings.Contains(page, w) {
			t.Fatalf("%s lacks %q:\n%s", path, w, page)
		}
	}
	return page
}

func TestGroupWebPages(t *testing.T) { //nolint:gocyclo // one sequential story
	h, a := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GrantGroup(ctx, group, project, []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.NewCred(ctx, group, team.KindToken, "autoscale", time.Now().Add(24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	web1, err := a.NewCred(ctx, group, team.KindMachine, "web-1", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fetchDev(ctx, t, web1); got == "" {
		t.Fatal("no key")
	}
	// A machine asks to join and is left waiting.
	k, cred, err := team.NewCredKey(h.URL, group, strings.Repeat("0", 64), team.KindMachine, "web-2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := wire.GroupJoin{Group: group, Machine: cred.ID, Name: cred.Name, EncPub: cred.EncPub, SignPub: cred.SignPub, Timestamp: time.Now().Unix(), Nonce: "join-nonce-for-the-web-test"}
	req.Sig = ed25519.Sign(k.Sign(), team.JoinMessage("join", group, cred, req.Timestamp, req.Nonce))
	c, _ := client.New(h.URL)
	if _, err := c.FleetJoin(ctx, req, false); err != nil {
		t.Fatal(err)
	}

	b := h.Browser("mscno")
	getPage(t, b, "/groups", group, "1 to approve")
	page := getPage(t, b, "/groups/"+group, "web-1", "autoscale", "web-2", "esec vault group approve "+group, project, "created the group", "Fetched its keys")
	if strings.Contains(page, team.JoinWords(group, strings.Repeat("0", 64), cred)) {
		t.Fatal("the web page shows join words")
	}
	getPage(t, b, "/teams/"+project, group, "let the machine group "+group+" read dev")
	getPage(t, b, "/account", group+": 1 machine waiting to join")

	// Changes on the web wait for a device; a removal blocks at once.
	csrf := servertest.CSRF(page)
	if status, body, err := b.Post("/groups/"+group+"/access", csrf, url.Values{"project": {project}}); err != nil || status != http.StatusOK {
		t.Fatalf("access form: %d %v\n%s", status, err, body)
	}
	if status, body, err := b.Post("/groups/"+group+"/remove", csrf, url.Values{"cred": {web1.ID}}); err != nil || status != http.StatusOK {
		t.Fatalf("remove form: %d %v\n%s", status, err, body)
	}
	if status, _, _ := b.Post("/groups/"+group+"/remove", "", url.Values{"cred": {web1.ID}}); status != http.StatusForbidden {
		t.Fatalf("form without CSRF: %d", status)
	}
	if _, err := machine.FetchGroup(ctx, web1, ""); err == nil {
		t.Fatal("blocked machine fetched keys")
	}
	page = getPage(t, b, "/groups/"+group, "change waiting to be signed", "blocked")
	props, err := a.Changes(ctx)
	if err != nil || len(props) != 2 {
		t.Fatalf("changes: %+v %v", props, err)
	}
	for _, p := range props {
		switch p.Kind {
		case wire.ChangeAccess:
			res, err := a.GrantGroup(ctx, group, p.Project, p.Envs)
			if err != nil || !res.Granted {
				t.Fatalf("apply access: %+v %v", res, err)
			}
			if err := a.CloseChange(ctx, p.ID, true); err != nil {
				t.Fatal(err)
			}
		case wire.ChangeRemove:
			// Dismissing a removal lets the machine back in.
			if status, body, err := b.Post("/groups/"+group+"/changes/"+strconv.FormatInt(p.ID, 10)+"/dismiss", servertest.CSRF(page), nil); err != nil || status != http.StatusOK {
				t.Fatalf("dismiss: %d %v\n%s", status, err, body)
			}
		}
	}
	keys, err := machine.FetchGroup(ctx, web1, "")
	if err != nil || len(keys.Projects) != 0 {
		t.Fatalf("after the web changes: %+v %v", keys, err)
	}
	_, joins, err := a.PendingJoins(ctx, group)
	if err != nil || len(joins) != 1 {
		t.Fatal(joins, err)
	}
	if status, body, err := b.Post("/groups/"+group+"/joins/"+joins[0].ID+"/reject", servertest.CSRF(page), nil); err != nil || status != http.StatusOK {
		t.Fatalf("reject: %d %v\n%s", status, err, body)
	}
	if res, err := c.FleetJoin(ctx, signedJoin(k, cred, "status", "status-nonce-for-the-web-tst"), true); err != nil || res.Status != wire.JoinRejected {
		t.Fatalf("status after reject: %+v %v", res, err)
	}
}

func signedJoin(k *team.CredKey, cred team.Credential, action, nonce string) wire.GroupJoin {
	req := wire.GroupJoin{Group: group, Machine: cred.ID, Name: cred.Name, EncPub: cred.EncPub, SignPub: cred.SignPub, Timestamp: time.Now().Unix(), Nonce: nonce}
	req.Sig = ed25519.Sign(k.Sign(), team.JoinMessage(action, group, cred, req.Timestamp, req.Nonce))
	return req
}

// dsRequest sends a request the way Datastar does, from the page's origin
// unless origin says otherwise.
func dsRequest(t *testing.T, h *servertest.Harness, b *servertest.Browser, method, path, origin string, form url.Values) (dsResponse, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, h.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Datastar-Request", "true")
	req.Header.Set("Accept", "text/event-stream, text/html, application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin == "" {
		origin = h.URL
	}
	req.Header.Set("Origin", origin)
	resp, err := b.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return dsResponse{StatusCode: resp.StatusCode, Header: resp.Header}, string(raw)
}

// dsResponse is what the tests check of a response.
type dsResponse struct {
	StatusCode int
	Header     http.Header
}

func TestDatastarPages(t *testing.T) { //nolint:gocyclo // one sequential story
	h, a := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GrantGroup(ctx, group, project, []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	b := h.Browser("mscno")

	// Pages load Datastar in nonce mode, under a policy without eval.
	status, page, err := b.Get("/teams/" + project)
	if err != nil || status != http.StatusOK {
		t.Fatal(status, err)
	}
	m := regexp.MustCompile(`<html lang="en" data-nonce="([A-Za-z0-9_-]{20,})">`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no nonce:\n%s", page[:300])
	}
	resp, err := b.Client().Get(h.URL + "/teams/" + project)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") || strings.Contains(csp, "unsafe") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("policy: %s", csp)
	}
	for _, want := range []string{`src="/static/datastar.js"`, `data-on:submit="`, `data-on-interval__duration.15s="@get(&#39;/teams/` + project + `/live&#39;)"`, `action="/teams/` + project + `/members"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %s", want)
		}
	}
	csrf := servertest.CSRF(page)

	// A form sent in place answers with patches and a message.
	dr, body := dsRequest(t, h, b, http.MethodPost, "/teams/"+project+"/members/set", "", url.Values{"csrf": {csrf}, "login": {"mscno"}, "admin": {"on"}})
	if dr.StatusCode != http.StatusOK || !strings.HasPrefix(dr.Header.Get("Content-Type"), "text/event-stream") || !strings.Contains(body, "datastar-patch-elements") || !strings.Contains(body, "esec vault changes") || !strings.Contains(body, `id="team-members"`) {
		t.Fatalf("member change: %d %s\n%s", dr.StatusCode, dr.Header.Get("Content-Type"), body)
	}
	// Errors come back as a message too.
	_, body = dsRequest(t, h, b, http.MethodPost, "/teams/"+project+"/members", "", url.Values{"csrf": {csrf}, "login": {"nobody-here"}, "env": {"dev"}})
	if !strings.Contains(body, "has no account on this server") || !strings.Contains(body, `id="flash"`) {
		t.Fatalf("member add error:\n%s", body)
	}
	_, body = dsRequest(t, h, b, http.MethodPost, "/teams/"+project+"/members", "", url.Values{"csrf": {csrf}, "login": {"x'+alert(1)+'"}, "env": {"dev"}})
	if !strings.Contains(body, "not a GitHub login") || strings.Contains(body, "alert(1)") {
		t.Fatalf("bad login:\n%s", body)
	}
	// Without the CSRF token, or from another site, nothing changes.
	_, body = dsRequest(t, h, b, http.MethodPost, "/teams/"+project+"/members/set", "", url.Values{"login": {"mscno"}, "env": {"dev"}})
	if !strings.Contains(body, "The form expired") {
		t.Fatalf("no csrf:\n%s", body)
	}
	_, body = dsRequest(t, h, b, http.MethodPost, "/teams/"+project+"/members/set", "https://evil.example", url.Values{"csrf": {csrf}, "login": {"mscno"}, "env": {"dev"}})
	if !strings.Contains(body, "The form expired") {
		t.Fatalf("other origin:\n%s", body)
	}
	changes, err := a.Changes(ctx)
	if err != nil || len(changes) != 1 || changes[0].Kind != wire.ChangeMemberSet || !changes[0].Admin || changes[0].Subject != "mscno" {
		t.Fatalf("changes: %+v %v", changes, err)
	}

	// The changes page lists it; dismissing it in place removes it.
	page = getPage(t, b, "/changes", project, "let mscno read everything, as an admin")
	_, body = dsRequest(t, h, b, http.MethodPost, "/changes/"+strconv.FormatInt(changes[0].ID, 10)+"/dismiss", "", url.Values{"csrf": {servertest.CSRF(page)}})
	if !strings.Contains(body, "Dismissed.") || !strings.Contains(body, "Nothing waits to be signed") {
		t.Fatalf("dismiss:\n%s", body)
	}

	// Live parts refresh; a signed-out page is told so instead of being
	// sent to sign in.
	dr, body = dsRequest(t, h, b, http.MethodGet, "/groups/"+group+"/live", "", nil)
	if dr.StatusCode != http.StatusOK || !strings.Contains(body, `id="group-machines"`) || strings.Contains(body, `id="group-access"`) {
		t.Fatalf("group live: %d\n%s", dr.StatusCode, body)
	}
	req, _ := http.NewRequest(http.MethodGet, h.URL+"/teams/"+project+"/live", nil)
	req.Header.Set("Datastar-Request", "true")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(raw), "You were signed out") {
		t.Fatalf("signed out live:\n%s", raw)
	}

	// Without scripts, the same forms still post and redirect.
	status, _, err = b.Post("/teams/"+project+"/members/set", csrf, url.Values{"login": {"mscno"}, "env": {"dev"}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("plain form: %d %v", status, err)
	}
	if changes, _ := a.Changes(ctx); len(changes) != 1 {
		t.Fatalf("plain form change: %+v", changes)
	}
}
