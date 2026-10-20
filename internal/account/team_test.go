package account_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/machine"
	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const project = "acme/store"

// postMachine sends a raw machine request and returns the status code.
func postMachine(t *testing.T, h *servertest.Harness, req wire.MachineKeysRequest) int {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(h.URL+"/v1/machines/keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func signed(key *team.MachineKey, nonce string) wire.MachineKeysRequest {
	req := wire.MachineKeysRequest{Machine: key.ID, Project: key.Project, Timestamp: time.Now().Unix(), Nonce: nonce}
	req.Sig = ed25519.Sign(key.Sign(), team.KeysMessage(req.Machine, req.Project, req.Timestamp, req.Nonce, ""))
	return req
}

func TestMachines(t *testing.T) { //nolint:gocyclo,maintidx // one sequential story
	oidc := servertest.NewFakeOIDC(t)
	h, a := setupWith(t, []server.Option{server.WithOIDCIssuer(oidc.URL, oidc.JWKS())})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	st, err := a.CreateTeam(ctx, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.EnvNames(); len(got) != 1 || got[0] != "dev" {
		t.Fatalf("shared environments: %v", got)
	}
	devPriv := strings.Repeat("ab", 32)

	// A machine without a policy fetches its keys with its key alone.
	key, err := a.CreateMachine(ctx, project, "ci", []string{"dev"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := team.ParseToken(key.Token())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := machine.Fetch(ctx, parsed, "")
	if err != nil {
		t.Fatal(err)
	}
	if keys.Projects[project]["dev"] != devPriv || keys.Name != "ci" {
		t.Fatalf("machine keys: %+v", keys.Projects)
	}
	devPub, _ := team.PublicHex(devPriv)
	env, err := keys.Environ(nil, "", nil)
	if err != nil || len(env) != 2 || env[0] != "ESEC_PRIVATE_KEY_DEV="+devPriv || env[1] != team.PubKeyEntry(devPub)+"="+devPriv {
		t.Fatalf("environ: %v %v", env, err)
	}
	if _, err := keys.Environ(nil, "", []string{"prod"}); err == nil {
		t.Fatal("a machine was given an environment it cannot read")
	}

	// Requests are signed and single-use.
	req := signed(key, "nonce-0123456789abcdef")
	if code := postMachine(t, h, req); code != http.StatusOK {
		t.Fatalf("signed request: %d", code)
	}
	if code := postMachine(t, h, req); code != http.StatusUnauthorized {
		t.Fatalf("replayed request: %d", code)
	}
	bad := signed(key, "nonce-1123456789abcdef")
	bad.Sig[0] ^= 1
	if code := postMachine(t, h, bad); code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", code)
	}
	other := signed(key, "nonce-2123456789abcdef")
	other.Project = "acme/other"
	if code := postMachine(t, h, other); code != http.StatusUnauthorized {
		t.Fatalf("wrong project: %d", code)
	}

	// The machine refuses a project chain that does not start at its root.
	forged := *parsed
	forged.Root = strings.Repeat("0", 64)
	if _, err := machine.Fetch(ctx, &forged, ""); err == nil || !strings.Contains(err.Error(), "does not start") {
		t.Fatalf("forged root: %v", err)
	}

	// A machine bound to GitHub Actions needs a matching OIDC token.
	policy := &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: "acme/store", Refs: []string{"refs/heads/main"}}
	deploy, err := a.CreateMachine(ctx, project, "deploy", []string{"dev"}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.Fetch(ctx, deploy, ""); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("no token: %v", err)
	}
	claims := func(extra map[string]any) map[string]any {
		c := map[string]any{"aud": h.URL, "repository": "acme/store", "repository_id": "42", "ref": "refs/heads/main", "run_id": "7", "actor": "mscno"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	if _, err := machine.Fetch(ctx, deploy, oidc.Token(claims(nil))); err != nil {
		t.Fatalf("matching token: %v", err)
	}
	for name, c := range map[string]map[string]any{
		"another repository": claims(map[string]any{"repository": "evil/store"}),
		"another branch":     claims(map[string]any{"ref": "refs/heads/feature"}),
		"another audience":   claims(map[string]any{"aud": "https://elsewhere.example"}),
		"expired":            claims(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"another issuer":     claims(map[string]any{"iss": "https://evil.example"}),
	} {
		if _, err := machine.Fetch(ctx, deploy, oidc.Token(c)); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	// A job's token request, as in GitHub Actions.
	for _, kv := range oidc.JobEnv() {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	oidc.SetClaims(map[string]any{"repository": "acme/store", "ref": "refs/heads/main"})
	tok, err := machine.GitHubToken(ctx, h.URL)
	if err != nil || tok == "" {
		t.Fatalf("job token: %v", err)
	}
	if _, err := machine.Fetch(ctx, deploy, tok); err != nil {
		t.Fatalf("job token: %v", err)
	}

	// The project page shows the machines and their use; the refused
	// attempts are in its log.
	status, page, err := h.Browser("mscno").Get("/teams/" + project)
	if err != nil || status != http.StatusOK {
		t.Fatalf("project page: %d %v", status, err)
	}
	for _, want := range []string{"deploy", "GitHub Actions in acme/store on refs/heads/main", "Machine fetched its keys", "Machine refused", "dev · held"} {
		if !strings.Contains(page, want) {
			t.Fatalf("project page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, devPriv) {
		t.Fatal("the project page shows a private key")
	}

	// Removing a machine stops it at once and asks for a new dev key.
	if _, err := a.RemoveMachine(ctx, project, "ci", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.Fetch(ctx, parsed, ""); err == nil {
		t.Fatal("a removed machine still got keys")
	}
	v, err := a.Team(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	if rot := v.State.Rotations(); len(rot) != 1 || rot[0].Name != "dev" || rot[0].Exposed[0].Name != "ci" {
		t.Fatalf("rotations: %+v", rot)
	}

	// A new dev key, published, clears the to-do; the remaining machine is
	// sent the new key and keeps working.
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	entries, err := ks.Read(project)
	if err != nil {
		t.Fatal(err)
	}
	entries[team.EnvKey("dev")] = priv
	if err := ks.Write(project, entries, true); err != nil {
		t.Fatal(err)
	}
	res, err := a.PublishEnv(ctx, project, "dev", "rotated")
	if err != nil {
		t.Fatal(err)
	}
	if res.PublicKey != pub || len(res.Sent) != 1 || res.Sent[0] != "deploy" {
		t.Fatalf("publish: %+v", res)
	}
	keys, err = machine.Fetch(ctx, deploy, tok)
	if err != nil || keys.Projects[project]["dev"] != priv {
		t.Fatalf("machine after rotation: %v", err)
	}
	v, err = a.Team(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.State.Rotations()) != 0 {
		t.Fatalf("rotation to-do left: %+v", v.State.Rotations())
	}

	// A team sync finds nothing left to do.
	sync, err := a.TeamSync(ctx, account.TeamSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sync.Sent)+len(sync.Imported)+len(sync.Unsent) != 0 {
		t.Fatalf("team sync: %+v", sync)
	}
}

func TestTeamPinDetectsRollback(t *testing.T) {
	h, a := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateMachine(ctx, project, "ci", []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	// The server drops the last link: a device that saw it refuses.
	exec(t, h, `DELETE FROM project_links WHERE project = ? AND seq = 2`, project)
	if _, err := a.Team(ctx, project); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("rolled-back project chain: %v", err)
	}
}

// TestServerRejectsForgedProjectCommits sends commits the client would never
// make, signed with the account's real device key, and checks that the
// server's own verification refuses them.
func TestServerRejectsForgedProjectCommits(t *testing.T) { //nolint:gocyclo // one sequential story
	h, a := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.CreateTeam(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(a.KR)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := a.Client.ProjectChain(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	chains := func(user string) (*chain.State, error) { return chain.Verify(user, pc.Chains[user]) }
	st, err := team.Verify(project, pc.Links, chains)
	if err != nil {
		t.Fatal(err)
	}
	me, version := a.State.User, a.State.Chain.UKeyVersion
	_, stranger, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	commit := func(links, grants []*envelope.Envelope) error {
		_, err := a.Client.ProjectCommit(ctx, project, &wire.ProjectCommit{Links: links, Grants: grants})
		return err
	}
	link := func(typ string, body any, ver uint64, key ed25519.PrivateKey) *envelope.Envelope {
		e, err := st.NewLink(typ, body, now, me, ver, a.State.Chain.Seq, key)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	newEnv := team.EnvSetBody{Env: team.Env{Name: "qa", PublicKey: strings.Repeat("cd", 32)}}
	for name, e := range map[string]*envelope.Envelope{
		"a stranger's signature":   link(team.TypeEnvSet, newEnv, version, stranger),
		"an unknown key version":   link(team.TypeEnvSet, newEnv, version+5, id.Sign),
		"a member with no account": link(team.TypeMemberAdd, team.MemberAddBody{Member: team.Person{User: "gh:999", Login: "ghost", Root: strings.Repeat("ab", 32)}, Envs: []string{"dev"}, Verified: team.VerifiedAccountKey}, version, id.Sign),
	} {
		if err := commit([]*envelope.Envelope{e}, nil); !client.IsCode(err, wire.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A second init for the same project.
	again, err := team.New(project).NewLink(team.TypeInit, team.InitBody{Creator: team.Person{User: me, Login: "mscno", Root: st.Members[me].Root}}, now, me, version, a.State.Chain.Seq, id.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit([]*envelope.Envelope{again}, nil); !client.IsCode(err, wire.ErrConflict) {
		t.Errorf("second init: %v", err)
	}
	// A grant claiming to be from someone else, and one to a stale key.
	pub, _ := chain.ParseKey32(strings.Repeat("ef", 32))
	g, err := team.NewGrant(st, "gh:4242", version, id.Sign, team.Recipient{ID: me, Version: version, EncPub: pub}, map[string]string{"dev": strings.Repeat("ab", 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(nil, []*envelope.Envelope{g}); !client.IsCode(err, wire.ErrInvalidRequest) {
		t.Errorf("grant from someone else: %v", err)
	}
	g, err = team.NewGrant(st, me, version, id.Sign, team.Recipient{ID: me, Version: version, EncPub: pub}, map[string]string{"dev": strings.Repeat("ab", 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(nil, []*envelope.Envelope{g}); !client.IsCode(err, wire.ErrConflict) {
		t.Errorf("grant to a key that is not the recipient's: %v", err)
	}
	// Nothing of it was stored.
	var n int
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM project_links`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored links: %d %v", n, err)
	}
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM project_grants`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stored grants: %d %v", n, err)
	}
	// A valid change this device did not make, as from another device of
	// the account (or a revoked one with the old key), is pointed out.
	if err := commit([]*envelope.Envelope{link(team.TypeEnvSet, newEnv, version, id.Sign)}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := a.TeamSync(ctx, account.TeamSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Elsewhere) != 1 || !strings.Contains(res.Elsewhere[0], "set a new key for qa") {
		t.Fatalf("changes made elsewhere: %v", res.Elsewhere)
	}
}
