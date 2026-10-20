package team_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

const group = "acme/production"

type groupWorld struct {
	t     *testing.T
	w     *world
	st    *team.GroupState
	links []*envelope.Envelope
	key   [32]byte
}

func newGroupWorld(t *testing.T, w *world, by *acct) *groupWorld {
	t.Helper()
	k, priv, err := team.NewGroupKey(1)
	if err != nil {
		t.Fatal(err)
	}
	g := &groupWorld{t: t, w: w, st: team.NewGroup(group), key: priv}
	g.add(by, team.GroupInit, team.GroupInitBody{Creator: by.person(), Key: k})
	return g
}

func (g *groupWorld) link(by *acct, typ string, body any) *envelope.Envelope {
	g.t.Helper()
	g.w.now = g.w.now.Add(time.Minute)
	e, err := g.st.NewLink(typ, body, g.w.now, by.user, by.st.UKeyVersion, by.st.Seq, by.u.Sign)
	if err != nil {
		g.t.Fatal(err)
	}
	return e
}

func (g *groupWorld) apply(e *envelope.Envelope) error {
	next, err := g.st.Next(e, g.w.chains)
	if err != nil {
		return err
	}
	g.st, g.links = next, append(g.links, e)
	return nil
}

func (g *groupWorld) add(by *acct, typ string, body any) {
	g.t.Helper()
	if err := g.apply(g.link(by, typ, body)); err != nil {
		g.t.Fatalf("%s: %v", typ, err)
	}
}

// tokenLink signs a machine_add as an enrollment token.
func (g *groupWorld) tokenLink(tok *team.CredKey, typ string, body any, at time.Time) *envelope.Envelope {
	g.t.Helper()
	e, err := g.st.NewLink(typ, body, at, tok.ID, 0, 0, tok.Sign())
	if err != nil {
		g.t.Fatal(err)
	}
	return e
}

func (g *groupWorld) cred(kind, name string) (*team.CredKey, team.Credential) {
	g.t.Helper()
	k, c, err := team.NewCredKey("https://vault.example", group, g.st.Root(), kind, name, g.w.now)
	if err != nil {
		g.t.Fatal(err)
	}
	return k, c
}

func credRecipient(k *team.CredKey) (team.Recipient, [32]byte) {
	pub, priv := k.Keys()
	return team.Recipient{ID: k.ID, EncPub: pub}, priv
}

func TestGroupLifecycle(t *testing.T) { //nolint:gocyclo // one sequential story
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	g := newGroupWorld(t, w, alice)
	if !g.st.Admin(alice.user) || g.st.Key.Version != 1 || g.st.Root() == "" {
		t.Fatalf("init: %+v", g.st)
	}

	// An admin adds a machine, and seals the group key to it.
	web1, web1Cred := g.cred(team.KindMachine, "web-1")
	g.add(alice, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: web1Cred})
	to, priv := credRecipient(web1)
	kg, err := team.NewKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, to, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := team.OpenKeyGrant(kg, g.st, w.chains, to, priv)
	if err != nil || got != g.key {
		t.Fatalf("open key grant: %v", err)
	}

	// A token enrolls a machine by itself and hands it the group key.
	tok, tokCred := g.cred(team.KindToken, "autoscale")
	tokCred.Expires = w.now.Add(24 * time.Hour)
	g.add(alice, team.GroupTokenAdd, team.GroupTokenAddBody{Token: tokCred})
	web2, web2Cred := g.cred(team.KindMachine, "web-2")
	w.now = w.now.Add(time.Minute)
	if err := g.apply(g.tokenLink(tok, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: web2Cred}, w.now)); err != nil {
		t.Fatalf("token enroll: %v", err)
	}
	to2, priv2 := credRecipient(web2)
	kg2, err := team.NewKeyGrant(g.st, tok.ID, 0, tok.Sign(), to2, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := team.OpenKeyGrant(kg2, g.st, w.chains, to2, priv2); err != nil {
		t.Fatalf("token key grant: %v", err)
	}
	if c, _ := g.st.Cred(web2.ID); c.AddedBy != tok.ID {
		t.Fatalf("added by %s", c.AddedBy)
	}

	// A token can do nothing else, and nothing once it expired.
	_, other := g.cred(team.KindToken, "other")
	if err := g.apply(g.tokenLink(tok, team.GroupTokenAdd, team.GroupTokenAddBody{Token: other}, w.now)); err == nil {
		t.Fatal("a token added a token")
	}
	_, late := g.cred(team.KindMachine, "late")
	if err := g.apply(g.tokenLink(tok, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: late}, w.now.Add(25*time.Hour))); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token enrolled: %v", err)
	}

	// The project grants the group an environment; one grant to the group
	// key serves every machine.
	pub, envPriv := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "prod", PublicKey: pub}}})
	g.add(alice, team.GroupAccessAdd, team.GroupAccessBody{Project: project, Root: w.st.Root()})
	w.add(alice, team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"prod"}})
	holder := team.GroupHolder(group)
	if !w.st.HasAccess(holder, "prod") {
		t.Fatal("group has no access")
	}
	gpub, _ := chain.ParseKey32(g.st.Key.EncPub)
	gr, err := team.NewGrant(w.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, team.Recipient{ID: holder, Version: 1, EncPub: gpub}, map[string]string{"prod": envPriv}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, keys, err := team.Open(gr, w.st, w.chains, team.Recipient{ID: holder, Version: 1, EncPub: gpub}, got); err != nil || keys["prod"] != envPriv {
		t.Fatalf("open group grant: %v", err)
	}

	// A destroyed machine exposes nothing; a removed one exposes the group
	// key and the environments.
	g.add(alice, team.GroupRemove, team.GroupRemoveBody{ID: web2.ID, Destroyed: true})
	if len(g.st.KeyExposed) != 0 || len(team.GroupExposures(w.st, g.st)) != 0 {
		t.Fatal("destroyed machine exposed keys")
	}
	g.add(alice, team.GroupRemove, team.GroupRemoveBody{ID: web1.ID, Reason: "compromised"})
	if len(g.st.KeyExposed) != 1 || len(team.GroupExposures(w.st, g.st)["prod"]) != 1 {
		t.Fatalf("exposures: %+v %+v", g.st.KeyExposed, team.GroupExposures(w.st, g.st))
	}
	if _, err := team.OpenKeyGrant(kg, g.st, w.chains, to, priv); err == nil {
		t.Fatal("removed machine's key grant still opens")
	}

	// A new group key clears the group's exposure and makes old grants
	// stale; a new environment key clears the project's.
	k2, priv2k, _ := team.NewGroupKey(2)
	g.add(alice, team.GroupKeyRotate, team.GroupKeyRotateBody{Key: k2})
	if len(g.st.KeyExposed) != 0 {
		t.Fatal("rotation kept exposure")
	}
	if _, err := team.CheckKeyGrant(kg2, g.st, w.chains); !errors.Is(err, team.ErrStale) {
		t.Fatalf("old key grant: %v", err)
	}
	w.now = w.now.Add(time.Hour)
	pub2, _ := newKey(t)
	w.add(alice, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "prod", PublicKey: pub2}})
	if len(team.GroupExposures(w.st, g.st)) != 0 {
		t.Fatal("new env key kept group exposure")
	}
	_ = priv2k

	// Taking the group's access away exposes the environment.
	w.add(alice, team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: nil})
	if w.st.HasAccess(holder, "prod") || len(w.st.Envs["prod"].Exposed) != 1 {
		t.Fatalf("group access removal: %+v", w.st.Envs["prod"])
	}

	// Bob is not an admin until added; then the last admin cannot go.
	if err := g.apply(g.link(bob, team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: project})); err == nil {
		t.Fatal("non-admin changed the group")
	}
	g.add(alice, team.GroupAdminAdd, team.GroupAdminAddBody{Admin: bob.person(), Verified: team.VerifiedAccountKey})
	g.add(bob, team.GroupAdminRemove, team.GroupAdminRemoveBody{User: alice.user})
	if err := g.apply(g.link(bob, team.GroupAdminRemove, team.GroupAdminRemoveBody{User: bob.user})); err == nil {
		t.Fatal("removed the last admin")
	}

	// The whole chain verifies again from scratch.
	again, err := team.VerifyGroup(group, g.links, w.chains)
	if err != nil || again.Head() != g.st.Head() {
		t.Fatalf("reverify: %v", err)
	}
}

func TestGroupForgeries(t *testing.T) {
	alice, mallory := newAcct(t, 1, "alice"), newAcct(t, 3, "mallory")
	w := newWorld(t, alice, mallory)
	g := newGroupWorld(t, w, alice)

	// Someone outside the group cannot add a machine.
	_, c := g.cred(team.KindMachine, "evil")
	if err := g.apply(g.link(mallory, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c})); err == nil {
		t.Fatal("outsider added a machine")
	}
	// A machine cannot pose as a token.
	m, mc := g.cred(team.KindMachine, "web")
	g.add(alice, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: mc})
	if err := g.apply(g.tokenLink(m, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c}, w.now)); err == nil {
		t.Fatal("machine enrolled a machine")
	}
	// A token with an OIDC policy only enrolls machines with that policy.
	tok, tc := g.cred(team.KindToken, "ci")
	tc.OIDC = &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: "acme/store"}
	g.add(alice, team.GroupTokenAdd, team.GroupTokenAddBody{Token: tc})
	if err := g.apply(g.tokenLink(tok, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c}, w.now)); err == nil {
		t.Fatal("token enrolled a machine without its policy")
	}
	c.OIDC = tc.OIDC
	if err := g.apply(g.tokenLink(tok, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c}, w.now)); err != nil {
		t.Fatalf("token enroll with policy: %v", err)
	}
	// A removed token enrolls nothing.
	g.add(alice, team.GroupRemove, team.GroupRemoveBody{ID: tok.ID})
	_, c2 := g.cred(team.KindMachine, "after")
	c2.OIDC = tc.OIDC
	if err := g.apply(g.tokenLink(tok, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: c2}, w.now)); err == nil {
		t.Fatal("removed token enrolled a machine")
	}
	// A key grant whose box holds another key does not open.
	to, priv := credRecipient(m)
	_, wrong, _ := team.NewGroupKey(1)
	if _, err := team.NewKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, to, wrong, w.now); err == nil {
		t.Fatal("sealed a key that is not the group's")
	}
	kg, err := team.NewKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, to, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	// Mallory re-signs the grant: refused.
	var body team.KeyGrant
	if err := kg.Decode(&body); err != nil {
		t.Fatal(err)
	}
	body.From = mallory.user
	forged, _ := envelope.New(team.KindGroupKey, body, mallory.u.Sign)
	if _, err := team.OpenKeyGrant(forged, g.st, w.chains, to, priv); err == nil {
		t.Fatal("outsider's key grant opened")
	}
	// A link signed by a key the chain does not name is refused.
	_, stray, _ := ed25519.GenerateKey(nil)
	e, _ := g.st.NewLink(team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: project}, w.now, alice.user, alice.st.UKeyVersion, alice.st.Seq, stray)
	if err := g.apply(e); err == nil {
		t.Fatal("link with a stray key")
	}
}

func TestCredKeyAndJoinWords(t *testing.T) {
	k, c, err := team.NewCredKey("https://vault.example", group, strings.Repeat("a", 64), team.KindToken, "ci", t0)
	if err != nil {
		t.Fatal(err)
	}
	back, err := team.ParseCredKey(k.String())
	if err != nil || back.ID != k.ID || back.Kind() != team.KindToken || !back.Matches(c) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := team.ParseCredKey("esecg1_xx"); err == nil {
		t.Fatal("parsed garbage")
	}
	a := team.JoinWords(group, strings.Repeat("a", 64), c)
	b := team.JoinWords(group, strings.Repeat("b", 64), c)
	if a == b || len(strings.Split(a, "-")) != 6 {
		t.Fatalf("join words %q %q", a, b)
	}
}
