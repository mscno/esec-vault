package team_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/kms"
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

// People in a group: an admin adds them, the group key is sealed to their
// user key, they may leave by themselves but change nothing else, and a
// member who leaves exposes the group key and the environments it read.
func TestGroupMembers(t *testing.T) { //nolint:gocyclo // one sequential story
	alice, bob, carol := newAcct(t, 1, "alice"), newAcct(t, 2, "bob"), newAcct(t, 3, "carol")
	w := newWorld(t, alice, bob, carol)
	g := newGroupWorld(t, w, alice)
	pub, envPriv := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "prod", PublicKey: pub}}})
	g.add(alice, team.GroupAccessAdd, team.GroupAccessBody{Project: project, Root: w.st.Root()})
	w.add(alice, team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"prod"}})

	// Only an admin adds a member, and only once.
	if err := g.apply(g.link(bob, team.GroupMemberAdd, team.GroupMemberAddBody{Member: bob.person(), Verified: team.VerifiedAccountKey})); err == nil {
		t.Fatal("a non-admin added themselves")
	}
	g.add(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: bob.person(), Verified: team.VerifiedGitHubSSH})
	if !g.st.Member(bob.user) || g.st.Admin(bob.user) || !g.st.HoldsKey(bob.user) || len(g.st.KeyHolders()) != 2 {
		t.Fatalf("member: %+v", g.st.Members)
	}
	if err := g.apply(g.link(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: bob.person(), Verified: team.VerifiedGitHubSSH})); err == nil {
		t.Fatal("added a member twice")
	}
	if err := g.apply(g.link(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: alice.person(), Verified: team.VerifiedGitHubSSH})); err == nil {
		t.Fatal("added an admin as a member")
	}
	// A member added on the web needs a delegate's signature.
	if err := g.apply(g.link(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: carol.person(), Verified: team.VerifiedWeb})); err == nil {
		t.Fatal("a device added a member checked on the web")
	}

	// The group key reaches the member, and through it the project's keys.
	kg, err := team.NewKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, bob.recipient(), g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	gpriv, err := team.OpenKeyGrant(kg, g.st, w.chains, bob.recipient(), bob.u.Private)
	if err != nil || gpriv != g.key {
		t.Fatalf("member opens the group key: %v", err)
	}
	gpub, _ := chain.ParseKey32(g.st.Key.EncPub)
	holder := team.Recipient{ID: team.GroupHolder(group), Version: g.st.Key.Version, EncPub: gpub}
	gr, err := team.NewGrant(w.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, holder, map[string]string{"prod": envPriv}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, keys, err := team.Open(gr, w.st, w.chains, holder, gpriv); err != nil || keys["prod"] != envPriv {
		t.Fatalf("member opens the project's keys: %v", err)
	}

	// A member changes nothing but their own membership.
	if err := g.apply(g.link(bob, team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: project})); err == nil {
		t.Fatal("a member changed the group")
	}
	g.add(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: carol.person(), Verified: team.VerifiedAccountKey})
	if err := g.apply(g.link(bob, team.GroupMemberRemove, team.GroupMemberRemoveBody{User: carol.user})); err == nil {
		t.Fatal("a member removed another member")
	}
	g.add(bob, team.GroupMemberRemove, team.GroupMemberRemoveBody{User: bob.user, Reason: "moved teams"})
	if g.st.HoldsKey(bob.user) || len(g.st.KeyExposed) != 1 || g.st.KeyExposed[0].Reason != "member left" {
		t.Fatalf("leave: %+v", g.st.KeyExposed)
	}
	if ex := team.GroupExposures(w.st, g.st)["prod"]; len(ex) != 1 || ex[0].Holder != bob.user {
		t.Fatalf("project exposure: %+v", ex)
	}
	if _, err := team.CheckKeyGrant(kg, g.st, w.chains); !errors.Is(err, team.ErrStale) {
		t.Fatalf("a former member's key grant: %v", err)
	}
	// Once gone, they sign nothing, not even their own removal.
	if err := g.apply(g.link(bob, team.GroupMemberRemove, team.GroupMemberRemoveBody{User: bob.user})); err == nil {
		t.Fatal("a former member signed a link")
	}
	g.add(alice, team.GroupMemberRemove, team.GroupMemberRemoveBody{User: carol.user})
	if g.st.KeyExposed[1].Reason != "member removed" {
		t.Fatalf("removal reason: %+v", g.st.KeyExposed)
	}
	// They may come back.
	g.add(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: bob.person(), Verified: team.VerifiedAccountKey})

	again, err := team.VerifyGroup(group, g.links, w.chains)
	if err != nil || again.Head() != g.st.Head() || !again.Member(bob.user) {
		t.Fatalf("reverify: %v", err)
	}
}

// A member made an admin is an admin only: removing them as an admin takes
// them out of the group, and the group key is not sealed to them again.
func TestGroupMemberPromoted(t *testing.T) {
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	g := newGroupWorld(t, w, alice)
	g.add(alice, team.GroupMemberAdd, team.GroupMemberAddBody{Member: bob.person(), Verified: team.VerifiedAccountKey})
	g.add(alice, team.GroupAdminAdd, team.GroupAdminAddBody{Admin: bob.person(), Verified: team.VerifiedAccountKey})
	if !g.st.Admin(bob.user) || g.st.Member(bob.user) || len(g.st.KeyHolders()) != 2 {
		t.Fatalf("promoted: admin %v member %v", g.st.Admin(bob.user), g.st.Member(bob.user))
	}
	g.add(alice, team.GroupAdminRemove, team.GroupAdminRemoveBody{User: bob.user})
	if g.st.HoldsKey(bob.user) {
		t.Fatal("a former admin who was a member still holds the group key")
	}
}

// A workload holds no secret: its group key is wrapped with a KMS key the
// chain names, and it must have an OIDC policy.
func TestGroupWorkload(t *testing.T) {
	alice := newAcct(t, 1, "alice")
	w := newWorld(t, alice)
	g := newGroupWorld(t, w, alice)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	key := &kms.Key{Provider: "gcp", Name: "projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/workloads/cryptoKeyVersions/1", Audience: "projects/123456789/locations/global/workloadIdentityPools/esec-fly/providers/fly-acme", PublicKey: base64.StdEncoding.EncodeToString(der)}
	policy := &team.OIDCPolicy{Provider: team.ProviderFly, FlyOrg: "acme", FlyApps: []string{"store"}}
	wl := team.Credential{ID: "w_abcdefghij", Name: "store", EncPub: key.Fingerprint(), KMS: key, OIDC: policy, Created: w.now}

	noPolicy := wl
	noPolicy.OIDC = nil
	if err := g.apply(g.link(alice, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: noPolicy})); err == nil {
		t.Fatal("a workload without an OIDC policy")
	}
	wrongFP := wl
	wrongFP.EncPub = strings.Repeat("ab", 32)
	if err := g.apply(g.link(alice, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: wrongFP})); err == nil {
		t.Fatal("a workload whose key is not its KMS key")
	}
	g.add(alice, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: wl})
	c, ok := g.st.Cred(wl.ID)
	if !ok || c.Kind != team.KindWorkload {
		t.Fatalf("workload: %+v", c)
	}
	// A second app on the same KMS key.
	wl2 := wl
	wl2.ID, wl2.Name, wl2.OIDC = "w_bcdefghijk", "web", &team.OIDCPolicy{Provider: team.ProviderFly, FlyOrg: "acme", FlyApps: []string{"web"}}
	g.add(alice, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: wl2})

	kg, err := team.NewWorkloadKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, c, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	unwrap := func(box []byte) ([]byte, error) { return rsa.DecryptOAEP(sha256.New(), nil, priv, box, nil) }
	got, err := team.OpenWorkloadKeyGrant(kg, g.st, w.chains, wl.ID, unwrap)
	if err != nil || got != g.key {
		t.Fatalf("open: %v", err)
	}
	// It opens for that workload only, and a sealed grant cannot pose as
	// one.
	if _, err := team.OpenWorkloadKeyGrant(kg, g.st, w.chains, wl2.ID, unwrap); err == nil {
		t.Fatal("another workload opened the grant")
	}
	var body team.KeyGrant
	_ = kg.Decode(&body)
	body.Seal = ""
	forged, _ := envelope.New(team.KindGroupKey, body, alice.u.Sign)
	if _, err := team.CheckKeyGrant(forged, g.st, w.chains); err == nil {
		t.Fatal("a workload's grant without the KMS seal")
	}
	// Removing it exposes the group key, like a machine.
	g.add(alice, team.GroupRemove, team.GroupRemoveBody{ID: wl.ID})
	if len(g.st.KeyExposed) != 1 {
		t.Fatalf("exposures: %+v", g.st.KeyExposed)
	}
	if again, err := team.VerifyGroup(group, g.links, w.chains); err != nil || again.Head() != g.st.Head() {
		t.Fatalf("reverify: %v", err)
	}
}

// A workload moves to a new KMS key in place: its id stays, grants wrapped
// with the old key stop counting.
func TestGroupWorkloadRekey(t *testing.T) {
	alice := newAcct(t, 1, "alice")
	w := newWorld(t, alice)
	g := newGroupWorld(t, w, alice)
	mk := func(version string) (*kms.Key, *rsa.PrivateKey) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		return &kms.Key{Provider: "gcp", Name: "projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/workloads/cryptoKeyVersions/" + version, Audience: "projects/123456789/locations/global/workloadIdentityPools/esec-fly/providers/fly-acme", PublicKey: base64.StdEncoding.EncodeToString(der)}, priv
	}
	k1, _ := mk("1")
	k2, p2 := mk("2")
	wl := team.Credential{ID: "w_abcdefghij", Name: "store", EncPub: k1.Fingerprint(), KMS: k1, OIDC: &team.OIDCPolicy{Provider: team.ProviderFly, FlyOrg: "acme"}, Created: w.now}
	g.add(alice, team.GroupWorkloadAdd, team.GroupWorkloadAddBody{Workload: wl})
	c, _ := g.st.Cred(wl.ID)
	old, err := team.NewWorkloadKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, c, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.apply(g.link(alice, team.GroupWorkloadRekey, team.GroupWorkloadRekeyBody{ID: wl.ID, KMS: *k1})); err == nil {
		t.Fatal("rekeyed to the same key")
	}
	g.add(alice, team.GroupWorkloadRekey, team.GroupWorkloadRekeyBody{ID: wl.ID, KMS: *k2})
	if _, err := team.CheckKeyGrant(old, g.st, w.chains); err == nil {
		t.Fatal("a grant wrapped with the old key still counts")
	}
	c, _ = g.st.Cred(wl.ID)
	kg, err := team.NewWorkloadKeyGrant(g.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, c, g.key, w.now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := team.OpenWorkloadKeyGrant(kg, g.st, w.chains, wl.ID, func(box []byte) ([]byte, error) { return rsa.DecryptOAEP(sha256.New(), nil, p2, box, nil) })
	if err != nil || got != g.key {
		t.Fatalf("open with the new key: %v", err)
	}
}
