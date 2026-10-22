package team_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/team"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const project = "acme/store"

// acct is a user with a verified user chain.
type acct struct {
	t     *testing.T
	user  string
	login string
	u     *identity.Identity
	st    *chain.State
}

func newAcct(t *testing.T, id int, login string) *acct {
	t.Helper()
	u, err := identity.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	a := &acct{t: t, user: fmt.Sprintf("gh:%d", id), login: login, u: u}
	a.st = chain.New(a.user)
	var master [32]byte
	if _, err := rand.Read(master[:]); err != nil {
		t.Fatal(err)
	}
	_, masterSign, _ := ed25519.GenerateKey(rand.Reader)
	a.add(chain.TypeInit, chain.NewInitBody(u.Public, u.SignPublic(), master, masterSign), t0, u.Sign)
	k, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	d := chain.Device{ID: fmt.Sprintf("d_dev%08d", id), Name: "laptop", Platform: "darwin/arm64", EncPub: k.EncPubHex(), SignPub: k.SignPubHex(), Created: t0}
	proof, err := k.Proof(a.user, d)
	if err != nil {
		t.Fatal(err)
	}
	a.add(chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *proof, Method: chain.MethodFirst}, t0, u.Sign)
	return a
}

func (a *acct) add(typ string, body any, at time.Time, keys ...ed25519.PrivateKey) {
	a.t.Helper()
	e, err := a.st.NewLink(typ, body, at, keys...)
	if err != nil {
		a.t.Fatal(err)
	}
	if a.st, err = a.st.Next(e); err != nil {
		a.t.Fatalf("%s: %v", typ, err)
	}
}

// rotate replaces the user key at time at and returns the old key.
func (a *acct) rotate(at time.Time) *identity.Identity {
	a.t.Helper()
	next, err := identity.NewRandom()
	if err != nil {
		a.t.Fatal(err)
	}
	keep := make([]string, 0, len(a.st.ActiveDevices()))
	for _, d := range a.st.ActiveDevices() {
		keep = append(keep, d.ID)
	}
	old := a.u
	a.add(chain.TypeUKeyRotate, chain.UKeyRotateBody{EncPub: hex.EncodeToString(next.Public[:]), SignPub: hex.EncodeToString(next.SignPublic()), Devices: keep}, at, old.Sign, next.Sign)
	a.u = next
	return old
}

func (a *acct) person() team.Person {
	return team.Person{User: a.user, Login: a.login, Root: a.st.Root()}
}

func (a *acct) recipient() team.Recipient {
	return team.Recipient{ID: a.user, Version: a.st.UKeyVersion, EncPub: a.u.Public}
}

type world struct {
	t     *testing.T
	accts map[string]*acct
	st    *team.State
	links []*envelope.Envelope
	now   time.Time
}

func (w *world) chains(user string) (*chain.State, error) {
	a, ok := w.accts[user]
	if !ok {
		return nil, errors.New("no such account")
	}
	return a.st, nil
}

func newWorld(t *testing.T, accts ...*acct) *world {
	w := &world{t: t, accts: map[string]*acct{}, st: team.New(project), now: t0.Add(time.Hour)}
	for _, a := range accts {
		w.accts[a.user] = a
	}
	return w
}

func (w *world) link(by *acct, typ string, body any) *envelope.Envelope {
	w.t.Helper()
	w.now = w.now.Add(time.Minute)
	e, err := w.st.NewLink(typ, body, w.now, by.user, by.st.UKeyVersion, by.st.Seq, by.u.Sign)
	if err != nil {
		w.t.Fatal(err)
	}
	return e
}

func (w *world) add(by *acct, typ string, body any) {
	w.t.Helper()
	e := w.link(by, typ, body)
	next, err := w.st.Next(e, w.chains)
	if err != nil {
		w.t.Fatalf("%s: %v", typ, err)
	}
	w.st, w.links = next, append(w.links, e)
}

func (w *world) reject(want string, by *acct, typ string, body any) {
	w.t.Helper()
	e := w.link(by, typ, body)
	if _, err := w.st.Next(e, w.chains); err == nil || !strings.Contains(err.Error(), want) {
		w.t.Fatalf("%s: expected error containing %q, got %v", typ, want, err)
	}
}

func newKey(t *testing.T) (pub, priv string) {
	t.Helper()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestProjectLifecycle(t *testing.T) { //nolint:gocyclo // one sequential story
	owner, alice, bob := newAcct(t, 1, "owner"), newAcct(t, 2, "alice"), newAcct(t, 3, "bob")
	w := newWorld(t, owner, alice, bob)
	devPub, _ := newKey(t)
	prodPub, _ := newKey(t)
	w.add(owner, team.TypeInit, team.InitBody{Creator: owner.person(), Envs: []team.Env{{Name: "dev", PublicKey: devPub}, {Name: "prod", PublicKey: prodPub}}})
	if !w.st.Admin(owner.user) || len(w.st.Envs) != 2 {
		t.Fatalf("after init: %+v", w.st)
	}

	// Non-admins cannot change anything; admins can.
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: alice.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})
	w.reject("only an admin", alice, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})
	w.reject("unknown environment", owner, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"qa"}, Verified: team.VerifiedGitHubSSH})
	w.reject("sorted", owner, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"prod", "dev"}, Verified: team.VerifiedGitHubSSH})
	w.reject("admins read every", owner, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Admin: true, Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"dev", "prod"}, Verified: team.VerifiedAccountKey})
	if !w.st.HasAccess(bob.user, "prod") || w.st.HasAccess(alice.user, "prod") || !w.st.HasAccess(owner.user, "prod") {
		t.Fatal("access is wrong")
	}

	// The last admin can neither leave nor be demoted.
	w.reject("last admin", owner, team.TypeMemberRemove, team.MemberRemoveBody{User: owner.user})
	w.reject("at least one admin", owner, team.TypeMemberUpdate, team.MemberUpdateBody{User: owner.user, Envs: []string{"dev"}})

	// Removing bob leaves dev and prod exposed; a new prod key clears prod.
	w.add(owner, team.TypeMemberRemove, team.MemberRemoveBody{User: bob.user, Reason: "left the company"})
	if rot := w.st.Rotations(); len(rot) != 2 || rot[0].Exposed[0].Name != "bob" {
		t.Fatalf("rotations after removal: %+v", rot)
	}
	newProd, _ := newKey(t)
	w.add(owner, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "prod", PublicKey: newProd}, Reason: "bob left"})
	if rot := w.st.Rotations(); len(rot) != 1 || rot[0].Name != "dev" {
		t.Fatalf("rotations after the new prod key: %+v", rot)
	}
	if got := w.st.Envs["prod"].Retired; len(got) != 1 || got[0] != prodPub {
		t.Fatalf("retired prod keys: %v", got)
	}
	// A key can never come back.
	w.reject("already used", owner, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "prod", PublicKey: prodPub}})
	// A removed member signs nothing.
	w.reject("not a member", bob, team.TypeMemberRemove, team.MemberRemoveBody{User: alice.user})

	// A member may leave on their own.
	w.add(alice, team.TypeMemberRemove, team.MemberRemoveBody{User: alice.user})
	if _, ok := w.st.Member(alice.user); ok {
		t.Fatal("alice is still a member")
	}

	// Machines.
	k, m, err := team.NewMachineKey("https://vault.example.com", project, w.st.Root(), "ci", w.now)
	if err != nil {
		t.Fatal(err)
	}
	w.reject("at least one environment", owner, team.TypeMachineAdd, team.MachineAddBody{Machine: m})
	w.add(owner, team.TypeMachineAdd, team.MachineAddBody{Machine: m, Envs: []string{"prod"}, OIDC: &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: "acme/store", Refs: []string{"refs/heads/main"}}})
	if !k.Matches(m) || !w.st.HasAccess(m.ID, "prod") || w.st.HasAccess(m.ID, "dev") {
		t.Fatal("machine access is wrong")
	}
	parsed, err := team.ParseToken(k.Token())
	if err != nil || parsed.ID != m.ID || parsed.Root != w.st.Root() {
		t.Fatalf("token round trip: %v", err)
	}
	w.add(owner, team.TypeMachineRemove, team.MachineRemoveBody{ID: m.ID})
	if rot := w.st.Rotations(); len(rot) != 2 {
		t.Fatalf("a removed machine exposes its keys: %+v", rot)
	}

	// The whole chain verifies again from scratch, and a pin detects forks.
	again, err := team.Verify(project, w.links, w.chains)
	if err != nil || again.Head() != w.st.Head() {
		t.Fatalf("re-verify: %v", err)
	}
	if err := again.CheckPin(3, w.st.Hashes[2]); err != nil {
		t.Fatal(err)
	}
	if err := again.CheckPin(3, strings.Repeat("0", 64)); !errors.Is(err, team.ErrRollback) {
		t.Fatalf("fork not detected: %v", err)
	}
	short, _ := team.Verify(project, w.links[:2], w.chains)
	if err := short.CheckPin(w.st.Seq, w.st.Head()); !errors.Is(err, team.ErrRollback) {
		t.Fatalf("rollback not detected: %v", err)
	}
}

func TestForgedLinksAreRejected(t *testing.T) {
	owner, alice, mallory := newAcct(t, 1, "owner"), newAcct(t, 2, "alice"), newAcct(t, 6, "mallory")
	w := newWorld(t, owner, alice, mallory)
	devPub, _ := newKey(t)
	w.add(owner, team.TypeInit, team.InitBody{Creator: owner.person(), Envs: []team.Env{{Name: "dev", PublicKey: devPub}}})

	// Signed by a key that is not the signer's.
	e, err := w.st.NewLink(team.TypeMemberAdd, team.MemberAddBody{Member: mallory.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH}, w.now.Add(time.Minute), owner.user, 1, 2, mallory.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.st.Next(e, w.chains); err == nil {
		t.Fatal("accepted a link signed with someone else's key")
	}
	// Another project's link.
	other := team.New("acme/other")
	e, _ = other.NewLink(team.TypeInit, team.InitBody{Creator: owner.person()}, w.now, owner.user, 1, 2, owner.u.Sign)
	if _, err := team.Verify(project, []*envelope.Envelope{e}, w.chains); err == nil {
		t.Fatal("accepted another project's link")
	}
	// An init link for someone else.
	e, _ = team.New(project).NewLink(team.TypeInit, team.InitBody{Creator: alice.person()}, w.now, owner.user, 1, 2, owner.u.Sign)
	if _, err := team.Verify(project, []*envelope.Envelope{e}, w.chains); err == nil {
		t.Fatal("accepted an init link signed by someone other than its creator")
	}
	// A creator whose recorded account root is not their account.
	fake := owner.person()
	fake.Root = alice.st.Root()
	e, _ = team.New(project).NewLink(team.TypeInit, team.InitBody{Creator: fake}, w.now, owner.user, 1, 2, owner.u.Sign)
	if _, err := team.Verify(project, []*envelope.Envelope{e}, w.chains); err == nil {
		t.Fatal("accepted a creator with a foreign account root")
	}

	// After the owner rotates their user key, links made before still
	// verify, whatever the clocks said: a rotation dated before them changes
	// nothing.
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: alice.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})
	oldSeq := owner.st.Seq
	oldKey := owner.rotate(w.now.Add(-2 * time.Hour))
	if _, err := team.Verify(project, w.links, w.chains); err != nil {
		t.Fatalf("links made before the rotation: %v", err)
	}
	// The old key cannot sign as of a position after the rotation.
	e, _ = w.st.NewLink(team.TypeMemberAdd, team.MemberAddBody{Member: mallory.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH}, w.now.Add(time.Minute), owner.user, 1, owner.st.Seq, oldKey.Sign)
	if _, err := w.st.Next(e, w.chains); err == nil || !strings.Contains(err.Error(), "not current") {
		t.Fatalf("accepted the old key at a later position: %v", err)
	}
	// Nor claim the new version with the old key.
	e, _ = w.st.NewLink(team.TypeMemberAdd, team.MemberAddBody{Member: mallory.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH}, w.now.Add(time.Minute), owner.user, 2, owner.st.Seq, oldKey.Sign)
	if _, err := w.st.Next(e, w.chains); err == nil {
		t.Fatal("accepted the old key for the new version")
	}
	// The new key works; after that, the old key cannot sign as of the
	// earlier position either.
	w.add(owner, team.TypeMemberUpdate, team.MemberUpdateBody{User: alice.user, Admin: true})
	e, _ = w.st.NewLink(team.TypeMemberAdd, team.MemberAddBody{Member: mallory.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH}, w.now.Add(time.Minute), owner.user, 1, oldSeq, oldKey.Sign)
	if _, err := w.st.Next(e, w.chains); err == nil || !strings.Contains(err.Error(), "earlier position") {
		t.Fatalf("accepted the old key at an earlier position: %v", err)
	}
}

func TestGrants(t *testing.T) {
	owner, alice, bob := newAcct(t, 1, "owner"), newAcct(t, 2, "alice"), newAcct(t, 3, "bob")
	w := newWorld(t, owner, alice, bob)
	devPub, devPriv := newKey(t)
	prodPub, prodPriv := newKey(t)
	w.add(owner, team.TypeInit, team.InitBody{Creator: owner.person(), Envs: []team.Env{{Name: "dev", PublicKey: devPub}, {Name: "prod", PublicKey: prodPub}}})
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: alice.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH})

	grant := func(by *acct, to team.Recipient, keys map[string]string) *envelope.Envelope {
		t.Helper()
		g, err := team.NewGrant(w.st, by.user, by.st.UKeyVersion, by.u.Sign, to, keys, w.now)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := grant(owner, alice.recipient(), map[string]string{"dev": devPriv})
	_, keys, err := team.Open(g, w.st, w.chains, alice.recipient(), alice.u.Private)
	if err != nil || keys["dev"] != devPriv {
		t.Fatalf("open: %v", err)
	}
	// Only the recipient opens it.
	if _, _, err := team.Open(g, w.st, w.chains, bob.recipient(), bob.u.Private); err == nil {
		t.Fatal("bob opened alice's grant")
	}
	// An admin cannot grant an environment the recipient may not read, and
	// a member who is not an admin cannot grant at all.
	if _, err := team.NewGrant(w.st, owner.user, 1, owner.u.Sign, alice.recipient(), map[string]string{"prod": prodPriv}, w.now); err == nil {
		t.Fatal("granted prod to a dev-only member")
	}
	bad := grant(owner, alice.recipient(), map[string]string{"dev": devPriv})
	forged, err := team.PeekGrant(bad)
	if err != nil {
		t.Fatal(err)
	}
	forged.From = bob.user
	env, _ := envelope.New(team.KindGrant, forged, bob.u.Sign)
	if _, _, err := team.Open(env, w.st, w.chains, alice.recipient(), alice.u.Private); err == nil {
		t.Fatal("accepted a grant from a member who is not an admin")
	}
	// A wrong key under the right public key is refused when opened.
	if _, err := team.NewGrant(w.st, owner.user, 1, owner.u.Sign, alice.recipient(), map[string]string{"dev": prodPriv}, w.now); err == nil {
		t.Fatal("granted a key that is not the environment's")
	}

	// After a new dev key the old grant is stale.
	newDev, newDevPriv := newKey(t)
	w.add(owner, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "dev", PublicKey: newDev}})
	if _, _, err := team.Open(g, w.st, w.chains, alice.recipient(), alice.u.Private); !errors.Is(err, team.ErrStale) {
		t.Fatalf("old grant after a new key: %v", err)
	}
	// After alice rotates her user key, a grant sealed to the old one is
	// stale too: her devices no longer hold that key.
	g = grant(owner, alice.recipient(), map[string]string{"dev": newDevPriv})
	alice.rotate(w.now)
	if _, _, err := team.Open(g, w.st, w.chains, alice.recipient(), alice.u.Private); !errors.Is(err, team.ErrStale) {
		t.Fatalf("grant to a replaced user key: %v", err)
	}
	if _, err := team.NewGrant(w.st, owner.user, 1, owner.u.Sign, alice.recipient(), map[string]string{}, w.now); err == nil {
		t.Fatal("a grant without keys was made")
	}
}

func TestOIDCPolicy(t *testing.T) {
	p := &team.OIDCPolicy{Provider: team.ProviderGitHub, Repository: "acme/store", RepositoryID: 42, Refs: []string{"refs/heads/main", "refs/tags/v*"}, Environments: []string{"production"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	ok := team.Claims{Repository: "ACME/store", RepositoryID: "42", Ref: "refs/tags/v1.2.0", Environment: "production"}
	if err := p.Allows(&ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]team.Claims{
		"repo":        {Repository: "evil/store", RepositoryID: "42", Ref: "refs/heads/main", Environment: "production"},
		"recreated":   {Repository: "acme/store", RepositoryID: "43", Ref: "refs/heads/main", Environment: "production"},
		"branch":      {Repository: "acme/store", RepositoryID: "42", Ref: "refs/heads/feature", Environment: "production"},
		"environment": {Repository: "acme/store", RepositoryID: "42", Ref: "refs/heads/main", Environment: "staging"},
	} {
		if err := p.Allows(&c); err == nil {
			t.Errorf("%s: allowed %+v", name, c)
		}
	}
	for _, bad := range []team.OIDCPolicy{
		{Provider: "gitlab", Repository: "acme/store"},
		{Provider: team.ProviderGitHub, Repository: "acme"},
		{Provider: team.ProviderGitHub, Repository: "acme/store", Refs: []string{"main"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// An archived project changes in nothing but members leaving, until it is
// unarchived; only an admin archives it, and a successor names a chain.
func TestArchive(t *testing.T) {
	owner, alice := newAcct(t, 1, "owner"), newAcct(t, 2, "alice")
	w := newWorld(t, owner, alice)
	pub, _ := newKey(t)
	w.add(owner, team.TypeInit, team.InitBody{Creator: owner.person(), Envs: []team.Env{{Name: "dev", PublicKey: pub}}})
	w.add(owner, team.TypeMemberAdd, team.MemberAddBody{Member: alice.person(), Envs: []string{"dev"}, Verified: team.VerifiedAccountKey})
	w.reject("only an admin", alice, team.TypeArchive, team.ArchiveBody{})
	w.reject("invalid successor", owner, team.TypeArchive, team.ArchiveBody{Successor: &team.ProjectRef{Project: project, Root: strings.Repeat("a", 64)}})
	w.add(owner, team.TypeArchive, team.ArchiveBody{Reason: "done"})
	if !w.st.Archived || w.st.Successor != nil {
		t.Fatalf("archive: %+v", w.st)
	}
	pub2, _ := newKey(t)
	w.reject("archived", owner, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "dev", PublicKey: pub2}})
	w.reject("archived", owner, team.TypeArchive, team.ArchiveBody{})
	w.add(alice, team.TypeMemberRemove, team.MemberRemoveBody{User: alice.user})
	w.add(owner, team.TypeUnarchive, team.UnarchiveBody{})
	w.reject("not archived", owner, team.TypeUnarchive, team.UnarchiveBody{})
	w.add(owner, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "dev", PublicKey: pub2}})
	next := &team.ProjectRef{Project: "acme/shop", Root: strings.Repeat("b", 64)}
	w.add(owner, team.TypeArchive, team.ArchiveBody{Successor: next})
	if !w.st.Archived || w.st.Successor == nil || *w.st.Successor != *next {
		t.Fatalf("archive with a successor: %+v", w.st.Successor)
	}
	if again, err := team.Verify(project, w.links, w.chains); err != nil || !again.Archived {
		t.Fatalf("reverify: %v", err)
	}
}
