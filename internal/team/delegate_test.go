package team_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/passkey/passkeytest"
	"github.com/mscno/esec-vault/internal/team"
)

// delegateLink builds a link signed by a delegate of by.
func (w *world) delegateLink(by *acct, delegate, typ string, body any, sign func(*envelope.Envelope)) *envelope.Envelope {
	w.t.Helper()
	w.now = w.now.Add(time.Minute)
	e, err := w.st.DelegateLink(typ, body, w.now, by.user, delegate, by.st.Seq)
	if err != nil {
		w.t.Fatal(err)
	}
	sign(e)
	return e
}

func (w *world) try(e *envelope.Envelope) error {
	next, err := w.st.Next(e, w.chains)
	if err != nil {
		return err
	}
	w.st, w.links = next, append(w.links, e)
	return nil
}

func TestDelegates(t *testing.T) { //nolint:gocyclo // one sequential story
	alice, bob, carol := newAcct(t, 1, "alice"), newAcct(t, 2, "bob"), newAcct(t, 3, "carol")
	w := newWorld(t, alice, bob, carol)
	devPub, _ := newKey(t)
	prodPub, _ := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "dev", PublicKey: devPub}, {Name: "prod", PublicKey: prodPub}}})
	w.add(alice, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"dev", "prod"}, Verified: team.VerifiedAccountKey})

	// Alice lets the server sign removals, and a passkey manage.
	srvPub, srvKey, _ := ed25519.GenerateKey(rand.Reader)
	alice.add(chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: chain.Delegate{ID: "dl_server0001", Kind: chain.DelegateServer, Name: "vault server", Scope: chain.ScopeRemove, SignPub: hex.EncodeToString(srvPub), Created: t0}}, t0, alice.u.Sign)
	pk := passkeytest.New("vault.example", "https://vault.example")
	alice.add(chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: pk.Delegate("dl_passkey001", "YubiKey", chain.ScopeManage, t0)}, t0, alice.u.Sign)
	server := func(e *envelope.Envelope) { e.AddSignature(srvKey) }

	// The server cannot add anyone, or let bob read more.
	if err := w.try(w.delegateLink(alice, "dl_server0001", team.TypeMemberAdd, team.MemberAddBody{Member: carol.person(), Envs: []string{"dev"}, Verified: team.VerifiedWeb}, server)); err == nil {
		t.Fatal("the server added a member")
	}
	// It can narrow what bob reads.
	if err := w.try(w.delegateLink(alice, "dl_server0001", team.TypeMemberUpdate, team.MemberUpdateBody{User: bob.user, Envs: []string{"dev"}}, server)); err != nil {
		t.Fatalf("server narrows: %v", err)
	}
	if err := w.try(w.delegateLink(alice, "dl_server0001", team.TypeMemberUpdate, team.MemberUpdateBody{User: bob.user, Envs: []string{"dev", "prod"}}, server)); err == nil {
		t.Fatal("the server widened access")
	}

	// The passkey adds carol, checked on the web, and can widen access.
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMemberAdd, team.MemberAddBody{Member: carol.person(), Envs: []string{"dev"}, Verified: team.VerifiedWeb}, pk.Sign)); err != nil {
		t.Fatalf("passkey adds: %v", err)
	}
	if m, _ := w.st.Member(carol.user); m.Verified != team.VerifiedWeb {
		t.Fatalf("verified %q", m.Verified)
	}
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMemberUpdate, team.MemberUpdateBody{User: bob.user, Envs: []string{"dev", "prod"}}, pk.Sign)); err != nil {
		t.Fatalf("passkey widens: %v", err)
	}
	// Nobody's delegate makes an admin, and a delegate's member is always
	// "checked on the web".
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMemberUpdate, team.MemberUpdateBody{User: bob.user, Admin: true}, pk.Sign)); err == nil {
		t.Fatal("a passkey made an admin")
	}
	if err := w.try(w.link(alice, team.TypeMemberRemove, team.MemberRemoveBody{User: carol.user})); err != nil {
		t.Fatal(err)
	}
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMemberAdd, team.MemberAddBody{Member: carol.person(), Envs: []string{"dev"}, Verified: team.VerifiedGitHubSSH}, pk.Sign)); err == nil {
		t.Fatal("a passkey claimed a GitHub check")
	}
	if err := w.try(w.link(alice, team.TypeMemberAdd, team.MemberAddBody{Member: carol.person(), Envs: []string{"dev"}, Verified: team.VerifiedWeb})); err == nil {
		t.Fatal("a device's link claimed a web check")
	}
	// No environment keys, ever.
	newPub, _ := newKey(t)
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "dev", PublicKey: newPub}}, pk.Sign)); err == nil {
		t.Fatal("a passkey set a key")
	}

	// Forged passkey signatures fail: another origin, another site,
	// nobody present, a server signature on a passkey link.
	for name, mutate := range map[string]func(*passkeytest.Authenticator){
		"origin":  func(a *passkeytest.Authenticator) { a.Origin = "https://evil.example" },
		"rp":      func(a *passkeytest.Authenticator) { a.RPID = "evil.example" },
		"present": func(a *passkeytest.Authenticator) { a.Flags = 0 },
	} {
		bad := *pk
		mutate(&bad)
		if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMachineRemove, team.MachineRemoveBody{ID: "m_nonexistent1"}, bad.Sign)); err == nil || !strings.Contains(err.Error(), "passkey") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeMemberRemove, team.MemberRemoveBody{User: bob.user}, server)); err == nil {
		t.Fatal("the server signed as the passkey")
	}
	e := w.delegateLink(alice, "dl_passkey001", team.TypeMemberRemove, team.MemberRemoveBody{User: bob.user}, pk.Sign)
	other := w.delegateLink(alice, "dl_passkey001", team.TypeMemberRemove, team.MemberRemoveBody{User: carol.user}, pk.Sign)
	e.Passkey = other.Passkey
	if err := w.try(e); err == nil {
		t.Fatal("an assertion for another link was accepted")
	}

	// Removed, the server delegate signs nothing as of a later position.
	alice.add(chain.TypeDelegateRemove, chain.DelegateRemoveBody{ID: "dl_server0001"}, t0, alice.u.Sign)
	if err := w.try(w.delegateLink(alice, "dl_server0001", team.TypeMemberRemove, team.MemberRemoveBody{User: bob.user}, server)); err == nil {
		t.Fatal("a removed delegate signed")
	}
	// Nor as of an earlier one, once alice signed later.
	w.add(alice, team.TypeMemberUpdate, team.MemberUpdateBody{User: bob.user, Envs: []string{"dev", "prod"}})
	early, err := w.st.DelegateLink(team.TypeMemberRemove, team.MemberRemoveBody{User: bob.user}, w.now.Add(time.Minute), alice.user, "dl_server0001", alice.st.Seq-1)
	if err != nil {
		t.Fatal(err)
	}
	server(early)
	if err := w.try(early); err == nil {
		t.Fatal("a removed delegate signed as of an earlier position")
	}

	// The whole chain verifies again from scratch.
	if _, err := team.Verify(project, w.links, w.chains); err != nil {
		t.Fatal(err)
	}

	// Groups: a passkey chooses projects, the server removes machines but
	// never says their keys are gone.
	g := newGroupWorld(t, w, alice)
	m, mc := g.cred(team.KindMachine, "web")
	g.add(alice, team.GroupMachineAdd, team.GroupMachineAddBody{Machine: mc})
	glink := func(delegate, typ string, body any, sign func(*envelope.Envelope)) error {
		g.w.now = g.w.now.Add(time.Minute)
		e, err := g.st.DelegateLink(typ, body, g.w.now, alice.user, delegate, alice.st.Seq)
		if err != nil {
			t.Fatal(err)
		}
		sign(e)
		return g.apply(e)
	}
	alice.add(chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: chain.Delegate{ID: "dl_server0002", Kind: chain.DelegateServer, Name: "vault server", Scope: chain.ScopeRemove, SignPub: hex.EncodeToString(srvPub), Created: t0}}, t0, alice.u.Sign)
	if err := glink("dl_passkey001", team.GroupAccessAdd, team.GroupAccessBody{Project: project, Root: w.st.Root()}, pk.Sign); err == nil {
		t.Fatal("a passkey chose a project for the group")
	}
	g.add(alice, team.GroupAccessAdd, team.GroupAccessBody{Project: project, Root: w.st.Root()})
	// A passkey cannot grant a group the project does not grant yet,
	// only change what a granted one reads.
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"dev"}}, pk.Sign)); err == nil {
		t.Fatal("a passkey granted a new group")
	}
	w.add(alice, team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"dev"}})
	if err := w.try(w.delegateLink(alice, "dl_passkey001", team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"dev", "prod"}}, pk.Sign)); err != nil {
		t.Fatalf("passkey widens a group: %v", err)
	}
	if err := glink("dl_passkey001", team.GroupAccessRemove, team.GroupAccessRemoveBody{Project: project}, pk.Sign); err != nil {
		t.Fatalf("passkey access remove: %v", err)
	}
	if err := glink("dl_server0002", team.GroupRemove, team.GroupRemoveBody{ID: m.ID, Destroyed: true}, server); err == nil {
		t.Fatal("the server said a machine's keys are gone")
	}
	if err := glink("dl_server0002", team.GroupRemove, team.GroupRemoveBody{ID: m.ID}, server); err != nil {
		t.Fatalf("server removes: %v", err)
	}
	if len(g.st.KeyExposed) != 1 {
		t.Fatal("removal by the server exposed nothing")
	}
	k2, _, _ := team.NewGroupKey(2)
	if err := glink("dl_passkey001", team.GroupKeyRotate, team.GroupKeyRotateBody{Key: k2}, pk.Sign); err == nil {
		t.Fatal("a passkey rotated the group key")
	}

	// A new user key drops every delegate.
	alice.rotate(w.now)
	if len(alice.st.ActiveDelegates()) != 0 {
		t.Fatal("delegates survived a new user key")
	}
}
