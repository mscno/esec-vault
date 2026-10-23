package team_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/team"
)

type orgWorld struct {
	t     *testing.T
	w     *world
	st    *team.OrgState
	links []*envelope.Envelope
}

func newOrgWorld(t *testing.T, w *world, by *acct) *orgWorld {
	t.Helper()
	o := &orgWorld{t: t, w: w, st: team.NewOrg("acme")}
	o.add(by, team.OrgInit, team.OrgInitBody{Creator: by.person()})
	return o
}

func (o *orgWorld) link(by *acct, typ string, body any) *envelope.Envelope {
	o.t.Helper()
	o.w.now = o.w.now.Add(time.Minute)
	e, err := o.st.NewLink(typ, body, o.w.now, by.user, by.st.UKeyVersion, by.st.Seq, by.u.Sign)
	if err != nil {
		o.t.Fatal(err)
	}
	return e
}

func (o *orgWorld) try(by *acct, typ string, body any) error {
	o.t.Helper()
	e := o.link(by, typ, body)
	next, err := o.st.Next(e, o.w.chains)
	if err != nil {
		return err
	}
	o.st, o.links = next, append(o.links, e)
	return nil
}

func (o *orgWorld) add(by *acct, typ string, body any) {
	o.t.Helper()
	if err := o.try(by, typ, body); err != nil {
		o.t.Fatalf("%s: %v", typ, err)
	}
}

func (o *orgWorld) reject(want string, by *acct, typ string, body any) {
	o.t.Helper()
	if err := o.try(by, typ, body); err == nil || !strings.Contains(err.Error(), want) {
		o.t.Fatalf("%s: expected error containing %q, got %v", typ, want, err)
	}
}

func testKMSKey(t *testing.T, name string) kms.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return kms.Key{Provider: "gcp", Name: "projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/" + name + "/cryptoKeyVersions/1", Audience: "projects/123456789/locations/global/workloadIdentityPools/esec-fly/providers/fly-acme", PublicKey: base64.StdEncoding.EncodeToString(der)}
}

func TestOrgLifecycle(t *testing.T) { //nolint:gocyclo // one sequential story
	alice, bob, carol, mallory := newAcct(t, 1, "alice"), newAcct(t, 2, "bob"), newAcct(t, 3, "carol"), newAcct(t, 4, "mallory")
	w := newWorld(t, alice, bob, carol, mallory)
	o := newOrgWorld(t, w, alice)
	if !o.st.Admin(alice.user) || o.st.Root() == "" || len(strings.Split(o.st.Words(), "-")) != 8 {
		t.Fatalf("init: %+v", o.st)
	}

	// Only admins add people; a member is not an admin.
	o.add(alice, team.OrgMemberAdd, team.OrgMemberAddBody{Member: bob.person(), Verified: team.VerifiedGitHubSSH})
	o.reject("not an admin", bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedGitHubSSH})
	o.reject("already a member", alice, team.OrgMemberAdd, team.OrgMemberAddBody{Member: bob.person(), Verified: team.VerifiedGitHubSSH})
	o.reject("only a delegate", alice, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedWeb})
	if !o.st.In(bob.user) || o.st.Admin(bob.user) {
		t.Fatal("bob is a member")
	}

	// Approved keys: a name each, a key once, groups of the org only.
	shared, perApp := testKMSKey(t, "workloads"), testKMSKey(t, "fly-api")
	o.add(alice, team.OrgKMSAdd, team.OrgKMSAddBody{Key: team.OrgKMSKey{Name: "gcp-prod", Key: shared}})
	o.reject("already", alice, team.OrgKMSAdd, team.OrgKMSAddBody{Key: team.OrgKMSKey{Name: "again", Key: shared}})
	o.reject("not a group of acme", alice, team.OrgKMSAdd, team.OrgKMSAddBody{Key: team.OrgKMSKey{Name: "fly-api", Key: perApp, Groups: []string{"other/fly-api"}}})
	o.reject("not an admin", bob, team.OrgKMSAdd, team.OrgKMSAddBody{Key: team.OrgKMSKey{Name: "fly-api", Key: perApp}})
	o.add(alice, team.OrgKMSAdd, team.OrgKMSAddBody{Key: team.OrgKMSKey{Name: "fly-api", Key: perApp, Groups: []string{"acme/fly-api"}}})
	if err := o.st.CheckKMS(shared, "acme/production"); err != nil {
		t.Fatalf("shared key: %v", err)
	}
	if err := o.st.CheckKMS(perApp, "acme/fly-web"); err == nil || !strings.Contains(err.Error(), "only for acme/fly-api") {
		t.Fatalf("per-app key for another group: %v", err)
	}
	if err := o.st.CheckKMS(perApp, "acme/fly-api"); err != nil {
		t.Fatalf("per-app key: %v", err)
	}
	if err := o.st.CheckKMS(testKMSKey(t, "server"), "acme/production"); err == nil || !strings.Contains(err.Error(), "has not approved") {
		t.Fatalf("a key the server made up: %v", err)
	}
	// Same name and public key, another audience: not the approved key.
	other := shared
	other.Audience = "projects/1/locations/global/workloadIdentityPools/evil/providers/evil"
	if err := o.st.CheckKMS(other, "acme/production"); err == nil {
		t.Fatal("a key with another audience counts as approved")
	}

	// Settings: checked, and the rules they set.
	o.reject("no key nope", alice, team.OrgSettingsSet, team.OrgSettingsBody{Settings: team.OrgSettings{DefaultKMS: "nope"}})
	o.reject("day counts", alice, team.OrgSettingsSet, team.OrgSettingsBody{Settings: team.OrgSettings{MaxTokenDays: -1}})
	o.reject("not an admin", bob, team.OrgSettingsSet, team.OrgSettingsBody{Settings: team.OrgSettings{}})
	o.add(alice, team.OrgSettingsSet, team.OrgSettingsBody{Settings: team.OrgSettings{RequireGitHubProof: true, MembersOnly: true, MaxTokenDays: 30, FlyOrg: "acme", DefaultKMS: "gcp-prod"}})
	if o.st.SettingsBy != alice.user {
		t.Fatal("settings signer")
	}
	if err := o.st.CheckPerson(carol.user, "carol", team.VerifiedGitHubSSH); err == nil || !strings.Contains(err.Error(), "only its people") {
		t.Fatalf("members only: %v", err)
	}
	if err := o.st.CheckPerson(bob.user, "bob", team.VerifiedAccountKey); err == nil || !strings.Contains(err.Error(), "GitHub SSH proof") {
		t.Fatalf("proof: %v", err)
	}
	if err := o.st.CheckPerson(bob.user, "bob", team.VerifiedGitHubSSH); err != nil {
		t.Fatal(err)
	}
	if err := o.st.CheckToken(time.Time{}, w.now); err == nil {
		t.Fatal("a token that never expires")
	}
	if err := o.st.CheckToken(w.now.Add(31*24*time.Hour), w.now); err == nil {
		t.Fatal("a token beyond the limit")
	}
	if err := o.st.CheckToken(w.now.Add(30*24*time.Hour), w.now); err != nil {
		t.Fatal(err)
	}
	o.reject("GitHub SSH proof", alice, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedAccountKey})

	// Withdrawing the default key clears the default.
	o.add(alice, team.OrgKMSRemove, team.OrgKMSRemoveBody{Name: "gcp-prod"})
	if o.st.Settings.DefaultKMS != "" {
		t.Fatal("default key withdrawn but still the default")
	}
	if err := o.st.CheckKMS(shared, "acme/production"); err == nil || !strings.Contains(err.Error(), "withdrew") {
		t.Fatalf("withdrawn key: %v", err)
	}

	// A member becomes an admin; an admin needs another to leave.
	o.add(alice, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: bob.person(), Verified: team.VerifiedGitHubSSH})
	if !o.st.Admin(bob.user) || o.st.Member(bob.user) {
		t.Fatal("bob is an admin only")
	}
	o.add(bob, team.OrgAdminRemove, team.OrgAdminRemoveBody{User: alice.user})
	o.reject("at least one admin", bob, team.OrgAdminRemove, team.OrgAdminRemoveBody{User: bob.user})
	if at, left := o.st.Left(alice.user); !left || at.IsZero() {
		t.Fatal("alice left the org")
	}
	if _, left := o.st.Left(mallory.user); left {
		t.Fatal("mallory was never in it")
	}

	// A member may leave by themselves, and only themselves.
	o.add(bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedGitHubSSH})
	o.add(bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: mallory.person(), Verified: team.VerifiedGitHubSSH})
	o.reject("only remove themselves", mallory, team.OrgMemberRemove, team.OrgMemberRemoveBody{User: carol.user})
	o.add(carol, team.OrgMemberRemove, team.OrgMemberRemoveBody{User: carol.user})
	if len(o.st.Former()) != 2 {
		t.Fatalf("former: %v", o.st.Former())
	}

	// The whole chain verifies from scratch, and a pin catches a rollback.
	st, err := team.VerifyOrg("acme", o.links, w.chains)
	if err != nil || st.Head() != o.st.Head() {
		t.Fatalf("verify: %v", err)
	}
	short, err := team.VerifyOrg("acme", o.links[:3], w.chains)
	if err != nil {
		t.Fatal(err)
	}
	if err := short.CheckPin(o.st.Seq, o.st.Head()); err == nil {
		t.Fatal("rollback not caught")
	}
	if _, err := team.VerifyOrg("other", o.links, w.chains); err == nil {
		t.Fatal("links of acme verify as another organisation")
	}
	if _, err := team.VerifyOrg("Acme", o.links, w.chains); err == nil {
		t.Fatal("an upper-case organisation name")
	}
}

// Someone outside the organisation cannot sign its links, and a chain must
// start with its creator's init.
func TestOrgForgery(t *testing.T) {
	alice, mallory := newAcct(t, 1, "alice"), newAcct(t, 2, "mallory")
	w := newWorld(t, alice, mallory)
	o := newOrgWorld(t, w, alice)
	o.reject("not an admin", mallory, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: mallory.person(), Verified: team.VerifiedGitHubSSH})
	o.reject("not an admin", mallory, team.OrgMemberRemove, team.OrgMemberRemoveBody{User: alice.user})

	fresh := team.NewOrg("acme")
	e, err := fresh.NewLink(team.OrgInit, team.OrgInitBody{Creator: alice.person()}, w.now, mallory.user, mallory.st.UKeyVersion, mallory.st.Seq, mallory.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Next(e, w.chains); err == nil {
		t.Fatal("an init signed by someone else than its creator")
	}
}

// A link a delegate signed (the server, a passkey on a page) is not one the
// person signed with their user key, so it anchors nothing; removals signed
// by a delegate, or marked so, leave admin roles alone.
func TestOrgDelegateLinks(t *testing.T) {
	alice, bob, carol := newAcct(t, 1, "alice"), newAcct(t, 2, "bob"), newAcct(t, 3, "carol")
	w := newWorld(t, alice, bob, carol)
	o := newOrgWorld(t, w, bob)
	o.add(bob, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: alice.person(), Verified: team.VerifiedGitHubSSH})
	o.add(bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedGitHubSSH})
	if o.st.SignedWithUserKey(alice.user) {
		t.Fatal("alice signed nothing")
	}
	srvPub, srvKey, _ := ed25519.GenerateKey(rand.Reader)
	alice.add(chain.TypeDelegateAdd, chain.DelegateAddBody{Delegate: chain.Delegate{ID: "dl_server0001", Kind: chain.DelegateServer, Name: "vault server", Scope: chain.ScopeRemove, SignPub: hex.EncodeToString(srvPub), Created: t0}}, t0, alice.u.Sign)
	w.now = w.now.Add(time.Minute)
	e, err := o.st.DelegateLink(team.OrgMemberRemove, team.OrgMemberRemoveBody{User: carol.user}, w.now, alice.user, "dl_server0001", alice.st.Seq)
	if err != nil {
		t.Fatal(err)
	}
	e.AddSignature(srvKey)
	next, err := o.st.Next(e, w.chains)
	if err != nil {
		t.Fatalf("the server removes a member for alice: %v", err)
	}
	o.st = next
	if o.st.SignedWithUserKey(alice.user) {
		t.Fatal("a link the server signed counts as alice's own")
	}
	if !o.st.KeepsAdminRoles(carol.user) {
		t.Fatal("a removal the server signed takes admin roles away")
	}
	// A removal with the user key takes everything, unless it says not to.
	o.add(bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedGitHubSSH})
	o.add(alice, team.OrgMemberRemove, team.OrgMemberRemoveBody{User: carol.user})
	if o.st.KeepsAdminRoles(carol.user) || !o.st.SignedWithUserKey(alice.user) {
		t.Fatal("a removal alice signed")
	}
	o.add(bob, team.OrgMemberAdd, team.OrgMemberAddBody{Member: carol.person(), Verified: team.VerifiedGitHubSSH})
	o.add(alice, team.OrgMemberRemove, team.OrgMemberRemoveBody{User: carol.user, KeepAdminRoles: true})
	if !o.st.KeepsAdminRoles(carol.user) {
		t.Fatal("a removal that keeps admin roles")
	}
}
