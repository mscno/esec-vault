package team_test

import (
	"testing"

	"github.com/mscno/esec-vault/internal/team"
)

func TestPersonalTenantHasOnePermanentOwner(t *testing.T) {
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	o := &orgWorld{t: t, w: w, st: team.NewOrg("alice")}
	o.add(alice, team.OrgInit, team.OrgInitBody{Creator: alice.person(), Kind: "personal"})
	if o.st.Kind != "personal" {
		t.Fatal("personal kind was not signed")
	}
	o.reject("permanent owner", alice, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: bob.person(), Verified: team.VerifiedAccountKey})
	o.reject("permanent owner", alice, team.OrgMemberAdd, team.OrgMemberAddBody{Member: bob.person(), Verified: team.VerifiedAccountKey})
	o.reject("cannot leave", alice, team.OrgAdminRemove, team.OrgAdminRemoveBody{User: alice.user})
	verified, err := team.VerifyOrg("alice", o.links, w.chains)
	if err != nil || verified.Kind != "personal" || !verified.Admin(alice.user) {
		t.Fatalf("verify personal: %+v %v", verified, err)
	}
	legacy := newOrgWorld(t, w, alice)
	if legacy.st.Kind != "team" {
		t.Fatal("legacy organisation no longer verifies as team")
	}
}

func TestExplicitOwnersAndStableNamespaceIdentity(t *testing.T) {
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	id, err := team.NewTenantID()
	if err != nil {
		t.Fatal(err)
	}
	o := &orgWorld{t: t, w: w, st: team.NewOrg("geoman")}
	o.add(alice, team.OrgInit, team.OrgInitBody{Creator: alice.person(), Kind: "team", TenantID: id, ExplicitOwners: true})
	o.add(alice, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: bob.person(), Verified: team.VerifiedAccountKey})
	if o.st.Owner(bob.user) {
		t.Fatal("daily admin automatically became an owner")
	}
	o.reject("only a tenant owner", bob, team.OrgOwnerSet, team.OrgOwnerBody{User: alice.user, Owner: false})
	o.reject("at least one owner", alice, team.OrgOwnerSet, team.OrgOwnerBody{User: alice.user, Owner: false})
	o.add(alice, team.OrgOwnerSet, team.OrgOwnerBody{User: bob.user, Owner: true})
	o.add(bob, team.OrgOwnerSet, team.OrgOwnerBody{User: alice.user, Owner: false})
	o.reject("at least one owner", bob, team.OrgAdminRemove, team.OrgAdminRemoveBody{User: bob.user})
	o.add(bob, team.OrgAdminRemove, team.OrgAdminRemoveBody{User: alice.user})
	o.add(bob, team.OrgAdminAdd, team.OrgAdminAddBody{Admin: alice.person(), Verified: team.VerifiedAccountKey})
	if o.st.Owner(alice.user) {
		t.Fatal("re-added admin regained former ownership")
	}
	previous := o.st
	root := o.st.Root()
	o.add(bob, team.OrgProfileSet, team.OrgProfileBody{TenantID: id, Namespace: "geoman-work", DisplayName: "Geoman Work"})
	if o.st.Root() != root || o.st.TenantID != id || !o.st.ContainsProject("geoman/api") || !o.st.ContainsProject("geoman-work/api") {
		t.Fatal("rename changed identity or lost historical resources")
	}
	if previous.HasNamespace("geoman-work") {
		t.Fatal("profile application mutated the prior verified state")
	}
	other, _ := team.NewTenantID()
	o.reject("identity cannot change", bob, team.OrgProfileSet, team.OrgProfileBody{TenantID: other, Namespace: "geoman-next"})
	o.reject("only a tenant owner", alice, team.OrgProfileSet, team.OrgProfileBody{TenantID: id, Namespace: "stolen"})
}
