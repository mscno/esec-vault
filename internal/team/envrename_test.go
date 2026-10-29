package team_test

import (
	"reflect"
	"testing"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/team"
)

func TestRenameEnvironmentPreservesGrantsAndHistory(t *testing.T) {
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	pub, priv := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "prod", PublicKey: pub}}})
	w.add(alice, team.TypeMemberAdd, team.MemberAddBody{Member: bob.person(), Envs: []string{"prod"}, Verified: team.VerifiedAccountKey})
	g, err := team.NewGrant(w.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, bob.recipient(), map[string]string{"prod": priv}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	before := w.st
	w.add(alice, team.TypeEnvRename, team.EnvRenameBody{Old: "prod", New: "production"})
	if w.st.Envs["production"].Since != before.Envs["prod"].Since || w.st.Envs["production"].Seq != before.Envs["prod"].Seq {
		t.Fatal("rename masqueraded as rotation")
	}
	if before.Envs["prod"].Name != "prod" || !reflect.DeepEqual(before.Members[bob.user].Envs, []string{"prod"}) {
		t.Fatal("previous verified state mutated")
	}
	if !w.st.HasAccess(bob.user, "production") || w.st.HasAccess(bob.user, "prod") {
		t.Fatal("member access not renamed")
	}
	_, keys, err := team.Open(g, w.st, w.chains, bob.recipient(), bob.u.Private)
	if err != nil || keys["production"] != priv || keys["prod"] != "" {
		t.Fatalf("historical grant cannot open under new name: %v", err)
	}
	w.add(alice, team.TypeEnvRename, team.EnvRenameBody{Old: "production", New: "live"})
	_, keys, err = team.Open(g, w.st, w.chains, bob.recipient(), bob.u.Private)
	if err != nil || keys["live"] != priv {
		t.Fatalf("repeated rename: %v", err)
	}
	retired := w.link(alice, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "prod", PublicKey: pub}})
	if _, err := w.st.Next(retired, w.chains); err == nil {
		t.Fatal("retired environment name reused")
	}
	newPub, _ := newKey(t)
	w.add(alice, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "live", PublicKey: newPub}})
	if _, _, err := team.Open(g, w.st, w.chains, bob.recipient(), bob.u.Private); err == nil {
		t.Fatal("rename allowed stale grant after rotation")
	}
}

func TestRenameEnvironmentPreservesGroupGrantAndExposure(t *testing.T) {
	alice := newAcct(t, 1, "alice")
	w := newWorld(t, alice)
	g := newGroupWorld(t, w, alice)
	pub, priv := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "prod", PublicKey: pub}}})
	g.add(alice, team.GroupAccessAdd, team.GroupAccessBody{Project: project, Root: w.st.Root()})
	w.add(alice, team.TypeGroupSet, team.GroupSetBody{Group: group, Root: g.st.Root(), Envs: []string{"prod"}})
	gp, err := chain.ParseKey32(g.st.Key.EncPub)
	if err != nil {
		t.Fatal(err)
	}
	to := team.Recipient{ID: team.GroupHolder(group), Version: 1, EncPub: gp}
	grant, err := team.NewGrant(w.st, alice.user, alice.st.UKeyVersion, alice.u.Sign, to, map[string]string{"prod": priv}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	// Seed exposure and retired history to check the structural rename keeps
	// them exactly, rather than using env_set's rotation semantics.
	w.st.Envs["prod"].Exposed = []team.Exposure{{Holder: "old-reader", Name: "reader"}}
	w.st.Envs["prod"].Retired = []string{"previous-key"}
	previous := w.st
	groupHead := g.st.Head()
	w.add(alice, team.TypeEnvRename, team.EnvRenameBody{Old: "prod", New: "production"})
	if !reflect.DeepEqual(w.st.Envs["production"].Exposed, previous.Envs["prod"].Exposed) || !reflect.DeepEqual(w.st.Envs["production"].Retired, previous.Envs["prod"].Retired) {
		t.Fatal("rename cleared key history or exposure")
	}
	if g.st.Head() != groupHead || w.st.Groups[group].Envs[0] != "production" {
		t.Fatal("group access not preserved")
	}
	_, keys, err := team.Open(grant, w.st, w.chains, to, g.key)
	if err != nil || keys["production"] != priv {
		t.Fatalf("existing group grant broken: %v", err)
	}
}
