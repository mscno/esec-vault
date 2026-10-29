package account_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

func TestPersonalAndWorkTenantsAndTransfer(t *testing.T) { //nolint:gocyclo // sequential transfer story with explicit assertions
	_, a := setup(t)
	ctx := context.Background()
	names, err := a.Client.Namespaces(ctx)
	if err != nil || len(names) != 2 {
		t.Fatalf("namespaces: %+v %v", names, err)
	}
	personal, err := a.CreateOrg(ctx, "mscno")
	if err != nil || personal.Kind != "personal" {
		t.Fatalf("personal: %+v %v", personal, err)
	}
	work, err := a.CreateOrg(ctx, "acme")
	if err != nil || work.Kind != "team" {
		t.Fatalf("work: %+v %v", work, err)
	}
	old, err := a.CreateTeam(ctx, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateMachine(ctx, project, "old-ci", []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := a.MoveProject(ctx, project, "mscno/store")
	if err != nil {
		t.Fatal(err)
	}
	if !res.CrossTenant || len(res.Members) != 0 || len(res.Machines) != 1 {
		t.Fatalf("transfer: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Lines(project), "\n"), "rotate") {
		t.Fatal("transfer omitted key rotation warning")
	}
	from, err := a.Team(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	to, err := a.Team(ctx, "mscno/store")
	if err != nil {
		t.Fatal(err)
	}
	if !from.State.Archived || from.State.Successor == nil || from.State.Successor.Root != to.State.Root() || to.State.Predecessor == nil || to.State.Predecessor.Root != old.Root() {
		t.Fatal("transfer lost signed lineage")
	}
	if len(to.State.ActiveMembers()) != 1 || len(to.State.ActiveMachines()) != 0 || len(to.State.ActiveGroups()) != 0 {
		t.Fatal("source access leaked into destination")
	}
	if to.State.Envs["dev"].PublicKey != old.Envs["dev"].PublicKey {
		t.Fatal("environment key changed unexpectedly")
	}
	keys, err := a.KS.Read("mscno/store")
	if err != nil || keys["ESEC_PRIVATE_KEY_DEV"] == "" {
		t.Fatalf("destination keys: %v", err)
	}
	// The same project can be moved from the personal tenant into work.
	if _, err := a.MoveProject(ctx, "mscno/store", "acme/store2"); err != nil {
		t.Fatal(err)
	}
	// A collision never archives the source.
	if _, err := a.MoveProject(ctx, "acme/store2", "acme/store"); err == nil {
		t.Fatal("destination collision accepted")
	}
	still, err := a.Team(ctx, "acme/store2")
	if err != nil || still.State.Archived {
		t.Fatalf("failed transfer changed source: %v", err)
	}
}

func TestInvalidSelfServiceInitializationDoesNotClaimNamespace(t *testing.T) {
	_, a := setup(t)
	ctx := context.Background()
	id, err := team.NewTenantID()
	if err != nil {
		t.Fatal(err)
	}
	_, wrong, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := team.NewOrg("failed-claim").NewLink(team.OrgInit, team.OrgInitBody{Creator: team.Person{User: a.State.User, Login: a.State.Login, Root: a.State.Chain.Root}, Kind: "team", TenantID: id, ExplicitOwners: true}, a.Now(), a.State.User, a.State.Chain.UKeyVersion, a.State.Chain.Seq, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Client.OrgCommit(ctx, "failed-claim", &wire.OrgCommit{Links: []*envelope.Envelope{e}}); err == nil {
		t.Fatal("invalid signature initialized a tenant")
	}
	if _, err := a.Client.Namespace(ctx, "failed-claim"); !client.IsCode(err, wire.ErrNotFound) {
		t.Fatalf("failed claim left a namespace behind: %v", err)
	}
	if _, err := a.CreateOrg(ctx, "failed-claim"); err != nil {
		t.Fatalf("failed setup squatted a name: %v", err)
	}
}

func TestTransferRollbackAndAuthorization(t *testing.T) {
	h, a := setup(t)
	ctx := context.Background()
	old, err := a.CreateTeam(ctx, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(a.KR)
	if err != nil {
		t.Fatal(err)
	}
	own := a.State.Chain
	sign := func(st *team.State, typ string, body any) *envelope.Envelope {
		t.Helper()
		e, err := st.NewLink(typ, body, a.Now(), a.State.User, own.UKeyVersion, own.Seq, id.Sign)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	dest := "mscno/new"
	init := sign(team.New(dest), team.TypeInit, team.InitBody{Creator: old.Members[a.State.User].Person, Envs: []team.Env{old.Envs["dev"].Env}, Predecessor: &team.ProjectRef{Project: project, Root: old.Root()}})
	archive := sign(old, team.TypeArchive, team.ArchiveBody{Successor: &team.ProjectRef{Project: dest, Root: strings.Repeat("00", 32)}})
	req := &wire.ProjectTransfer{Destination: dest, Links: []*envelope.Envelope{init}, Archive: archive}
	if err := a.Client.TransferProject(ctx, project, req); !client.IsCode(err, wire.ErrInvalidRequest) {
		t.Fatalf("invalid reciprocal root: %v", err)
	}
	var n int
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM projects WHERE id = ?`, dest).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed transfer left destination: %d %v", n, err)
	}
	// The ordinary commit API must not accept a detached transfer init.
	if _, err := a.Client.ProjectCommit(ctx, dest, &wire.ProjectCommit{Links: req.Links}); !client.IsCode(err, wire.ErrInvalidRequest) {
		t.Fatalf("detached predecessor: %v", err)
	}
	// A request built against an old source head must roll back the newly
	// created destination, not leave both projects active.
	req.Archive = sign(old, team.TypeArchive, team.ArchiveBody{Successor: &team.ProjectRef{Project: dest, Root: init.Hash()}})
	if _, err := a.CreateMachine(ctx, project, "changed-source", []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Client.TransferProject(ctx, project, req); !client.IsCode(err, wire.ErrConflict) {
		t.Fatalf("stale source: %v", err)
	}
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM projects WHERE id = ?`, dest).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stale transfer left destination: %d %v", n, err)
	}
	// Bypass the CLI preflight: the server itself must refuse another
	// account's personal namespace.
	exec(t, h, `INSERT INTO namespaces(name, kind, owner, created_at) VALUES ('alice', 'personal', 'gh:2', 1)`)
	other := "alice/new"
	otherInit := sign(team.New(other), team.TypeInit, team.InitBody{Creator: old.Members[a.State.User].Person, Envs: []team.Env{old.Envs["dev"].Env}, Predecessor: &team.ProjectRef{Project: project, Root: old.Root()}})
	if err := a.Client.TransferProject(ctx, project, &wire.ProjectTransfer{Destination: other, Links: []*envelope.Envelope{otherInit}, Archive: req.Archive}); !client.IsCode(err, wire.ErrForbidden) {
		t.Fatalf("another personal tenant: %v", err)
	}
	// A reserved team is not sufficient: the receiving signed tenant must
	// have an admin accepting the move.
	exec(t, h, `INSERT INTO namespaces(name, kind, owner, created_at) VALUES ('geoman', 'team', ?, 1)`, a.State.User)
	if _, err := a.MoveProject(ctx, project, "geoman/new"); err == nil {
		t.Fatal("transfer into unsigned work tenant accepted")
	}
	view, err := a.Team(ctx, project)
	if err != nil || view.State.Archived {
		t.Fatalf("failed transfer archived source: %v", err)
	}
	if err := a.KS.Write(dest, map[string]string{"ESEC_PRIVATE_KEY_DEV": strings.Repeat("cd", 32)}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.MoveProject(ctx, project, dest); err == nil || !strings.Contains(err.Error(), "different local keyring") {
		t.Fatalf("local key collision: %v", err)
	}
}
