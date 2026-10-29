package server

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func namespaceServer(t *testing.T, reservations ...NamespaceConfig) (*Server, *DB) {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &Config{Access: AccessConfig{AllowedGitHubIDs: []int64{1, 2}, AdminGitHubIDs: []int64{1}}, Namespaces: reservations}
	s, err := New(cfg, db, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestNamespaceOwnership(t *testing.T) {
	s, db := namespaceServer(t, NamespaceConfig{Name: "geoman", OwnerGitHubID: 1})
	ctx := context.Background()
	for _, u := range []struct {
		id    int64
		login string
	}{{1, "mscno"}, {2, "alice"}} {
		if _, err := db.upsertUser(ctx, u.id, u.login, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, user string, allowed bool) {
		t.Helper()
		err := db.tx(ctx, func(tx *sql.Tx) error { return s.checkClaim(ctx, tx, name, user) })
		if (err == nil) != allowed {
			t.Fatalf("claim %s by %s: %v", name, user, err)
		}
	}
	check("mscno", "gh:1", true)
	check("mscno", "gh:2", false)
	check("geoman", "gh:1", true)
	check("geoman", "gh:2", false)
	check("unclaimed", "gh:1", true) // onboarded users may create real organisations
	check("admin", "gh:1", false)
	for _, test := range []struct {
		id, user string
		allowed  bool
	}{
		{"mscno/app", "gh:1", true}, {"mscno/app", "gh:2", false},
		{"geoman/app", "gh:1", true}, {"geoman/app", "gh:2", false},
		{"unclaimed/app", "gh:1", false}, {"MSCNO/app", "gh:1", false},
	} {
		err := s.checkNamespace(ctx, db.sql, test.id, test.user, "display")
		if (err == nil) != test.allowed {
			t.Errorf("create %s by %s: %v", test.id, test.user, err)
		}
	}
	// A rename neither loses the original namespace nor reserves a new one.
	if _, err := db.upsertUser(ctx, 1, "newlogin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.upsertUser(ctx, 2, "mscno", time.Now()); err != nil {
		t.Fatal(err)
	}
	check("mscno", "gh:1", true)
	check("mscno", "gh:2", false)
	if n, err := namespace(ctx, db.sql, "newlogin"); err != nil || n != nil {
		t.Fatalf("GitHub rename reserved another personal namespace: %+v %v", n, err)
	}
	// Deleting the config entry does not free the name for someone else.
	s.cfg.Namespaces = nil
	if err := s.initNamespaces(ctx); err != nil {
		t.Fatal(err)
	}
	check("geoman", "gh:2", false)
	s.cfg.Namespaces = []NamespaceConfig{{Name: "geoman", OwnerGitHubID: 2}}
	if err := s.initNamespaces(ctx); err == nil {
		t.Fatal("configuration reassigned an existing tenant")
	}
}

func TestLegacyNamespacesRequireExplicitApproval(t *testing.T) {
	s, db := namespaceServer(t)
	ctx := context.Background()
	if _, err := db.sql.Exec(`INSERT INTO projects(id, created_by, created_at) VALUES ('paraplyventures/old', 'gh:2', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.initNamespaces(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := namespace(ctx, db.sql, "paraplyventures")
	if err != nil || n == nil || n.Kind != "legacy" || n.Owner != "" {
		t.Fatalf("legacy namespace: %+v %v", n, err)
	}
	if err := db.tx(ctx, func(tx *sql.Tx) error { return s.checkClaim(ctx, tx, n.Name, "gh:2") }); err == nil {
		t.Fatal("earliest project creator claimed a legacy namespace")
	}
	s.cfg.Namespaces = []NamespaceConfig{{Name: n.Name, OwnerGitHubID: 1}}
	if err := s.initNamespaces(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.checkNamespace(ctx, db.sql, n.Name+"/new", "gh:1", "mscno"); err != nil {
		t.Fatal(err)
	}
	if err := s.checkNamespace(ctx, db.sql, n.Name+"/new", "gh:2", "alice"); err == nil {
		t.Fatal("legacy creator inherited namespace ownership")
	}
}

func TestNamespaceReservationValidation(t *testing.T) {
	for _, name := range []string{"Geoman", "admin", ".", "..", "a/b", "", "a b"} {
		t.Run(name, func(t *testing.T) {
			s, _ := namespaceServer(t)
			s.cfg.Namespaces = []NamespaceConfig{{Name: name, OwnerGitHubID: 1}}
			if err := s.initNamespaces(context.Background()); err == nil {
				t.Fatal("accepted invalid namespace")
			}
		})
	}
	for _, reservations := range [][]NamespaceConfig{
		{{Name: "geoman", OwnerGitHubID: 1}, {Name: "geoman", OwnerGitHubID: 2}},
		{{Name: "geoman", OwnerGitHubID: 999}},
		{{Name: "geoman", Kind: "unknown", OwnerGitHubID: 1}},
	} {
		s, _ := namespaceServer(t)
		s.cfg.Namespaces = reservations
		if err := s.initNamespaces(context.Background()); err == nil {
			t.Fatalf("accepted invalid reservations: %+v", reservations)
		}
	}
}

func TestPersonalCollisionAndWhitelistReservations(t *testing.T) {
	s, db := namespaceServer(t)
	ctx := context.Background()
	s.cfg.Access.ReservedGitHubHandles = map[string]int64{"mscno": 1}
	if err := s.initNamespaces(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.upsertUser(ctx, 2, "mscno", time.Now()); err != nil {
		t.Fatal(err)
	}
	var personal int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE kind='personal' AND owner='gh:2'`).Scan(&personal); err != nil || personal != 0 {
		t.Fatalf("recycled login inherited a tenant: %d %v", personal, err)
	}
	choose := func(name string) error {
		return db.tx(ctx, func(tx *sql.Tx) error { return s.choosePersonal(ctx, tx, "gh:2", name) })
	}
	if err := choose("mscno"); err == nil {
		t.Fatal("another user's reserved personal handle was taken")
	}
	if err := choose("other-personal"); err != nil {
		t.Fatal(err)
	}
	if err := choose("OTHER-PERSONAL"); err != nil {
		t.Fatalf("personal choice was not idempotent: %v", err)
	}
	if err := choose("second-personal"); err == nil {
		t.Fatal("account created a second personal tenant")
	}
	if _, err := db.upsertUser(ctx, 2, "new-github-login", time.Now()); err != nil {
		t.Fatal(err)
	}
	n, err := namespace(ctx, db.sql, "other-personal")
	if err != nil || n.Owner != "gh:2" {
		t.Fatalf("GitHub rename changed tenant ownership: %+v %v", n, err)
	}
}
