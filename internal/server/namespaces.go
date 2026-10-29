package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,38}$`)

func reservedNamespace(name string) bool {
	switch name {
	case "admin", "api", "auth", "system", "support", "www", "vault", "esec", "orgs", "projects", "settings", "login", "device", "devices", "account", "groups", "changes", "teams", "v1":
		return true
	}
	return false
}

func namespace(ctx context.Context, q queryer, name string) (*wire.Namespace, error) {
	n := &wire.Namespace{Name: strings.ToLower(name)}
	err := q.QueryRowContext(ctx, `SELECT COALESCE(t.kind,n.kind), COALESCE(t.owner,n.owner), COALESCE(t.id,''), COALESCE(t.canonical,n.name), COALESCE(t.namespace,n.name), COALESCE(t.display_name,'')
		FROM namespaces n LEFT JOIN tenants t ON t.id=n.tenant_id WHERE n.name = ?`, n.Name).Scan(&n.Kind, &n.Owner, &n.TenantID, &n.Canonical, &n.Name, &n.DisplayName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

// reservePersonal runs only after GitHub authentication. A rename never
// reserves another name; a recycled login never inherits its previous owner.
func reservePersonal(ctx context.Context, tx *sql.Tx, user, login string, now time.Time) error {
	name := strings.ToLower(login)
	if !namespacePattern.MatchString(name) || reservedNamespace(name) {
		return nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE kind='personal' AND owner=?`, user).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	existing, err := namespace(ctx, tx, name)
	if err != nil || existing != nil {
		return err
	}
	return createTenant(ctx, tx, name, "personal", user, "", name, now)
}

func createTenant(ctx context.Context, tx *sql.Tx, name, kind, owner, id, display string, now time.Time) error {
	if id == "" {
		var err error
		id, err = team.NewTenantID()
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants(id, canonical, namespace, kind, owner, display_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, name, name, kind, owner, display, now.Unix()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO namespaces(name,kind,owner,created_at,tenant_id) VALUES (?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET tenant_id=excluded.tenant_id WHERE namespaces.tenant_id=''`, name, kind, owner, now.Unix(), id)
	return err
}

// Existing resource prefixes are quarantined, never awarded to their first
// creator. Operators resolve legacy names explicitly through reservations.
func (c *Config) validateNamespaces() error {
	if c.MaxOrgsPerAccount < 0 || c.MaxOrgsPerAccount > 1000 {
		return fmt.Errorf("max_orgs_per_account must be 0 (default 10) through 1000")
	}
	personalHints := map[int64]bool{}
	for name, id := range c.Access.ReservedGitHubHandles {
		if !team.ValidNamespace(name) || reservedNamespace(name) || !c.Allowed(id) {
			return fmt.Errorf("invalid whitelisted handle reservation %q", name)
		}
		if personalHints[id] {
			return fmt.Errorf("only one personal handle hint is allowed per GitHub account")
		}
		personalHints[id] = true
	}
	seen := map[string]bool{}
	for _, n := range c.Namespaces {
		if team.ValidOrg(n.Name) != nil || !namespacePattern.MatchString(n.Name) || reservedNamespace(n.Name) || seen[n.Name] || n.OwnerGitHubID <= 0 || !c.Allowed(n.OwnerGitHubID) || (n.Kind != "" && n.Kind != "team" && n.Kind != "personal") {
			return fmt.Errorf("invalid or duplicate namespace reservation %q (owner must be allowlisted)", n.Name)
		}
		seen[n.Name] = true
	}
	return nil
}

func (s *Server) reserveConfiguredNamespace(ctx context.Context, tx *sql.Tx, n NamespaceConfig) error {
	owner := userID(n.OwnerGitHubID)
	kind := n.Kind
	if kind == "" {
		kind = "team"
	}
	existing, err := namespace(ctx, tx, n.Name)
	if err != nil {
		return err
	}
	if existing != nil && existing.Kind != "legacy" {
		if existing.Kind != kind || existing.Owner != owner {
			return fmt.Errorf("namespace %s is already reserved; ownership changes require an explicit migration", n.Name)
		}
		return nil
	}
	// Reservations can restrict admission, never replace signed tenant admins.
	os, _, err := s.db.orgState(ctx, tx, n.Name)
	if err != nil {
		return err
	}
	if os != nil && !os.Admin(owner) {
		return fmt.Errorf("namespace %s: nominated owner is not a signed tenant admin", n.Name)
	}
	if os != nil && kind == "personal" && len(os.People()) != 1 {
		return fmt.Errorf("namespace %s has multiple people; it cannot be personal", n.Name)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO namespaces(name, kind, owner, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, owner = excluded.owner WHERE namespaces.kind = 'legacy'`, n.Name, kind, owner, s.now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tenants SET kind=?, owner=? WHERE canonical=?`, kind, owner, n.Name); err != nil {
		return err
	}
	return s.db.audit(ctx, tx, owner, "", "", "namespace_reserved", n.Name, s.now())
}

func (s *Server) initNamespaces(ctx context.Context) error {
	if err := s.cfg.validateNamespaces(); err != nil {
		return err
	}
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		if err := backfillTenants(ctx, tx, s.now()); err != nil {
			return err
		}
		// Reserve configured teams before automatic personal names.
		for _, n := range s.cfg.Namespaces {
			if err := s.reserveConfiguredNamespace(ctx, tx, n); err != nil {
				return err
			}
		}
		// First mark old prefixes: a matching login alone does not prove
		// ownership of an existing project or organisation.
		if err := scanAll(ctx, tx, `SELECT id FROM projects UNION SELECT id FROM machine_groups UNION SELECT id || '/x' FROM orgs`, nil, func(r *sql.Rows) error {
			var id string
			if err := r.Scan(&id); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO namespaces(name, kind, created_at) VALUES (?, 'legacy', ?) ON CONFLICT(name) DO NOTHING`, team.OrgOf(id), s.now().Unix())
			return err
		}); err != nil {
			return err
		}
		if err := backfillTenants(ctx, tx, s.now()); err != nil {
			return err
		}
		for name, id := range s.cfg.Access.ReservedGitHubHandles {
			if err := reservePersonal(ctx, tx, userID(id), name, s.now()); err != nil {
				return err
			}
		}
		return scanAll(ctx, tx, `SELECT id, login FROM users ORDER BY created_at, id`, nil, func(r *sql.Rows) error {
			var user, login string
			if err := r.Scan(&user, &login); err != nil {
				return err
			}
			return reservePersonal(ctx, tx, user, login, s.now())
		})
	})
}

func (s *Server) apiNamespaces(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	out := []wire.Namespace{}
	err := scanAll(r.Context(), s.db.sql, `SELECT namespace, kind, owner, id, canonical, display_name FROM tenants n WHERE (owner = ? AND NOT EXISTS (SELECT 1 FROM orgs WHERE id=n.canonical)) OR (kind='personal' AND owner=?) OR EXISTS
		(SELECT 1 FROM org_people p WHERE p.org = n.canonical AND p.user_id = ? AND p.active = 1) ORDER BY namespace`, []any{c.user.ID, c.user.ID, c.user.ID}, func(rows *sql.Rows) error {
		var n wire.Namespace
		if err := rows.Scan(&n.Name, &n.Kind, &n.Owner, &n.TenantID, &n.Canonical, &n.DisplayName); err != nil {
			return err
		}
		out = append(out, n)
		return nil
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for i := range out {
		if err := s.describeNamespace(r.Context(), &out[i]); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) requireNamespaceOwner(ctx context.Context, q queryer, org, user string) error {
	n, err := namespace(ctx, q, org)
	if err != nil {
		return err
	}
	if n == nil || n.Kind == "legacy" || reservedNamespace(org) {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "namespace %s is not claimed; create its tenant first (legacy names require explicit operator approval)", org)
	}
	if n.Owner != user {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "namespace %s is reserved for another account", org)
	}
	return nil
}

func (s *Server) canCreateTenant(ctx context.Context, tx *sql.Tx, name, user string) error {
	if !team.ValidNamespace(name) || reservedNamespace(name) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid or reserved namespace")
	}
	n, err := namespace(ctx, tx, name)
	if err != nil {
		return err
	}
	if n != nil {
		return s.requireNamespaceOwner(ctx, tx, name, user)
	}
	var personal, created int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE kind='personal' AND owner=?`, user).Scan(&personal); err != nil {
		return err
	}
	if personal == 0 {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "choose your personal namespace first: esec vault personal choose NAME")
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE kind='team' AND owner=?`, user).Scan(&created); err != nil {
		return err
	}
	limit := s.cfg.MaxOrgsPerAccount
	if limit == 0 {
		limit = 10
	}
	if created >= limit {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "organisation creation limit reached (%d); ask the operator to raise it", limit)
	}
	return nil
}

func backfillTenants(ctx context.Context, tx *sql.Tx, now time.Time) error {
	return scanAll(ctx, tx, `SELECT name,kind,owner FROM namespaces WHERE tenant_id='' ORDER BY name`, nil, func(r *sql.Rows) error {
		var name, kind, owner string
		if err := r.Scan(&name, &kind, &owner); err != nil {
			return err
		}
		return createTenant(ctx, tx, name, kind, owner, "", name, now)
	})
}

func (s *Server) choosePersonal(ctx context.Context, tx *sql.Tx, user, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if !namespacePattern.MatchString(name) || reservedNamespace(name) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "choose a valid, non-reserved namespace")
	}
	var current string
	err := tx.QueryRowContext(ctx, `SELECT namespace FROM tenants WHERE kind='personal' AND owner=?`, user).Scan(&current)
	if err == nil {
		if current == name {
			return nil
		}
		return clientErr(http.StatusConflict, wire.ErrConflict, "your personal tenant is already %s; rename it instead", current)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	n, err := namespace(ctx, tx, name)
	if err != nil {
		return err
	}
	if n != nil {
		return clientErr(http.StatusConflict, wire.ErrConflict, "namespace %s is unavailable; choose another", name)
	}
	if err := createTenant(ctx, tx, name, "personal", user, "", name, s.now()); err != nil {
		return err
	}
	return s.db.audit(ctx, tx, user, "", "", "personal_namespace", name, s.now())
}

func (s *Server) apiChoosePersonal(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.PersonalNamespace
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid personal namespace")
		return
	}
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error { return s.choosePersonal(ctx, tx, c.user.ID, req.Name) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) apiNamespace(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	n, err := namespace(r.Context(), s.db.sql, strings.ToLower(r.PathValue("name")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if n == nil {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "namespace is available")
		return
	}
	if err := s.describeNamespace(r.Context(), n); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) describeNamespace(ctx context.Context, n *wire.Namespace) error {
	n.CreatedBy = n.Owner
	os, _, err := s.db.orgState(ctx, s.db.sql, n.Canonical)
	if err != nil {
		return err
	}
	if os == nil {
		return nil
	}
	n.Root = os.Root()
	for _, p := range os.ActiveAdmins() {
		if os.Owner(p.User) {
			n.Owners = append(n.Owners, p.User)
		}
	}
	if n.Kind == "team" {
		n.Owner = ""
	}
	return nil
}

func (s *Server) webChoosePersonal(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload and try again.")
		return
	}
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error { return s.choosePersonal(ctx, tx, ws.user.ID, r.PostForm.Get("namespace")) })
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	http.Redirect(w, r, "/orgs", http.StatusSeeOther)
}
