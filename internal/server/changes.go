package server

// Web changes. The web pages cannot sign links: the server holds no key.
// A change made on a page (who reads what, a member to add or remove, a
// machine to remove) is stored here until an admin's device shows it to its
// person and signs it (esec vault changes). A malicious server can invent
// changes, so devices never sign one without asking, and the web pages only
// take changes from the admins who could sign them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// openChanges lists the open changes of a group or project, with the names
// of the machines and tokens they remove.
func (d *DB) openChanges(ctx context.Context, scope, target string) ([]wire.Change, error) {
	cs, err := d.changesWhere(ctx, `scope = ? AND target = ? AND status = 'open'`, scope, target)
	if err != nil || scope != wire.ScopeGroup {
		return cs, err
	}
	for i, c := range cs {
		if c.Kind != wire.ChangeRemove {
			continue
		}
		if r, err := d.credName(ctx, target, c.Subject); err == nil {
			cs[i].Name = r
		}
	}
	return cs, nil
}

// credName returns the name of a group's machine or token.
func (d *DB) credName(ctx context.Context, group, id string) (string, error) {
	var name string
	err := d.sql.QueryRowContext(ctx, `SELECT name FROM group_creds WHERE group_id = ? AND id = ?`, group, id).Scan(&name)
	return name, err
}

func (d *DB) changesWhere(ctx context.Context, where string, args ...any) ([]wire.Change, error) {
	logins, err := d.logins(ctx)
	if err != nil {
		return nil, err
	}
	out := []wire.Change{}
	err = scanAll(ctx, d.sql, `SELECT id, scope, target, kind, project, envs, subject, admin, data, created_by, created_at FROM changes WHERE `+where+` ORDER BY id`, args, func(r *sql.Rows) error {
		var c wire.Change
		var envs, data, by string
		var at int64
		if err := r.Scan(&c.ID, &c.Scope, &c.Target, &c.Kind, &c.Project, &envs, &c.Subject, &c.Admin, &data, &by, &at); err != nil {
			return err
		}
		if data != "" {
			c.Data = json.RawMessage(data)
		}
		if err := json.Unmarshal([]byte(envs), &c.Envs); err != nil {
			return err
		}
		c.By, c.Created = logins[by], fromUnix(at)
		if c.By == "" {
			c.By = by
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

// adminChanges lists the open changes in the person's own account and in
// the groups and projects they administer: the ones their devices can sign.
func (s *Server) adminChanges(ctx context.Context, user string) ([]wire.Change, error) {
	out, err := s.db.openChanges(ctx, wire.ScopeAccount, user)
	if err != nil {
		return nil, err
	}
	groups, err := s.db.adminGroups(ctx, user)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		cs, err := s.db.openChanges(ctx, wire.ScopeGroup, g)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	projects, err := s.db.memberProjects(ctx, user)
	if err != nil {
		return nil, err
	}
	for _, p := range projects {
		st, err := s.listedProject(ctx, p)
		if err != nil {
			return nil, err
		}
		if st == nil || !st.Admin(user) {
			continue
		}
		cs, err := s.db.openChanges(ctx, wire.ScopeProject, p)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	return out, nil
}

// changeAdmins returns the admins of a change's group or project: who may
// sign or close it.
func (s *Server) changeAdmins(ctx context.Context, scope, target string) ([]string, error) {
	switch scope {
	case wire.ScopeAccount:
		return []string{target}, nil
	case wire.ScopeGroup:
		gs, err := s.listedGroup(ctx, target)
		if err != nil || gs == nil {
			return nil, err
		}
		var out []string
		for _, a := range gs.ActiveAdmins() {
			out = append(out, a.User)
		}
		return out, nil
	case wire.ScopeProject:
		st, err := s.listedProject(ctx, target)
		if err != nil || st == nil {
			return nil, err
		}
		return adminIDs(st), nil
	}
	return nil, nil
}

func (s *Server) apiChanges(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	cs, err := s.adminChanges(r.Context(), c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.Changes{Changes: cs})
}

func (s *Server) apiCloseChange(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.ChangeClose
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid change id")
		return
	}
	if err := s.closeChange(r.Context(), id, req.Applied, c.user.ID, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// closeChange marks a change applied or dismissed, for an admin of its
// group or project. A dismissed removal lets the machine back in.
func (s *Server) closeChange(ctx context.Context, id int64, applied bool, user, ip string) error {
	var scope, target, kind, subject string
	err := s.db.sql.QueryRowContext(ctx, `SELECT scope, target, kind, subject FROM changes WHERE id = ? AND status = 'open'`, id).Scan(&scope, &target, &kind, &subject)
	if errors.Is(err, sql.ErrNoRows) {
		return clientErr(http.StatusNotFound, wire.ErrNotFound, "no open change %d", id)
	}
	if err != nil {
		return err
	}
	admins, err := s.changeAdmins(ctx, scope, target)
	if err != nil {
		return err
	}
	if !contains(admins, user) {
		return clientErr(http.StatusNotFound, wire.ErrNotFound, "no open change %d", id)
	}
	now := s.now()
	status := "dismissed"
	if applied {
		status = "applied"
	}
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE changes SET status = ?, closed_at = ? WHERE id = ?`, status, now.Unix(), id); err != nil {
			return err
		}
		if scope == wire.ScopeGroup && kind == wire.ChangeRemove && !applied {
			if _, err := tx.ExecContext(ctx, `UPDATE group_creds SET suspended_at = 0 WHERE group_id = ? AND id = ?`, target, subject); err != nil {
				return err
			}
		}
		return s.changeAudit(ctx, tx, scope, target, user, ip, "change_"+status, kind+" "+subject, now)
	})
}

func (s *Server) changeAudit(ctx context.Context, q queryer, scope, target, user, ip, action, detail string, now time.Time) error {
	switch scope {
	case wire.ScopeAccount:
		return s.db.audit(ctx, q, target, "", ip, action, detail, now)
	case wire.ScopeGroup:
		return s.db.groupAudit(ctx, q, target, user, ip, action, detail, now)
	}
	return s.db.projectAudit(ctx, q, target, user, ip, action, detail, now)
}

// propose stores a web change for an admin's device to sign, unless the
// same one waits already, and wakes the admins. A newer change of the same
// kind to the same project, member or machine replaces an older one.
func (s *Server) propose(ctx context.Context, user, ip string, c wire.Change) error {
	envs, err := json.Marshal(team.SortEnvs(c.Envs))
	if err != nil {
		return err
	}
	admins, err := s.changeAdmins(ctx, c.Scope, c.Target)
	if err != nil {
		return err
	}
	now := s.now()
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		var n, same int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(kind = ? AND project = ? AND envs = ? AND subject = ? AND admin = ?), 0) FROM changes WHERE scope = ? AND target = ? AND status = 'open'`,
			c.Kind, c.Project, string(envs), c.Subject, c.Admin, c.Scope, c.Target).Scan(&n, &same); err != nil {
			return err
		}
		if same > 0 {
			return nil
		}
		if n >= maxOpenProposals {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many changes wait to be signed; sign or dismiss some first (esec vault changes)")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE changes SET status = 'dismissed', closed_at = ? WHERE scope = ? AND target = ? AND status = 'open' AND kind = ? AND project = ? AND subject = ?`,
			now.Unix(), c.Scope, c.Target, c.Kind, c.Project, c.Subject); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO changes (scope, target, kind, project, envs, subject, admin, data, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.Scope, c.Target, c.Kind, c.Project, string(envs), c.Subject, c.Admin, string(c.Data), user, now.Unix()); err != nil {
			return err
		}
		if err := s.changeAudit(ctx, tx, c.Scope, c.Target, user, ip, "change_proposed", c.Kind+" "+c.Project+c.Subject, now); err != nil {
			return err
		}
		for _, a := range admins {
			typ := wire.EventGroup
			if c.Scope != wire.ScopeGroup {
				typ = wire.EventProject
			}
			if err := s.db.addEvent(ctx, tx, a, typ, c.Target, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		for _, a := range admins {
			s.notify.wake(a)
		}
	}
	return err
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
