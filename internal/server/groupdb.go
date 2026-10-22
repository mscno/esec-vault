package server

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

func (d *DB) groupLinks(ctx context.Context, q queryer, group string) ([]*envelope.Envelope, error) {
	rows, err := q.QueryContext(ctx, `SELECT envelope FROM group_links WHERE group_id = ? ORDER BY seq`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*envelope.Envelope{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e envelope.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// groupCache holds verified group chains. Callers must not change what it
// returns.
type groupCache struct {
	mu sync.Mutex
	m  map[string]cachedGroup
}

type cachedGroup struct {
	head  string
	gs    *team.GroupState
	links []*envelope.Envelope
}

// groupState verifies a stored group chain, or returns the one verified at
// the same head before. It returns nil, nil for a group that does not
// exist. The state is shared: callers must not change it.
func (d *DB) groupState(ctx context.Context, q queryer, group string) (*team.GroupState, []*envelope.Envelope, error) {
	var head string
	err := q.QueryRowContext(ctx, `SELECT hash FROM group_links WHERE group_id = ? ORDER BY seq DESC LIMIT 1`, group).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	d.groups.mu.Lock()
	c, ok := d.groups.m[group]
	d.groups.mu.Unlock()
	if ok && c.head == head {
		return c.gs, c.links, nil
	}
	links, err := d.groupLinks(ctx, q, group)
	if err != nil {
		return nil, nil, err
	}
	if len(links) == 0 {
		return nil, nil, nil
	}
	gs, err := team.VerifyGroup(group, links, d.userChains(ctx, q))
	if err != nil {
		return nil, nil, fmt.Errorf("stored chain of group %s does not verify: %w", group, err)
	}
	d.groups.mu.Lock()
	if d.groups.m == nil {
		d.groups.m = map[string]cachedGroup{}
	}
	d.groups.m[group] = cachedGroup{head: gs.Head(), gs: gs, links: links}
	d.groups.mu.Unlock()
	return gs, links, nil
}

// addChains adds the user chains of users to out, for clients to verify
// signatures with.
func (d *DB) addChains(ctx context.Context, q queryer, out map[string][]*envelope.Envelope, users ...string) error {
	for _, u := range users {
		if _, ok := out[u]; ok || team.ValidCredID(u) == nil {
			continue
		}
		links, err := d.chainLinks(ctx, q, u, 0)
		if err != nil {
			return err
		}
		out[u] = links
	}
	return nil
}

// groupSigners lists everyone who signed a link of gs.
func groupSigners(gs *team.GroupState) []string {
	out := make([]string, 0, len(gs.Links))
	for _, l := range gs.Links {
		out = append(out, l.Signer)
	}
	return out
}

// mirrorGroup rewrites the admin, credential and access tables of a group
// from its verified state, and drops key grants that no longer apply.
func (d *DB) mirrorGroup(ctx context.Context, tx *sql.Tx, gs *team.GroupState, now time.Time) error {
	if err := mirrorGroupPeople(ctx, tx, gs); err != nil {
		return err
	}
	for _, c := range gs.Creds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_creds (group_id, id, kind, name, sign_pub, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(group_id, id) DO UPDATE SET active = excluded.active`, gs.Group, c.ID, c.Kind, c.Name, c.SignPub, c.Active, now.Unix()); err != nil {
			return err
		}
		if !c.Active {
			if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE group_id = ? AND to_id = ?`, gs.Group, c.ID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE group_id = ? AND version != ?`, gs.Group, gs.Key.Version); err != nil {
		return err
	}
	// A grant made by a token or admin no longer in the group no longer
	// verifies; dropping it lets an admin's device send a new one.
	grants, err := d.keyGrants(ctx, tx, gs.Group, "")
	if err != nil {
		return err
	}
	for _, g := range grants {
		kg, err := team.PeekKeyGrant(g.Env)
		if err != nil {
			continue
		}
		if c, ok := gs.Cred(kg.From); (ok && c.Kind == team.KindToken) || gs.Admin(kg.From) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE id = ?`, g.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_access WHERE group_id = ?`, gs.Group); err != nil {
		return err
	}
	for p, root := range gs.Access {
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_access (group_id, project, root) VALUES (?, ?, ?)`, gs.Group, p, root); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE machine_groups SET seq = ?, updated_at = ? WHERE id = ?`, gs.Seq, now.Unix(), gs.Group)
	return err
}

// mirrorGroupPeople mirrors a group's admins and members, and drops the key
// grants of those no longer in it. A member blocked on the web is unblocked
// once they leave or come back.
func mirrorGroupPeople(ctx context.Context, tx *sql.Tx, gs *team.GroupState) error {
	for _, a := range gs.Admins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_admins (group_id, user_id, login, active) VALUES (?, ?, ?, ?)
			ON CONFLICT(group_id, user_id) DO UPDATE SET login = excluded.login, active = excluded.active`, gs.Group, a.User, a.Login, a.Active); err != nil {
			return err
		}
		if !gs.HoldsKey(a.User) {
			if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE group_id = ? AND to_id = ?`, gs.Group, a.User); err != nil {
				return err
			}
		}
	}
	for _, m := range gs.Members {
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_members (group_id, user_id, login, active) VALUES (?, ?, ?, ?)
			ON CONFLICT(group_id, user_id) DO UPDATE SET login = excluded.login, active = excluded.active,
				suspended_at = CASE WHEN excluded.active != group_members.active THEN 0 ELSE group_members.suspended_at END`, gs.Group, m.User, m.Login, m.Active); err != nil {
			return err
		}
		if !gs.HoldsKey(m.User) {
			if _, err := tx.ExecContext(ctx, `DELETE FROM group_key_grants WHERE group_id = ? AND to_id = ?`, gs.Group, m.User); err != nil {
				return err
			}
		}
	}
	return nil
}

// mirrorProjectGroups rewrites the groups a project grants environments to.
func (d *DB) mirrorProjectGroups(ctx context.Context, tx *sql.Tx, st *team.State) error {
	for _, g := range st.Groups {
		envs, err := json.Marshal(g.Envs)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_groups (project, group_id, root, envs, active) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(project, group_id) DO UPDATE SET root = excluded.root, envs = excluded.envs, active = excluded.active`,
			st.Project, g.Group, g.Root, string(envs), g.Active); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) groupAudit(ctx context.Context, q queryer, group, actor, ip, action, detail string, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO group_audit (group_id, actor, ip, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`, group, actor, ip, action, detail, now.Unix())
	return err
}

// adminGroups lists the groups user is an active admin of.
func (d *DB) adminGroups(ctx context.Context, user string) ([]string, error) {
	var out []string
	err := scanAll(ctx, d.sql, `SELECT group_id FROM group_admins WHERE user_id = ? AND active = 1 ORDER BY group_id`, []any{user}, func(r *sql.Rows) error {
		var g string
		if err := r.Scan(&g); err != nil {
			return err
		}
		out = append(out, g)
		return nil
	})
	return out, err
}

// visibleGroups lists the groups user may read: those they administer or
// are a member of, and those that take keys from a project they are a
// member of. Only a group's
// admins choose those projects; a project granting a group environments
// does not make the group visible, since anyone can create a project.
func (d *DB) visibleGroups(ctx context.Context, user string) ([]string, error) {
	var out []string
	err := scanAll(ctx, d.sql, `SELECT group_id FROM group_admins WHERE user_id = ? AND active = 1
		UNION SELECT group_id FROM group_members WHERE user_id = ? AND active = 1
		UNION SELECT a.group_id FROM group_access a JOIN project_members m ON m.project = a.project WHERE m.user_id = ? AND m.active = 1
		ORDER BY 1`, []any{user, user, user}, func(r *sql.Rows) error {
		var g string
		if err := r.Scan(&g); err != nil {
			return err
		}
		out = append(out, g)
		return nil
	})
	return out, err
}

// allGroups lists every group id.
func (d *DB) allGroups(ctx context.Context) ([]string, error) {
	var out []string
	err := scanAll(ctx, d.sql, `SELECT id FROM machine_groups ORDER BY id`, nil, func(r *sql.Rows) error {
		var g string
		if err := r.Scan(&g); err != nil {
			return err
		}
		out = append(out, g)
		return nil
	})
	return out, err
}

// canReadGroup reports whether user may read a group's chain.
func (d *DB) canReadGroup(ctx context.Context, user, group string) (bool, error) {
	ids, err := d.visibleGroups(ctx, user)
	if err != nil {
		return false, err
	}
	for _, g := range ids {
		if g == group {
			return true, nil
		}
	}
	return false, nil
}

// keyGrantRow is a stored group key grant.
type keyGrantRow struct {
	ID      int64
	To      string
	Version uint64
	Env     *envelope.Envelope
}

func (d *DB) keyGrants(ctx context.Context, q queryer, group string, to string) ([]keyGrantRow, error) {
	where, args := `group_id = ?`, []any{group}
	if to != "" {
		where, args = where+` AND to_id = ?`, append(args, to)
	}
	rows, err := q.QueryContext(ctx, `SELECT id, to_id, version, envelope FROM group_key_grants WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyGrantRow
	for rows.Next() {
		var g keyGrantRow
		var raw []byte
		if err := rows.Scan(&g.ID, &g.To, &g.Version, &raw); err != nil {
			return nil, err
		}
		g.Env = &envelope.Envelope{}
		if err := json.Unmarshal(raw, g.Env); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// credRow is what the server alone knows of a machine or token.
type credRow struct {
	Kind      string
	SignPub   string
	Active    bool
	Suspended time.Time
	LastUsed  time.Time
	LastIP    string
	Uses      int
}

func (d *DB) credRows(ctx context.Context, group string) (map[string]credRow, error) {
	out := map[string]credRow{}
	err := scanAll(ctx, d.sql, `SELECT id, kind, sign_pub, active, suspended_at, last_used_at, last_ip, uses FROM group_creds WHERE group_id = ?`, []any{group}, func(r *sql.Rows) error {
		var id string
		var c credRow
		var susp, last int64
		if err := r.Scan(&id, &c.Kind, &c.SignPub, &c.Active, &susp, &last, &c.LastIP, &c.Uses); err != nil {
			return err
		}
		if susp > 0 {
			c.Suspended = fromUnix(susp)
		}
		c.LastUsed = fromUnix(last)
		out[id] = c
		return nil
	})
	return out, err
}

func (d *DB) credRow(ctx context.Context, group, id string) (*credRow, error) {
	var c credRow
	var susp, last int64
	err := d.sql.QueryRowContext(ctx, `SELECT kind, sign_pub, active, suspended_at, last_used_at, last_ip, uses FROM group_creds WHERE group_id = ? AND id = ?`, group, id).
		Scan(&c.Kind, &c.SignPub, &c.Active, &susp, &last, &c.LastIP, &c.Uses)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if susp > 0 {
		c.Suspended = fromUnix(susp)
	}
	c.LastUsed = fromUnix(last)
	return &c, nil
}

// pendingJoins lists a group's join requests that wait for approval.
func (d *DB) pendingJoins(ctx context.Context, group string, now time.Time) ([]wire.JoinRequest, error) {
	out := []wire.JoinRequest{}
	err := scanAll(ctx, d.sql, `SELECT id, machine_id, name, enc_pub, sign_pub, ip, created_at FROM group_joins WHERE group_id = ? AND status = ? AND expires_at > ? ORDER BY created_at`,
		[]any{group, wire.JoinPending, now.Unix()}, func(r *sql.Rows) error {
			var j wire.JoinRequest
			var at int64
			if err := r.Scan(&j.ID, &j.Machine, &j.Name, &j.EncPub, &j.SignPub, &j.IP, &at); err != nil {
				return err
			}
			j.Created = fromUnix(at)
			out = append(out, j)
			return nil
		})
	return out, err
}

// groupStatus reports the server's view of a group.
func (d *DB) groupStatus(ctx context.Context, gs *team.GroupState, now time.Time) (*wire.GroupStatus, error) {
	rows, err := d.credRows(ctx, gs.Group)
	if err != nil {
		return nil, err
	}
	grants, err := d.keyGrants(ctx, d.sql, gs.Group, "")
	if err != nil {
		return nil, err
	}
	chains := d.userChains(ctx, d.sql)
	has := map[string]bool{}
	for _, g := range grants {
		if g.Version != gs.Key.Version {
			continue
		}
		if gs.HoldsKey(g.To) {
			// Sealed to a person's earlier user key, it no longer opens.
			kg, err := team.PeekKeyGrant(g.Env)
			cs, cerr := chains(g.To)
			if err != nil || cerr != nil || kg.ToKey != cs.UKeyVersion || kg.ToEncPub != hex.EncodeToString(cs.EncPub[:]) {
				continue
			}
		}
		has[g.To] = true
	}
	out := &wire.GroupStatus{Seq: gs.Seq, Creds: []wire.CredStatus{}, AdminsWithKey: []string{}}
	for _, c := range gs.ActiveCreds("") {
		r := rows[c.ID]
		out.Creds = append(out.Creds, wire.CredStatus{ID: c.ID, HasKey: has[c.ID], Suspended: !r.Suspended.IsZero(), LastUsed: r.LastUsed, LastIP: r.LastIP, Uses: r.Uses})
	}
	for _, a := range gs.KeyHolders() {
		if has[a.User] {
			out.AdminsWithKey = append(out.AdminsWithKey, a.User)
		}
	}
	err = scanAll(ctx, d.sql, `SELECT user_id FROM group_members WHERE group_id = ? AND active = 1 AND suspended_at != 0`, []any{gs.Group}, func(r *sql.Rows) error {
		var u string
		if err := r.Scan(&u); err != nil {
			return err
		}
		out.BlockedMembers = append(out.BlockedMembers, u)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.Joins, err = d.pendingJoins(ctx, gs.Group, now); err != nil {
		return nil, err
	}
	if out.Changes, err = d.openChanges(ctx, wire.ScopeGroup, gs.Group); err != nil {
		return nil, err
	}
	return out, nil
}

// groupAuditRow is one group audit entry.
type groupAuditRow struct {
	Time   time.Time
	Actor  string
	IP     string
	Action string
	Detail string
}

func (d *DB) groupAuditPage(ctx context.Context, group string, limit int) ([]groupAuditRow, error) {
	var out []groupAuditRow
	err := scanAll(ctx, d.sql, `SELECT created_at, actor, ip, action, detail FROM group_audit WHERE group_id = ? ORDER BY id DESC LIMIT ?`, []any{group, limit}, func(r *sql.Rows) error {
		var e groupAuditRow
		var at int64
		if err := r.Scan(&at, &e.Actor, &e.IP, &e.Action, &e.Detail); err != nil {
			return err
		}
		e.Time = fromUnix(at)
		out = append(out, e)
		return nil
	})
	return out, err
}

// projectsGranting lists the projects whose chains grant group
// environments, as mirrored.
func (d *DB) projectsGranting(ctx context.Context, q queryer, group string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT project FROM project_groups WHERE group_id = ? AND active = 1 ORDER BY project`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
