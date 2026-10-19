package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// userChains returns a team.Chains that verifies user chains from the
// database, each at most once.
func (d *DB) userChains(ctx context.Context, q queryer) team.Chains {
	cache := map[string]*chain.State{}
	return func(user string) (*chain.State, error) {
		if st, ok := cache[user]; ok {
			return st, nil
		}
		links, err := d.chainLinks(ctx, q, user, 0)
		if err != nil {
			return nil, err
		}
		st, err := chain.Verify(user, links)
		if err != nil {
			return nil, fmt.Errorf("stored chain of %s does not verify: %w", user, err)
		}
		if st.Seq == 0 {
			return nil, fmt.Errorf("%s has no account", user)
		}
		cache[user] = st
		return st, nil
	}
}

func (d *DB) projectLinks(ctx context.Context, q queryer, project string, after uint64) ([]*envelope.Envelope, error) {
	rows, err := q.QueryContext(ctx, `SELECT envelope FROM project_links WHERE project = ? AND seq > ? ORDER BY seq`, project, after)
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

// projectState verifies a stored project chain. It returns nil, nil for a
// project that does not exist.
func (d *DB) projectState(ctx context.Context, q queryer, project string) (*team.State, []*envelope.Envelope, error) {
	links, err := d.projectLinks(ctx, q, project, 0)
	if err != nil {
		return nil, nil, err
	}
	if len(links) == 0 {
		return nil, nil, nil
	}
	st, err := team.Verify(project, links, d.userChains(ctx, q))
	if err != nil {
		return nil, nil, fmt.Errorf("stored chain of project %s does not verify: %w", project, err)
	}
	return st, links, nil
}

// signerChains returns the user chains of everyone who signed a link of st,
// for clients to verify the chain with.
func (d *DB) signerChains(ctx context.Context, q queryer, st *team.State) (map[string][]*envelope.Envelope, error) {
	out := map[string][]*envelope.Envelope{}
	for _, l := range st.Links {
		if _, ok := out[l.Signer]; ok {
			continue
		}
		links, err := d.chainLinks(ctx, q, l.Signer, 0)
		if err != nil {
			return nil, err
		}
		out[l.Signer] = links
	}
	return out, nil
}

// memberProjects lists the projects user is an active member of.
func (d *DB) memberProjects(ctx context.Context, user string) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT project FROM project_members WHERE user_id = ? AND active = 1 ORDER BY project`, user)
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

// allProjects lists every project id.
func (d *DB) allProjects(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id FROM projects ORDER BY id`)
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

// mirrorProject rewrites the member and machine tables of a project from
// its verified state.
func (d *DB) mirrorProject(ctx context.Context, tx *sql.Tx, st *team.State, now time.Time) error {
	for _, m := range st.Members {
		envs, err := json.Marshal(m.Envs)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_members (project, user_id, login, admin, envs, active) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(project, user_id) DO UPDATE SET login = excluded.login, admin = excluded.admin, envs = excluded.envs, active = excluded.active`,
			st.Project, m.User, m.Login, m.Admin, string(envs), m.Active); err != nil {
			return err
		}
	}
	for _, m := range st.Machines {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_machines (id, project, name, sign_pub, active, created_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET active = excluded.active WHERE project = excluded.project`,
			m.ID, st.Project, m.Name, m.SignPub, m.Active, now.Unix()); err != nil {
			return err
		}
	}
	// Grants and holdings of anyone who lost access are useless now.
	for holder := range holders(st, false) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM project_grants WHERE project = ? AND to_id = ?`, st.Project, holder); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM project_holdings WHERE project = ? AND holder = ?`, st.Project, holder); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE projects SET seq = ?, updated_at = ? WHERE id = ?`, st.Seq, now.Unix(), st.Project)
	return err
}

// holders returns the members and machines of st that are active (or, with
// active false, inactive).
func holders(st *team.State, active bool) map[string]bool {
	out := map[string]bool{}
	for id, m := range st.Members {
		if m.Active == active {
			out[id] = true
		}
	}
	for id, m := range st.Machines {
		if m.Active == active {
			out[id] = true
		}
	}
	return out
}

func (d *DB) projectAudit(ctx context.Context, q queryer, project, actor, ip, action, detail string, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO project_audit (project, actor, ip, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`, project, actor, ip, action, detail, now.Unix())
	return err
}

// grantRow is a stored grant.
type grantRow struct {
	ID      int64
	Project string
	To      string
	Version uint64
	Envs    []team.Env
	Env     *envelope.Envelope
	Created time.Time
}

func (d *DB) grants(ctx context.Context, q queryer, where string, args ...any) ([]grantRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, project, to_id, to_ukey_version, envs, envelope, created_at FROM project_grants WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []grantRow
	for rows.Next() {
		var g grantRow
		var envs string
		var raw []byte
		var created int64
		if err := rows.Scan(&g.ID, &g.Project, &g.To, &g.Version, &envs, &raw, &created); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(envs), &g.Envs); err != nil {
			return nil, err
		}
		g.Env = &envelope.Envelope{}
		if err := json.Unmarshal(raw, g.Env); err != nil {
			return nil, err
		}
		g.Created = fromUnix(created)
		out = append(out, g)
	}
	return out, rows.Err()
}

// projectStatus computes key delivery for every active holder of st.
func (d *DB) projectStatus(ctx context.Context, st *team.State) (*wire.ProjectStatus, error) {
	held, err := d.holdings(ctx, st.Project)
	if err != nil {
		return nil, err
	}
	grants, err := d.grants(ctx, d.sql, `project = ?`, st.Project)
	if err != nil {
		return nil, err
	}
	chains := d.userChains(ctx, d.sql)
	out := &wire.ProjectStatus{Seq: st.Seq, Holders: []wire.HolderStatus{}}
	waiting := func(holder string, version uint64, env team.Env) bool {
		for _, g := range grants {
			if g.To != holder || g.Version != version {
				continue
			}
			for _, e := range g.Envs {
				if e == env {
					return true
				}
			}
		}
		return false
	}
	for _, m := range st.ActiveMembers() {
		h := wire.HolderStatus{ID: m.User, Kind: "member", Envs: map[string]string{}}
		if cs, err := chains(m.User); err == nil {
			h.UKeyVersion = cs.UKeyVersion
		}
		for _, n := range st.Access(m.User) {
			cur := st.Envs[n].Env
			switch {
			case held[m.User][n] == cur.PublicKey:
				h.Envs[n] = wire.KeyHeld
			case h.UKeyVersion > 0 && waiting(m.User, h.UKeyVersion, cur):
				h.Envs[n] = wire.KeyWaiting
			default:
				h.Envs[n] = wire.KeyMissing
			}
		}
		out.Holders = append(out.Holders, h)
	}
	used, err := d.machineUse(ctx, st.Project)
	if err != nil {
		return nil, err
	}
	for _, m := range st.ActiveMachines() {
		h := wire.HolderStatus{ID: m.ID, Kind: "machine", Envs: map[string]string{}, LastUsed: used[m.ID].last}
		for _, n := range m.Envs {
			h.Envs[n] = wire.KeyMissing
			if waiting(m.ID, 0, st.Envs[n].Env) {
				h.Envs[n] = wire.KeyHeld
			}
		}
		out.Holders = append(out.Holders, h)
	}
	return out, nil
}

// holdings maps holders to the public keys they hold, by environment.
func (d *DB) holdings(ctx context.Context, project string) (map[string]map[string]string, error) {
	held := map[string]map[string]string{}
	err := scanAll(ctx, d.sql, `SELECT holder, env, public_key FROM project_holdings WHERE project = ?`, []any{project}, func(r *sql.Rows) error {
		var h, env, pub string
		if err := r.Scan(&h, &env, &pub); err != nil {
			return err
		}
		if held[h] == nil {
			held[h] = map[string]string{}
		}
		held[h][env] = pub
		return nil
	})
	return held, err
}

type machineUse struct {
	last time.Time
	ip   string
	uses int
}

func (d *DB) machineUse(ctx context.Context, project string) (map[string]machineUse, error) {
	out := map[string]machineUse{}
	err := scanAll(ctx, d.sql, `SELECT id, last_used_at, last_ip, uses FROM project_machines WHERE project = ?`, []any{project}, func(r *sql.Rows) error {
		var id string
		var last int64
		var u machineUse
		if err := r.Scan(&id, &last, &u.ip, &u.uses); err != nil {
			return err
		}
		u.last = fromUnix(last)
		out[id] = u
		return nil
	})
	return out, err
}

// accountProof returns a stored account proof, or nil.
func (d *DB) accountProof(ctx context.Context, user string) (*wire.AccountProof, error) {
	p := &wire.AccountProof{User: user}
	err := d.sql.QueryRowContext(ctx, `SELECT login, root, signature FROM account_proofs WHERE user_id = ?`, user).Scan(&p.Login, &p.Root, &p.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// userByLogin finds an account by GitHub login, ignoring case.
func (d *DB) userByLogin(ctx context.Context, login string) (*userRow, error) {
	u := &userRow{}
	err := d.sql.QueryRowContext(ctx, `SELECT id, github_id, login FROM users WHERE lower(login) = lower(?) ORDER BY created_at DESC LIMIT 1`, login).Scan(&u.ID, &u.GitHubID, &u.Login)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// projectAuditRow is one project audit entry.
type projectAuditRow struct {
	ID     int64
	Time   time.Time
	Actor  string
	IP     string
	Action string
	Detail string
}

func (d *DB) projectAuditPage(ctx context.Context, project string, limit int) ([]projectAuditRow, error) {
	var out []projectAuditRow
	err := scanAll(ctx, d.sql, `SELECT id, created_at, actor, ip, action, detail FROM project_audit WHERE project = ? ORDER BY id DESC LIMIT ?`, []any{project, limit}, func(r *sql.Rows) error {
		var e projectAuditRow
		var at int64
		if err := r.Scan(&e.ID, &at, &e.Actor, &e.IP, &e.Action, &e.Detail); err != nil {
			return err
		}
		e.Time = fromUnix(at)
		out = append(out, e)
		return nil
	})
	return out, err
}

// logins maps user ids to logins.
func (d *DB) logins(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	err := scanAll(ctx, d.sql, `SELECT id, login FROM users`, nil, func(r *sql.Rows) error {
		var id, login string
		if err := r.Scan(&id, &login); err != nil {
			return err
		}
		out[id] = login
		return nil
	})
	return out, err
}

// envList formats environment names for people.
func envList(envs []string) string {
	if len(envs) == 0 {
		return "no environments"
	}
	s := append([]string(nil), envs...)
	sort.Strings(s)
	return strings.Join(s, ", ")
}
