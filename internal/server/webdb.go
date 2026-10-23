package server

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Queries behind the web pages. They read metadata only: nothing here can
// decrypt anything.

// auditRow is one audit entry, with its account for the admin pages.
type auditRow struct {
	ID       int64
	UserID   string
	DeviceID string
	IP       string
	Action   string
	Detail   string
	Time     time.Time
}

// auditFilter selects audit entries, newest first.
type auditFilter struct {
	// UserID limits entries to one account; AllUsers lifts the limit (the
	// admin pages).
	UserID   string
	AllUsers bool
	// Actions limits entries to these actions when not empty.
	Actions []string
	// Device limits entries to those by or about one device.
	Device string
	// Query keeps entries whose action, detail or address contains it.
	Query string
	// Before returns entries older than this id, for paging.
	Before int64
	Limit  int
}

func (d *DB) auditPage(ctx context.Context, f auditFilter) ([]auditRow, error) {
	var where []string
	var args []any
	if !f.AllUsers {
		where = append(where, "user_id = ?")
		args = append(args, f.UserID)
	}
	if len(f.Actions) > 0 {
		where = append(where, "action IN (?"+strings.Repeat(", ?", len(f.Actions)-1)+")")
		for _, a := range f.Actions {
			args = append(args, a)
		}
	}
	if f.Device != "" {
		// Entries by the device, or about it: suspensions and ended sessions
		// name it in full, approvals as "<id> via <method>".
		where = append(where, "(device_id = ? OR detail = ? OR substr(detail, 1, ?) = ?)")
		args = append(args, f.Device, f.Device, len(f.Device)+1, f.Device+" ")
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q) + "%"
		where = append(where, `(action LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	if f.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, f.Before)
	}
	q := `SELECT id, user_id, device_id, ip, action, detail, created_at FROM audit`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ") //nolint:gosec // constant clauses; values are parameters
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var e auditRow
		var created int64
		if err := rows.Scan(&e.ID, &e.UserID, &e.DeviceID, &e.IP, &e.Action, &e.Detail, &created); err != nil {
			return nil, err
		}
		e.Time = fromUnix(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

// vaultVersionRow describes one stored vault version, not its contents.
type vaultVersionRow struct {
	Version  uint64
	Size     int64
	SHA256   string
	PushedBy string
	Created  time.Time
	HasIndex bool
}

func (d *DB) vaultVersions(ctx context.Context, userID string) ([]vaultVersionRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT version, length(blob), sha256, pushed_by, created_at, coalesce(length(index_json), 0) > 0
		FROM vault_versions WHERE user_id = ? ORDER BY version DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vaultVersionRow
	for rows.Next() {
		var v vaultVersionRow
		var created int64
		if err := rows.Scan(&v.Version, &v.Size, &v.SHA256, &v.PushedBy, &created, &v.HasIndex); err != nil {
			return nil, err
		}
		v.Created = fromUnix(created)
		out = append(out, v)
	}
	return out, rows.Err()
}

// browserRow is one signed-in browser.
type browserRow struct {
	IDHash    string
	Created   time.Time
	Expires   time.Time
	UserAgent string
	IP        string
}

func (d *DB) browsers(ctx context.Context, userID string, now time.Time) ([]browserRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id_hash, created_at, expires_at, user_agent, ip FROM web_sessions
		WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`, userID, unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []browserRow
	for rows.Next() {
		var b browserRow
		var created, expires int64
		if err := rows.Scan(&b.IDHash, &created, &expires, &b.UserAgent, &b.IP); err != nil {
			return nil, err
		}
		b.Created, b.Expires = fromUnix(created), fromUnix(expires)
		out = append(out, b)
	}
	return out, rows.Err()
}

// cliSession is one live CLI session of a device.
type cliSession struct {
	Created  time.Time
	LastUsed time.Time
	Expires  time.Time
}

// liveSessions lists a device's sessions that still work: not revoked, not
// past their absolute lifetime and not idle for longer than idle.
func (d *DB) liveSessions(ctx context.Context, deviceID string, now time.Time, idle time.Duration) ([]cliSession, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT created_at, last_used_at, expires_at FROM sessions
		WHERE device_id = ? AND revoked_at = 0 AND expires_at > ? AND last_used_at > ? ORDER BY last_used_at DESC`,
		deviceID, unix(now), unix(now.Add(-idle)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cliSession
	for rows.Next() {
		var c cliSession
		var created, used, expires int64
		if err := rows.Scan(&created, &used, &expires); err != nil {
			return nil, err
		}
		c.Created, c.LastUsed = fromUnix(created), fromUnix(used)
		// A session ends at its absolute expiry or after idle time unused,
		// whichever comes first.
		c.Expires = fromUnix(min(expires, used+int64(idle/time.Second)))
		out = append(out, c)
	}
	return out, rows.Err()
}

// liveSessionCounts counts each device's live sessions for one account.
func (d *DB) liveSessionCounts(ctx context.Context, userID string, now time.Time, idle time.Duration) (map[string]int, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT device_id, COUNT(*) FROM sessions
		WHERE user_id = ? AND revoked_at = 0 AND expires_at > ? AND last_used_at > ? GROUP BY device_id`,
		userID, unix(now), unix(now.Add(-idle)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// deviceNames maps device ids to names, for one account or (userID "")
// every account.
func (d *DB) deviceNames(ctx context.Context, userID string) (map[string]string, error) {
	q, args := `SELECT id, name FROM devices WHERE user_id = ?`, []any{userID}
	if userID == "" {
		q, args = `SELECT id, name FROM devices`, nil
	}
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// ---- admin ----

// liveDevices leaves out registrations never confirmed and waiting devices
// whose approval window passed, as the account pages do. It takes the
// current time as its one parameter.
const liveDevices = `status != 'registering' AND NOT (status = 'pending' AND pending_expires <= ?)`

// serverStats are server-wide counts for the admin page.
type serverStats struct {
	Users          int
	Devices        map[string]int
	CLISessions    int
	WebSessions    int
	OpenSignIns    int
	DeniedSignIns  int
	VaultBytes     int64
	VaultVersions  int
	DatabaseBytes  int64
	AuditEntries   int
	OldestAuditAge time.Duration
}

func (d *DB) serverStats(ctx context.Context, now time.Time, idle time.Duration) (*serverStats, error) {
	st := &serverStats{Devices: map[string]int{}}
	counts := []struct {
		dst  *int
		q    string
		args []any
	}{
		{&st.Users, `SELECT COUNT(*) FROM users`, nil},
		{&st.CLISessions, `SELECT COUNT(*) FROM sessions WHERE revoked_at = 0 AND expires_at > ? AND last_used_at > ?`, []any{unix(now), unix(now.Add(-idle))}},
		{&st.WebSessions, `SELECT COUNT(*) FROM web_sessions WHERE expires_at > ?`, []any{unix(now)}},
		{&st.OpenSignIns, `SELECT COUNT(*) FROM oauth_states WHERE created_at > ?`, []any{unix(now.Add(-oauthStateTTL))}},
		{&st.DeniedSignIns, `SELECT COUNT(*) FROM audit WHERE action = 'login_denied' AND created_at > ?`, []any{unix(now.Add(-24 * time.Hour))}},
		{&st.VaultVersions, `SELECT COUNT(*) FROM vault_versions`, nil},
		{&st.AuditEntries, `SELECT COUNT(*) FROM audit`, nil},
	}
	for _, c := range counts {
		if err := d.sql.QueryRowContext(ctx, c.q, c.args...).Scan(c.dst); err != nil {
			return nil, err
		}
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT coalesce(SUM(length(blob)), 0) FROM vault_versions`).Scan(&st.VaultBytes); err != nil {
		return nil, err
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&st.DatabaseBytes); err != nil {
		return nil, err
	}
	var oldest sql.NullInt64
	if err := d.sql.QueryRowContext(ctx, `SELECT MIN(created_at) FROM audit`).Scan(&oldest); err != nil {
		return nil, err
	}
	if oldest.Valid {
		st.OldestAuditAge = now.Sub(fromUnix(oldest.Int64))
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT status, COUNT(*) FROM devices WHERE `+liveDevices+` GROUP BY status`, unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		st.Devices[status] = n
	}
	return st, rows.Err()
}

// accountSummary is one account as the admin page lists it.
type accountSummary struct {
	ID       string
	GitHubID int64
	Login    string
	// Known is false for an allowed id that never signed in.
	Known   bool
	Allowed bool
	Admin   bool
	Created time.Time
	// ChainSeq is 0 until the account is created from a device.
	ChainSeq     uint64
	Devices      map[string]int
	LastSeen     time.Time
	VaultVersion uint64
	VaultPushed  time.Time
	VaultBytes   int64
	Slots        int
}

func (d *DB) accountSummaries(ctx context.Context, now time.Time) (map[string]*accountSummary, error) {
	out := map[string]*accountSummary{}
	get := func(id string) *accountSummary {
		a, ok := out[id]
		if !ok {
			a = &accountSummary{ID: id, Devices: map[string]int{}}
			out[id] = a
		}
		return a
	}
	queries := []struct {
		q    string
		args []any
		scan func(*sql.Rows) error
	}{
		{`SELECT id, github_id, login, created_at FROM users`, nil, func(r *sql.Rows) error {
			var id, login string
			var gh, created int64
			if err := r.Scan(&id, &gh, &login, &created); err != nil {
				return err
			}
			a := get(id)
			a.GitHubID, a.Login, a.Known, a.Created = gh, login, true, fromUnix(created)
			return nil
		}},
		{`SELECT user_id, status, COUNT(*), MAX(last_seen_at) FROM devices WHERE user_id != '' AND ` + liveDevices + ` GROUP BY user_id, status`, []any{unix(now)}, func(r *sql.Rows) error {
			var id, status string
			var n int
			var seen int64
			if err := r.Scan(&id, &status, &n, &seen); err != nil {
				return err
			}
			a := get(id)
			a.Devices[status] = n
			if t := fromUnix(seen); t.After(a.LastSeen) {
				a.LastSeen = t
			}
			return nil
		}},
		{`SELECT user_id, MAX(version), MAX(created_at), SUM(length(blob)) FROM vault_versions GROUP BY user_id`, nil, func(r *sql.Rows) error {
			var id string
			var version uint64
			var created, size int64
			if err := r.Scan(&id, &version, &created, &size); err != nil {
				return err
			}
			a := get(id)
			a.VaultVersion, a.VaultPushed, a.VaultBytes = version, fromUnix(created), size
			return nil
		}},
		{`SELECT user_id, MAX(seq) FROM chain_links GROUP BY user_id`, nil, func(r *sql.Rows) error {
			var id string
			var seq uint64
			if err := r.Scan(&id, &seq); err != nil {
				return err
			}
			get(id).ChainSeq = seq
			return nil
		}},
		{`SELECT user_id, COUNT(*) FROM agent_slots WHERE disabled_at = 0 AND expires_at > ? GROUP BY user_id`, []any{unix(now)}, func(r *sql.Rows) error {
			var id string
			var n int
			if err := r.Scan(&id, &n); err != nil {
				return err
			}
			get(id).Slots = n
			return nil
		}},
	}
	for _, q := range queries {
		if err := scanAll(ctx, d.sql, q.q, q.args, q.scan); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func scanAll(ctx context.Context, db queryer, q string, args []any, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// userByID returns an account, or nil when there is none.
func (d *DB) userByID(ctx context.Context, id string) (*userRow, error) {
	u, err := d.user(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}
