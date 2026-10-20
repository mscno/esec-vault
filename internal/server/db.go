package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // database/sql driver

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/wire"
)

const schemaVersion = 1

var schema = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		github_id INTEGER UNIQUE NOT NULL,
		login TEXT NOT NULL,
		created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL,
		platform TEXT NOT NULL,
		enc_pub TEXT NOT NULL,
		sign_pub TEXT NOT NULL,
		status TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT '',
		proof BLOB,
		created_at INTEGER NOT NULL,
		pending_expires INTEGER NOT NULL DEFAULT 0,
		last_seen_at INTEGER NOT NULL DEFAULT 0,
		last_ip TEXT NOT NULL DEFAULT '',
		register_ip TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id)`,
	`CREATE INDEX IF NOT EXISTS devices_status_created ON devices(status, created_at)`,
	`CREATE INDEX IF NOT EXISTS devices_sign_pub ON devices(sign_pub)`,
	`CREATE TABLE IF NOT EXISTS known_browsers (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS device_codes (
		device_code_hash TEXT PRIMARY KEY,
		user_code_hash TEXT UNIQUE NOT NULL,
		device_id TEXT NOT NULL,
		user_id TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		last_poll INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		revoked_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id)`,
	`CREATE TABLE IF NOT EXISTS nonces (
		device_id TEXT NOT NULL,
		nonce TEXT NOT NULL,
		seen_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, nonce))`,
	`CREATE TABLE IF NOT EXISTS chain_links (
		user_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		hash TEXT NOT NULL,
		envelope BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (user_id, seq))`,
	`CREATE TABLE IF NOT EXISTS device_boxes (
		device_id TEXT NOT NULL,
		ukey_version INTEGER NOT NULL,
		box BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, ukey_version))`,
	`CREATE TABLE IF NOT EXISTS identity_blobs (
		user_id TEXT NOT NULL,
		ukey_version INTEGER NOT NULL,
		blob BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (user_id, ukey_version))`,
	`CREATE TABLE IF NOT EXISTS vault_versions (
		user_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		blob BLOB NOT NULL,
		sig BLOB NOT NULL,
		index_json BLOB,
		sha256 TEXT NOT NULL,
		pushed_by TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (user_id, version))`,
	`CREATE TABLE IF NOT EXISTS agent_slots (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		ssh_key_fp TEXT NOT NULL,
		salt BLOB NOT NULL,
		box BLOB NOT NULL,
		ukey_version INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		disabled_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS web_sessions (
		id_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		csrf TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		user_agent TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS web_sessions_user ON web_sessions(user_id)`,
	`CREATE TABLE IF NOT EXISTS oauth_states (
		state_hash TEXT PRIMARY KEY,
		verifier TEXT NOT NULL,
		next TEXT NOT NULL,
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS oauth_states_created ON oauth_states(created_at)`,
	`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		type TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS events_user ON events(user_id, id)`,
	`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, id)`,
	`CREATE INDEX IF NOT EXISTS audit_created ON audit(created_at)`,
	// alert_outbox queues alerts until they are delivered; see alerts.go.
	`CREATE TABLE IF NOT EXISTS alert_outbox (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL,
		channel TEXT NOT NULL,
		recipient TEXT NOT NULL DEFAULT '',
		payload BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		next_at INTEGER NOT NULL,
		sent_at INTEGER NOT NULL DEFAULT 0,
		failed_at INTEGER NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS alert_outbox_due ON alert_outbox(sent_at, failed_at, next_at)`,
	// Shared projects; see teamapi.go. project_links is the signed chain;
	// members and machines mirror its verified state for queries.
	`CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		seq INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS project_links (
		project TEXT NOT NULL,
		seq INTEGER NOT NULL,
		hash TEXT NOT NULL,
		envelope BLOB NOT NULL,
		signer TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (project, seq))`,
	`CREATE TABLE IF NOT EXISTS project_members (
		project TEXT NOT NULL,
		user_id TEXT NOT NULL,
		login TEXT NOT NULL,
		admin INTEGER NOT NULL,
		envs TEXT NOT NULL,
		active INTEGER NOT NULL,
		PRIMARY KEY (project, user_id))`,
	`CREATE INDEX IF NOT EXISTS project_members_user ON project_members(user_id)`,
	`CREATE TABLE IF NOT EXISTS project_machines (
		id TEXT PRIMARY KEY,
		project TEXT NOT NULL,
		name TEXT NOT NULL,
		sign_pub TEXT NOT NULL,
		active INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		last_ip TEXT NOT NULL DEFAULT '',
		uses INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX IF NOT EXISTS project_machines_project ON project_machines(project)`,
	`CREATE TABLE IF NOT EXISTS project_grants (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project TEXT NOT NULL,
		to_id TEXT NOT NULL,
		to_ukey_version INTEGER NOT NULL,
		envs TEXT NOT NULL,
		envelope BLOB NOT NULL,
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS project_grants_to ON project_grants(to_id, id)`,
	`CREATE INDEX IF NOT EXISTS project_grants_project ON project_grants(project)`,
	`CREATE TABLE IF NOT EXISTS project_holdings (
		project TEXT NOT NULL,
		holder TEXT NOT NULL,
		env TEXT NOT NULL,
		public_key TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (project, holder, env))`,
	`CREATE TABLE IF NOT EXISTS project_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project TEXT NOT NULL,
		actor TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS project_audit_project ON project_audit(project, id)`,
	`CREATE TABLE IF NOT EXISTS account_proofs (
		user_id TEXT PRIMARY KEY,
		login TEXT NOT NULL,
		root TEXT NOT NULL,
		signature TEXT NOT NULL,
		created_at INTEGER NOT NULL)`,
	// Machine groups; see groupapi.go. group_links is the signed chain; the
	// other tables mirror its verified state, or hold what the server alone
	// knows: key grants waiting, join requests, use, web changes to sign.
	`CREATE TABLE IF NOT EXISTS machine_groups (
		id TEXT PRIMARY KEY,
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		seq INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS group_links (
		group_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		hash TEXT NOT NULL,
		envelope BLOB NOT NULL,
		signer TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (group_id, seq))`,
	`CREATE TABLE IF NOT EXISTS group_admins (
		group_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		login TEXT NOT NULL,
		active INTEGER NOT NULL,
		PRIMARY KEY (group_id, user_id))`,
	`CREATE INDEX IF NOT EXISTS group_admins_user ON group_admins(user_id)`,
	`CREATE TABLE IF NOT EXISTS group_creds (
		group_id TEXT NOT NULL,
		id TEXT NOT NULL,
		kind TEXT NOT NULL,
		name TEXT NOT NULL,
		sign_pub TEXT NOT NULL,
		active INTEGER NOT NULL,
		suspended_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		last_ip TEXT NOT NULL DEFAULT '',
		uses INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (group_id, id))`,
	`CREATE TABLE IF NOT EXISTS group_access (
		group_id TEXT NOT NULL,
		project TEXT NOT NULL,
		root TEXT NOT NULL,
		PRIMARY KEY (group_id, project))`,
	`CREATE INDEX IF NOT EXISTS group_access_project ON group_access(project)`,
	`CREATE TABLE IF NOT EXISTS project_groups (
		project TEXT NOT NULL,
		group_id TEXT NOT NULL,
		root TEXT NOT NULL,
		envs TEXT NOT NULL,
		active INTEGER NOT NULL,
		PRIMARY KEY (project, group_id))`,
	`CREATE INDEX IF NOT EXISTS project_groups_group ON project_groups(group_id)`,
	`CREATE TABLE IF NOT EXISTS group_key_grants (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id TEXT NOT NULL,
		to_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		envelope BLOB NOT NULL,
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS group_key_grants_to ON group_key_grants(group_id, to_id)`,
	`CREATE TABLE IF NOT EXISTS group_joins (
		id TEXT PRIMARY KEY,
		group_id TEXT NOT NULL,
		machine_id TEXT NOT NULL,
		name TEXT NOT NULL,
		enc_pub TEXT NOT NULL,
		sign_pub TEXT NOT NULL,
		ip TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS group_joins_group ON group_joins(group_id, status)`,
	`CREATE TABLE IF NOT EXISTS group_proposals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id TEXT NOT NULL,
		kind TEXT NOT NULL,
		project TEXT NOT NULL DEFAULT '',
		envs TEXT NOT NULL DEFAULT '[]',
		cred_id TEXT NOT NULL DEFAULT '',
		created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'open',
		closed_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX IF NOT EXISTS group_proposals_group ON group_proposals(group_id, status)`,
	`CREATE TABLE IF NOT EXISTS group_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id TEXT NOT NULL,
		actor TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS group_audit_group ON group_audit(group_id, id)`,
	`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`,
}

var addedColumns = []struct{ table, column, def string }{
	{"web_sessions", "user_agent", "TEXT NOT NULL DEFAULT ''"},
	{"web_sessions", "ip", "TEXT NOT NULL DEFAULT ''"},
	// The confirmed address for alert emails, and one waiting for its
	// owner to open the confirmation link.
	{"users", "alert_email", "TEXT NOT NULL DEFAULT ''"},
	{"users", "alert_email_pending", "TEXT NOT NULL DEFAULT ''"},
	{"users", "alert_email_token", "TEXT NOT NULL DEFAULT ''"},
	{"users", "alert_email_expires", "INTEGER NOT NULL DEFAULT 0"},
}

// addColumn adds a column to a table unless it is already there.
func addColumn(db *sql.DB, table, column, def string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + def)
	return err
}

// DB wraps the SQLite database. One connection serializes all access, which
// keeps transactions simple and is ample for a personal or small-team server.
type DB struct {
	sql *sql.DB
	// groups caches verified group chains by their head, since machines
	// and pages read them far more often than they change.
	groups groupCache
}

// OpenDB opens (and migrates) the database at path.
func OpenDB(path string) (*DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	// Columns added after schema 1. They have defaults, so servers that
	// predate them can still open the database after a rollback.
	for _, c := range addedColumns {
		if err := addColumn(db, c.table, c.column, c.def); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	var v int
	err = db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, schemaVersion); err != nil {
			db.Close()
			return nil, err
		}
	case err != nil:
		db.Close()
		return nil, err
	case v > schemaVersion:
		db.Close()
		return nil, fmt.Errorf("database schema %d is newer than this server (%d)", v, schemaVersion)
	}
	if err := os0600(path); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{sql: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the underlying database for operations tooling and tests that
// simulate a misbehaving server.
func (d *DB) SQL() *sql.DB { return d.sql }

// Cleanup runs the periodic cleanup once (operations tooling and tests).
func (d *DB) Cleanup(ctx context.Context, now time.Time) error { return d.cleanup(ctx, now) }

// tx runs fn in a transaction.
func (d *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// A panic must not leave the only connection inside a transaction.
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

// ---- users ----

type userRow struct {
	ID       string
	GitHubID int64
	Login    string
}

func (u userRow) wire() wire.User { return wire.User{ID: u.ID, GitHubID: u.GitHubID, Login: u.Login} }

func userID(githubID int64) string { return fmt.Sprintf("gh:%d", githubID) }

func (d *DB) upsertUser(ctx context.Context, githubID int64, login string, now time.Time) (*userRow, error) {
	id := userID(githubID)
	_, err := d.sql.ExecContext(ctx, `INSERT INTO users (id, github_id, login, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET login = excluded.login`, id, githubID, login, unix(now))
	if err != nil {
		return nil, err
	}
	return &userRow{ID: id, GitHubID: githubID, Login: login}, nil
}

func (d *DB) user(ctx context.Context, id string) (*userRow, error) {
	var u userRow
	err := d.sql.QueryRowContext(ctx, `SELECT id, github_id, login FROM users WHERE id = ?`, id).Scan(&u.ID, &u.GitHubID, &u.Login)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ---- devices ----

type deviceRow struct {
	ID             string
	UserID         string
	Name           string
	Platform       string
	EncPub         string
	SignPub        string
	Status         string
	Method         string
	Proof          []byte
	Created        time.Time
	PendingExpires time.Time
	LastSeen       time.Time
	LastIP         string
	RegisterIP     string
}

const deviceCols = `id, user_id, name, platform, enc_pub, sign_pub, status, method, proof, created_at, pending_expires, last_seen_at, last_ip, register_ip`

type scanner interface{ Scan(dest ...any) error }

func scanDevice(s scanner) (*deviceRow, error) {
	var r deviceRow
	var created, pending, seen int64
	if err := s.Scan(&r.ID, &r.UserID, &r.Name, &r.Platform, &r.EncPub, &r.SignPub, &r.Status, &r.Method, &r.Proof, &created, &pending, &seen, &r.LastIP, &r.RegisterIP); err != nil {
		return nil, err
	}
	r.Created, r.PendingExpires, r.LastSeen = fromUnix(created), fromUnix(pending), fromUnix(seen)
	return &r, nil
}

func (r *deviceRow) wire(withProof bool) wire.DeviceInfo {
	info := wire.DeviceInfo{ID: r.ID, Name: r.Name, Platform: r.Platform, EncPub: r.EncPub, SignPub: r.SignPub, Status: r.Status, Method: r.Method, Created: r.Created, LastSeen: r.LastSeen, LastIP: r.LastIP}
	if withProof && len(r.Proof) > 0 {
		var e envelope.Envelope
		if err := jsonUnmarshal(r.Proof, &e); err == nil {
			info.Proof = &e
		}
	}
	return info
}

func (d *DB) device(ctx context.Context, q queryer, id string) (*deviceRow, error) {
	return scanDevice(q.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
}

func (d *DB) devicesOf(ctx context.Context, q queryer, userID string) ([]*deviceRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE user_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*deviceRow
	for rows.Next() {
		r, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ---- chain ----

func (d *DB) chainLinks(ctx context.Context, q queryer, userID string, after uint64) ([]*envelope.Envelope, error) {
	rows, err := q.QueryContext(ctx, `SELECT envelope FROM chain_links WHERE user_id = ? AND seq > ? ORDER BY seq`, userID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*envelope.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e envelope.Envelope
		if err := jsonUnmarshal(raw, &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// firstLink returns the first link of a user's chain, or nil.
func (d *DB) firstLink(ctx context.Context, userID string) (*envelope.Envelope, error) {
	var raw []byte
	err := d.sql.QueryRowContext(ctx, `SELECT envelope FROM chain_links WHERE user_id = ? AND seq = 1`, userID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e envelope.Envelope
	if err := jsonUnmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) chainSeq(ctx context.Context, q queryer, userID string) (uint64, error) {
	var seq sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT MAX(seq) FROM chain_links WHERE user_id = ?`, userID).Scan(&seq); err != nil {
		return 0, err
	}
	if !seq.Valid || seq.Int64 < 0 {
		return 0, nil
	}
	return uint64(seq.Int64), nil
}

// ---- events and audit ----

func (d *DB) addEvent(ctx context.Context, q queryer, userID, typ, detail string, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO events (user_id, type, detail, created_at) VALUES (?, ?, ?, ?)`, userID, typ, detail, unix(now))
	return err
}

func (d *DB) events(ctx context.Context, userID string, after int64) ([]wire.Event, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, type, detail, created_at FROM events WHERE user_id = ? AND id > ? ORDER BY id LIMIT 100`, userID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.Event
	for rows.Next() {
		var e wire.Event
		var created int64
		if err := rows.Scan(&e.ID, &e.Type, &e.Detail, &created); err != nil {
			return nil, err
		}
		e.Created = fromUnix(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) lastEventID(ctx context.Context, userID string) (int64, error) {
	var id sql.NullInt64
	err := d.sql.QueryRowContext(ctx, `SELECT MAX(id) FROM events WHERE user_id = ?`, userID).Scan(&id)
	return id.Int64, err
}

func (d *DB) audit(ctx context.Context, q queryer, userID, deviceID, ip, action, detail string, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO audit (user_id, device_id, ip, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`, userID, deviceID, ip, action, detail, unix(now))
	return err
}

func (d *DB) auditEntries(ctx context.Context, userID string, limit int) ([]wire.AuditEntry, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, device_id, ip, action, detail, created_at FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.AuditEntry
	for rows.Next() {
		var e wire.AuditEntry
		var created int64
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.IP, &e.Action, &e.Detail, &created); err != nil {
			return nil, err
		}
		e.Time = fromUnix(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

// auditKeep is the most audit entries kept per account.
const auditKeep = 10000

// cleanup removes expired short-lived rows.
func (d *DB) cleanup(ctx context.Context, now time.Time) error {
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM nonces WHERE seen_at < ?`, []any{unix(now.Add(-10 * time.Minute))}},
		{`DELETE FROM device_codes WHERE expires_at < ?`, []any{unix(now.Add(-time.Hour))}},
		{`DELETE FROM oauth_states WHERE created_at < ?`, []any{unix(now.Add(-time.Hour))}},
		{`DELETE FROM web_sessions WHERE expires_at < ?`, []any{unix(now)}},
		{`DELETE FROM known_browsers WHERE expires_at < ?`, []any{unix(now)}},
		{`DELETE FROM sessions WHERE expires_at < ? OR (revoked_at > 0 AND revoked_at < ?)`, []any{unix(now), unix(now.Add(-24 * time.Hour))}},
		// Unconfirmed registrations are useless once their code expired.
		{`DELETE FROM devices WHERE status = 'registering' AND created_at < ?`, []any{unix(now.Add(-time.Hour - 10*time.Minute))}},
		{`DELETE FROM devices WHERE status = 'pending' AND pending_expires < ?`, []any{unix(now.Add(-24 * time.Hour))}},
		{`DELETE FROM sessions WHERE device_id NOT IN (SELECT id FROM devices)`, nil},
		{`DELETE FROM events WHERE created_at < ?`, []any{unix(now.Add(-30 * 24 * time.Hour))}},
		// Audit retention: a year, and at most auditKeep entries per account.
		{`DELETE FROM audit WHERE created_at < ?`, []any{unix(now.Add(-365 * 24 * time.Hour))}},
		{`DELETE FROM alert_outbox WHERE (sent_at > 0 OR failed_at > 0) AND created_at < ?`, []any{unix(now.Add(-alertKeep))}},
		{`UPDATE users SET alert_email_pending = '', alert_email_token = '', alert_email_expires = 0 WHERE alert_email_expires > 0 AND alert_email_expires < ?`, []any{unix(now)}},
		{`DELETE FROM project_audit WHERE created_at < ?`, []any{unix(now.Add(-365 * 24 * time.Hour))}},
		{`DELETE FROM group_audit WHERE created_at < ?`, []any{unix(now.Add(-365 * 24 * time.Hour))}},
		{`DELETE FROM group_joins WHERE expires_at < ?`, []any{unix(now.Add(-7 * 24 * time.Hour))}},
		{`DELETE FROM group_proposals WHERE status != 'open' AND closed_at < ?`, []any{unix(now.Add(-90 * 24 * time.Hour))}},
	}
	for _, s := range stmts {
		if _, err := d.sql.ExecContext(ctx, s.q, s.args...); err != nil {
			return err
		}
	}
	return d.trimAudit(ctx)
}

// auditAccounts lists every account id plus "" (account-less entries).
func (d *DB) auditAccounts(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id FROM users UNION SELECT ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// trimAudit keeps the newest auditKeep entries of each account (and of the
// account-less entries, such as denied sign-ins). Each account costs one
// index seek on audit(user_id, id), not a scan of the table.
func (d *DB) trimAudit(ctx context.Context) error {
	users, err := d.auditAccounts(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		var cut int64
		err := d.sql.QueryRowContext(ctx, `SELECT id FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?`, u, auditKeep).Scan(&cut)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := d.sql.ExecContext(ctx, `DELETE FROM audit WHERE user_id = ? AND id <= ?`, u, cut); err != nil {
			return err
		}
	}
	return nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// os0600 tightens the database file permissions; it may hold metadata that
// should not be world readable even though secrets in it are encrypted.
func os0600(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
