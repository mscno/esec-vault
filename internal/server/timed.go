package server

// Timed access and access requests.
//
// Timed access: an admin who grants environments for a while (access grant
// --for 8h) records here when to take them away. When the time comes, the
// server makes the removal a change by that admin: signed at once by the
// server, if they let it sign removals, and otherwise waiting for their
// passkey or device. Either way the project's page and the admins' devices
// show it. The server can only take access away this way; nothing here
// grants anything.
//
// Access requests: anyone signed in asks the admins of a project for
// environments. The server passes the request on; an admin grants it from a
// device or a passkey like any other access, or turns it down.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	// maxTimedAccess is the longest timed access.
	maxTimedAccess = 366 * 24 * time.Hour
	// maxExpiriesPerProject bounds the timed access waiting in a project.
	maxExpiriesPerProject = 200
	// maxOpenRequestsPerUser and maxOpenRequestsPerProject bound requests.
	maxOpenRequestsPerUser    = 10
	maxOpenRequestsPerProject = 50
	// requestLifetime is how long a request waits for an answer.
	requestLifetime = 30 * 24 * time.Hour
)

var requestReason = regexp.MustCompile(`^[\pL\pN .,:;()'/_+!?#@-]{0,200}$`)

// ---- timed access ----

func (s *Server) apiSetExpiry(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.AccessExpiry
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	ctx := r.Context()
	st, _, err := s.memberState(ctx, project, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !st.Admin(c.user.ID) {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "only an admin of "+project+" sets timed access")
		return
	}
	now := s.now()
	if err := checkExpiry(st, req, now); err != nil {
		s.fail(w, r, err)
		return
	}
	envs, err := json.Marshal(team.SortEnvs(req.Envs))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var id int64
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_expiries WHERE project = ? AND status = 'open'`, project).Scan(&n); err != nil {
			return err
		}
		if n >= maxExpiriesPerProject {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too much timed access waits in %s", project)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO access_expiries (project, subject, envs, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			project, req.Subject, string(envs), req.Expires.Unix(), c.user.ID, now.Unix())
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		return s.db.projectAudit(ctx, tx, project, c.user.ID, c.ip, "access_timed", req.Subject+" "+strings.Join(req.Envs, ",")+" until "+req.Expires.UTC().Format(time.RFC3339), now)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req.ID, req.Project = id, project
	writeJSON(w, http.StatusOK, req)
}

// checkExpiry checks timed access against the project: a member or group
// that reads the environments, for at most maxTimedAccess.
func checkExpiry(st *team.State, e wire.AccessExpiry, now time.Time) error {
	bad := func(format string, args ...any) error {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, format, args...)
	}
	if !e.Expires.After(now) || e.Expires.After(now.Add(maxTimedAccess)) {
		return bad("timed access ends after now and within a year")
	}
	if len(e.Envs) == 0 || len(e.Envs) > team.MaxEnvs {
		return bad("name the environments that end")
	}
	for _, n := range e.Envs {
		if _, ok := st.Envs[n]; !ok {
			return bad("%s has no environment %s", st.Project, n)
		}
	}
	if strings.Contains(e.Subject, "/") {
		if team.ValidGroup(e.Subject) != nil {
			return bad("invalid group")
		}
		if _, ok := st.Group(e.Subject); !ok {
			return bad("the group %s reads nothing of %s", e.Subject, st.Project)
		}
		return nil
	}
	if team.ValidLogin(e.Subject) != nil {
		return bad("invalid GitHub login")
	}
	m := memberOf(st, e.Subject)
	if m == nil {
		return bad("%s is not a member of %s", e.Subject, st.Project)
	}
	if m.Admin {
		return bad("%s is an admin and reads every environment; timed access is for members", m.Login)
	}
	return nil
}

func (s *Server) apiExpiries(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	if _, _, err := s.memberState(ctx, project, c.user.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.expiries(ctx, project)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.AccessExpiries{Expiries: list})
}

func (s *Server) apiDeleteExpiry(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	st, _, err := s.memberState(ctx, project, c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !st.Admin(c.user.ID) {
		writeErr(w, http.StatusForbidden, wire.ErrForbidden, "only an admin of "+project+" changes timed access")
		return
	}
	if err := s.cancelExpiry(ctx, project, r.PathValue("id"), c.user.ID, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) cancelExpiry(ctx context.Context, project, id, user, ip string) error {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid id")
	}
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE access_expiries SET status = 'cancelled' WHERE id = ? AND project = ? AND status = 'open'`, n, project)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k != 1 {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "no such timed access")
		}
		return s.db.projectAudit(ctx, tx, project, user, ip, "access_timed_cancelled", id, s.now())
	})
}

// expiries lists a project's open timed access, soonest first.
func (s *Server) expiries(ctx context.Context, project string) ([]wire.AccessExpiry, error) {
	logins, err := s.db.logins(ctx)
	if err != nil {
		return nil, err
	}
	out := []wire.AccessExpiry{}
	err = scanAll(ctx, s.db.sql, `SELECT id, subject, envs, expires_at, created_by, last_error FROM access_expiries WHERE project = ? AND status = 'open' ORDER BY expires_at`, []any{project}, func(r *sql.Rows) error {
		e := wire.AccessExpiry{Project: project}
		var envs, by string
		var at int64
		if err := r.Scan(&e.ID, &e.Subject, &envs, &at, &by, &e.Error); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(envs), &e.Envs); err != nil {
			return err
		}
		e.Expires, e.By = fromUnix(at), logins[by]
		out = append(out, e)
		return nil
	})
	return out, err
}

// ExpireAccess takes away the timed access that is due. The server does it
// every five minutes; tests call it directly.
func (s *Server) ExpireAccess(ctx context.Context) { s.expireAccess(ctx) }

// expireAccess takes away the timed access that is due (housekeeping).
func (s *Server) expireAccess(ctx context.Context) {
	type due struct {
		id                   int64
		project, subject, by string
		envs                 []string
	}
	var list []due
	err := scanAll(ctx, s.db.sql, `SELECT id, project, subject, envs, created_by FROM access_expiries WHERE status = 'open' AND expires_at <= ? ORDER BY expires_at LIMIT 100`, []any{s.now().Unix()}, func(r *sql.Rows) error {
		var d due
		var envs string
		if err := r.Scan(&d.id, &d.project, &d.subject, &envs, &d.by); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(envs), &d.envs); err != nil {
			return err
		}
		list = append(list, d)
		return nil
	})
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("reading timed access", "error", err)
		}
		return
	}
	for _, d := range list {
		status, err := s.expireOne(ctx, d.project, d.subject, d.by, d.envs)
		if err != nil {
			// Fail closed: it stays open, shown on the project's page and in
			// access show, and is tried again on the next round.
			s.log.Warn("ending timed access", "project", d.project, "subject", d.subject, "error", err)
			if _, err2 := s.db.sql.ExecContext(ctx, `UPDATE access_expiries SET last_error = ? WHERE id = ?`, truncate(err.Error(), 300), d.id); err2 != nil {
				s.log.Warn("noting a timed access failure", "error", err2)
			}
			continue
		}
		if _, err := s.db.sql.ExecContext(ctx, `UPDATE access_expiries SET status = ?, last_error = '' WHERE id = ?`, status, d.id); err != nil {
			s.log.Warn("closing timed access", "error", err)
		}
	}
}

// expireOne takes envs of project away from subject, as by. It returns
// "signed", "proposed", or "gone" when nothing was left to take.
func (s *Server) expireOne(ctx context.Context, project, subject, by string, envs []string) (string, error) {
	st, _, err := s.db.projectState(ctx, s.db.sql, project)
	if err != nil {
		return "", err
	}
	if st == nil {
		return "gone", nil
	}
	without := func(have []string) []string {
		return slices.DeleteFunc(slices.Clone(have), func(n string) bool { return slices.Contains(envs, n) })
	}
	var c wire.Change
	if strings.Contains(subject, "/") {
		pg, ok := st.Group(subject)
		if !ok || slices.Equal(without(pg.Envs), pg.Envs) {
			return "gone", nil
		}
		c = wire.Change{Scope: wire.ScopeGroup, Target: subject, Kind: wire.ChangeAccess, Project: project, Envs: without(pg.Envs)}
	} else {
		m := memberOf(st, subject)
		if m == nil || m.Admin || slices.Equal(without(m.Envs), m.Envs) {
			return "gone", nil
		}
		c = wire.Change{Scope: wire.ScopeProject, Target: project, Kind: wire.ChangeMemberSet, Subject: m.Login, Envs: without(m.Envs)}
		if len(c.Envs) == 0 {
			c = wire.Change{Scope: wire.ScopeProject, Target: project, Kind: wire.ChangeMemberRemove, Subject: m.Login}
		}
	}
	status := "proposed"
	if st.Admin(by) {
		ok, err := s.serverSigns(ctx, by, "", c)
		if err != nil {
			return "", err
		}
		if ok {
			status = "signed"
		}
	}
	if status == "proposed" {
		if err := s.propose(ctx, by, "", c); err != nil {
			return "", err
		}
	}
	return status, s.db.projectAudit(ctx, s.db.sql, project, by, "", "access_expired", subject+" "+strings.Join(envs, ",")+" "+status, s.now())
}

// ---- access requests ----

func (s *Server) apiNewRequest(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.AccessRequestNew
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	id, err := s.newRequest(r.Context(), c.user.ID, c.ip, req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.AccessRequest{ID: id, Project: req.Project, Login: c.user.Login, Envs: team.SortEnvs(req.Envs), Reason: req.Reason, Created: s.now()})
}

// newRequest stores a request of user for envs of a project. A project
// that does not exist takes the request too, and nobody sees it: the
// answer does not tell who has which projects.
func (s *Server) newRequest(ctx context.Context, user, ip string, req wire.AccessRequestNew) (int64, error) {
	if err := checkRequest(req); err != nil {
		return 0, err
	}
	// Withdrawn requests do not count as open: bound how often anyone asks.
	if !s.limits.allow("request:"+user, 30, time.Hour, s.now()) {
		return 0, clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests for access; try again later")
	}
	envs, err := json.Marshal(team.SortEnvs(req.Envs))
	if err != nil {
		return 0, err
	}
	now := s.now()
	var id int64
	var admins []string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		since := now.Add(-requestLifetime).Unix()
		var mine, theirs int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_requests WHERE user_id = ? AND status = 'open' AND created_at > ?`, user, since).Scan(&mine); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_requests WHERE project = ? AND status = 'open' AND created_at > ?`, req.Project, since).Scan(&theirs); err != nil {
			return err
		}
		if mine >= maxOpenRequestsPerUser || theirs >= maxOpenRequestsPerProject {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests wait already; withdraw some, or wait for an answer")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE access_requests SET status = 'replaced' WHERE user_id = ? AND project = ? AND status = 'open'`, user, req.Project); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO access_requests (project, user_id, envs, reason, created_at) VALUES (?, ?, ?, ?, ?)`, req.Project, user, string(envs), req.Reason, now.Unix())
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		var err2 error
		if admins, err2 = projectAdmins(ctx, tx, req.Project); err2 != nil {
			return err2
		}
		for _, a := range admins {
			if err := s.db.addEvent(ctx, tx, a, wire.EventProject, req.Project, now); err != nil {
				return err
			}
		}
		if len(admins) == 0 {
			return nil
		}
		return s.db.projectAudit(ctx, tx, req.Project, user, ip, "access_requested", strings.Join(req.Envs, ","), now)
	})
	if err == nil {
		for _, a := range admins {
			s.notify.wake(a)
		}
	}
	return id, err
}

// checkRequest checks what an access request asks for.
func checkRequest(req wire.AccessRequestNew) error {
	bad := func(format string, args ...any) error {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, format, args...)
	}
	if team.ValidProject(req.Project) != nil {
		return bad("invalid project: use org/repo")
	}
	if len(req.Envs) == 0 || len(req.Envs) > team.MaxEnvs {
		return bad("name the environments you need")
	}
	for _, n := range req.Envs {
		if team.ValidEnv(n) != nil {
			return bad("invalid environment %q", n)
		}
	}
	if !requestReason.MatchString(req.Reason) {
		return bad("a reason is at most 200 letters, digits, spaces and simple punctuation")
	}
	return nil
}

func (s *Server) apiRequests(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	out := wire.AccessRequests{ToDecide: []wire.AccessRequest{}, Mine: []wire.AccessRequest{}}
	var err error
	if out.ToDecide, err = s.requestsToDecide(ctx, c.user.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if out.Mine, err = s.requestsWhere(ctx, `r.user_id = ?`, c.user.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// requestsToDecide lists the open requests in the projects user
// administers.
func (s *Server) requestsToDecide(ctx context.Context, user string) ([]wire.AccessRequest, error) {
	return s.requestsWhere(ctx, `r.project IN (SELECT project FROM project_members WHERE user_id = ? AND active = 1 AND admin = 1)`, user)
}

// projectRequests lists a project's open requests.
func (s *Server) projectRequests(ctx context.Context, project string) ([]wire.AccessRequest, error) {
	return s.requestsWhere(ctx, `r.project = ?`, project)
}

func (s *Server) requestsWhere(ctx context.Context, where string, args ...any) ([]wire.AccessRequest, error) {
	out := []wire.AccessRequest{}
	args = append(args, s.now().Add(-requestLifetime).Unix())
	err := scanAll(ctx, s.db.sql, `SELECT r.id, r.project, u.login, r.envs, r.reason, r.created_at FROM access_requests r JOIN users u ON u.id = r.user_id
		WHERE `+where+` AND r.status = 'open' AND r.created_at > ? ORDER BY r.id`, args, func(rows *sql.Rows) error {
		var q wire.AccessRequest
		var envs string
		var at int64
		if err := rows.Scan(&q.ID, &q.Project, &q.Login, &envs, &q.Reason, &at); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(envs), &q.Envs); err != nil {
			return err
		}
		q.Created = fromUnix(at)
		out = append(out, q)
		return nil
	})
	return out, err
}

func (s *Server) apiCloseRequest(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.AccessRequestClose
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if err := s.closeRequest(r.Context(), r.PathValue("id"), req.Granted, c.user.ID, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// closeRequest answers a request, as an admin of its project, or withdraws
// it, as its asker.
func (s *Server) closeRequest(ctx context.Context, id string, granted bool, user, ip string) error {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request id")
	}
	var project, asker string
	err = s.db.sql.QueryRowContext(ctx, `SELECT project, user_id FROM access_requests WHERE id = ? AND status = 'open'`, n).Scan(&project, &asker)
	notFound := clientErr(http.StatusNotFound, wire.ErrNotFound, "no open request %s", id)
	if errors.Is(err, sql.ErrNoRows) {
		return notFound
	}
	if err != nil {
		return err
	}
	status := "withdrawn"
	if asker != user {
		admins, err := projectAdmins(ctx, s.db.sql, project)
		if err != nil {
			return err
		}
		if !contains(admins, user) {
			return notFound
		}
		status = "denied"
		if granted {
			status = "granted"
		}
	}
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE access_requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?`, status, user, now.Unix(), n); err != nil {
			return err
		}
		if err := s.db.addEvent(ctx, tx, asker, wire.EventProject, project, now); err != nil {
			return err
		}
		return s.db.projectAudit(ctx, tx, project, user, ip, "access_request_"+status, id, now)
	})
}
