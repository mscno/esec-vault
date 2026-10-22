package server

// Invites: an admin adds someone on the web who has no vault account on
// this server yet. The invite waits; when that GitHub login creates its
// account, it becomes a change for the admin's passkey or device to sign,
// like one made on the page then. Nothing is signed or sealed before: the
// device still checks the person's GitHub SSH proof first.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	// inviteLifetime is how long an invite waits for its person.
	inviteLifetime = 30 * 24 * time.Hour
	// maxInvitesPerTarget bounds the invites waiting in one project or
	// group.
	maxInvitesPerTarget = 50
)

// invite is an invite waiting for its person.
type invite struct {
	ID      int64
	Scope   string
	Target  string
	Login   string
	Envs    []string
	Admin   bool
	By      string
	ByLogin string
	Created time.Time
}

// addInvite stores an invite of login to a project or group by user.
func (s *Server) addInvite(ctx context.Context, user, ip string, c wire.Change) error {
	envs, err := json.Marshal(team.SortEnvs(c.Envs))
	if err != nil {
		return err
	}
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE scope = ? AND target = ? AND status = 'open' AND created_at > ?`, c.Scope, c.Target, now.Add(-inviteLifetime).Unix()).Scan(&n); err != nil {
			return err
		}
		if n >= maxInvitesPerTarget {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many invites wait in %s; cancel some first", c.Target)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET status = 'replaced' WHERE scope = ? AND target = ? AND login = ? AND status = 'open'`, c.Scope, c.Target, strings.ToLower(c.Subject)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO invites (scope, target, login, envs, admin, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			c.Scope, c.Target, strings.ToLower(c.Subject), string(envs), c.Admin, user, now.Unix()); err != nil {
			return err
		}
		return s.changeAudit(ctx, tx, c.Scope, c.Target, user, ip, "invited", c.Subject, now)
	})
}

// invites lists the open invites of a project or group.
func (s *Server) invites(ctx context.Context, scope, target string) ([]invite, error) {
	logins, err := s.db.logins(ctx)
	if err != nil {
		return nil, err
	}
	out := []invite{}
	err = scanAll(ctx, s.db.sql, `SELECT id, scope, target, login, envs, admin, created_by, created_at FROM invites WHERE scope = ? AND target = ? AND status = 'open' AND created_at > ? ORDER BY id`,
		[]any{scope, target, s.now().Add(-inviteLifetime).Unix()}, func(r *sql.Rows) error {
			var iv invite
			var envs string
			var at int64
			if err := r.Scan(&iv.ID, &iv.Scope, &iv.Target, &iv.Login, &envs, &iv.Admin, &iv.By, &at); err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(envs), &iv.Envs); err != nil {
				return err
			}
			iv.Created, iv.ByLogin = fromUnix(at), logins[iv.By]
			out = append(out, iv)
			return nil
		})
	return out, err
}

// redeemInvites turns the open invites of a person who just created their
// vault account into changes, made by the admins who invited them, if they
// still administer the project or group.
func (s *Server) redeemInvites(ctx context.Context, user string) {
	u, err := s.db.user(ctx, user)
	if err != nil || u == nil {
		return
	}
	var list []invite
	err = scanAll(ctx, s.db.sql, `SELECT id, scope, target, envs, admin, created_by FROM invites WHERE login = ? AND status = 'open' AND created_at > ? ORDER BY id`,
		[]any{strings.ToLower(u.Login), s.now().Add(-inviteLifetime).Unix()}, func(r *sql.Rows) error {
			var iv invite
			var envs string
			if err := r.Scan(&iv.ID, &iv.Scope, &iv.Target, &envs, &iv.Admin, &iv.By); err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(envs), &iv.Envs); err != nil {
				return err
			}
			list = append(list, iv)
			return nil
		})
	if err != nil {
		s.log.Warn("reading invites", "error", err)
		return
	}
	for _, iv := range list {
		admins, err := s.changeAdmins(ctx, iv.Scope, iv.Target)
		status := "redeemed"
		if err != nil || !contains(admins, iv.By) {
			status = "dropped"
		} else {
			c := wire.Change{Scope: iv.Scope, Target: iv.Target, Kind: wire.ChangeMemberAdd, Subject: u.Login, Envs: iv.Envs, Admin: iv.Admin}
			if err := s.propose(ctx, iv.By, "", c); err != nil {
				s.log.Warn("turning an invite into a change", "error", err)
				continue
			}
		}
		if _, err := s.db.sql.ExecContext(ctx, `UPDATE invites SET status = ? WHERE id = ?`, status, iv.ID); err != nil {
			s.log.Warn("closing an invite", "error", err)
		}
	}
}

// redeemWaitingInvites redeems the invites of people who have a vault
// account by now: redeeming when the account was made may have failed
// (housekeeping).
func (s *Server) redeemWaitingInvites(ctx context.Context) {
	var logins []string
	err := scanAll(ctx, s.db.sql, `SELECT DISTINCT login FROM invites WHERE status = 'open' AND created_at > ? LIMIT 200`, []any{s.now().Add(-inviteLifetime).Unix()}, func(r *sql.Rows) error {
		var l string
		if err := r.Scan(&l); err != nil {
			return err
		}
		logins = append(logins, l)
		return nil
	})
	if err != nil {
		return
	}
	for _, l := range logins {
		u, err := s.db.userByLogin(ctx, l)
		if err != nil || u == nil {
			continue
		}
		if first, err := s.db.firstLink(ctx, u.ID); err == nil && first != nil {
			s.redeemInvites(ctx, u.ID)
		}
	}
}

// cancelInvite cancels an open invite of a project or group user
// administers.
func (s *Server) cancelInvite(ctx context.Context, scope, target, user, ip, id string) (string, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid invite")
	}
	var login string
	err = s.db.sql.QueryRowContext(ctx, `SELECT login FROM invites WHERE id = ? AND scope = ? AND target = ? AND status = 'open'`, n, scope, target).Scan(&login)
	if err != nil {
		return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "no such invite")
	}
	now := s.now()
	return "Cancelled the invite of " + login + ".", s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET status = 'cancelled' WHERE id = ?`, n); err != nil {
			return err
		}
		return s.changeAudit(ctx, tx, scope, target, user, ip, "invite_cancelled", login, now)
	})
}

func (s *Server) webTeamCancelInvite(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		return s.cancelInvite(ctx, wire.ScopeProject, st.Project, ws.user.ID, s.clientIP(r), r.PathValue("id"))
	})
}

func (s *Server) webGroupCancelInvite(w http.ResponseWriter, r *http.Request) {
	s.groupForm(w, r, func(ctx context.Context, ws *webSession, gs *team.GroupState) (string, error) {
		if !gs.Admin(ws.user.ID) {
			return "", clientErr(http.StatusForbidden, wire.ErrForbidden, "only an admin of the group can cancel invites")
		}
		return s.cancelInvite(ctx, wire.ScopeGroup, gs.Group, ws.user.ID, s.clientIP(r), r.PathValue("id"))
	})
}
