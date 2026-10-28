package server

// Project settings on the web: archiving and unarchiving (signed links, by a
// passkey or a device), moving to a new id (a device builds the new chain),
// handing over admin and leaving (signed changes), and deleting an archived
// project's data from the server (the server's own data: no signature).

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

const proposedText = "Proposed. Sign it with your passkey on the Changes page, or on a device: esec vault changes"

func (s *Server) webTeamArchive(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		if st.Archived {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is archived already.", st.Project)
		}
		return proposedText + ". Once signed, no keys are sent for it until it is unarchived.", s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeProjectArchive})
	})
}

func (s *Server) webTeamUnarchive(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		if !st.Archived {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is not archived.", st.Project)
		}
		return proposedText, s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeProjectUnarchive})
	})
}

// webTeamMove proposes moving the project to a new id, for a device: it
// creates the new chain with the same keys and people, and archives this one
// pointing there.
func (s *Server) webTeamMove(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		next := strings.TrimSpace(r.PostForm.Get("project"))
		if team.ValidProject(next) != nil || strings.EqualFold(next, st.Project) {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Name the new project id as org/repo.")
		}
		if other, _, err := s.db.projectState(ctx, s.db.sql, next); err != nil || other != nil {
			if err != nil {
				return "", err
			}
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s exists already.", next)
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeProjectMove, Project: next}); err != nil {
			return "", err
		}
		return "Proposed. A device makes the move (esec vault changes): it creates " + next + " with the same keys and people, and archives " + st.Project + " pointing there. Then change project in the repository's esec.toml.", nil
	})
}

// webTeamHandover proposes making a member an admin and, if asked, the
// viewer a member who reads everything. A device signs both.
func (s *Server) webTeamHandover(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		m := memberOf(st, r.PostForm.Get("login"))
		if m == nil {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "That is not a member.")
		}
		if m.User == ws.user.ID {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Name someone else.")
		}
		ip := s.clientIP(r)
		if !m.Admin {
			if err := s.propose(ctx, ws.user.ID, ip, wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberSet, Subject: m.Login, Admin: true}); err != nil {
				return "", err
			}
		}
		msg := "Proposed making " + m.Login + " an admin"
		if r.PostForm.Get("step_down") == "on" {
			if err := s.propose(ctx, ws.user.ID, ip, wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberSet, Subject: ws.user.Login, Envs: st.EnvNames()}); err != nil {
				return "", err
			}
			msg += ", then you a member who reads every environment"
		}
		return msg + ". Only a device signs these (esec vault changes); it signs them in that order.", nil
	})
}

// webTeamLeave leaves a project: signed by the server or a passkey when the
// person lets them, otherwise by one of their devices.
func (s *Server) webTeamLeave(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	s.pageForm(w, r, "/projects", func(ctx context.Context, ws *webSession) (string, error) {
		st, _, err := s.memberState(ctx, project, ws.user.ID)
		if err != nil {
			return "", err
		}
		m, _ := st.Member(ws.user.ID)
		if m.Admin {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "An admin leaves from a device (esec vault access leave), once another member is an admin.")
		}
		c := wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeProjectLeave, Project: project}
		ip := s.clientIP(r)
		if ok, err := s.serverSigns(ctx, ws.user.ID, ip, c); err != nil || ok {
			return "You left " + project + ". Its admins are told, to replace the keys you held.", err
		}
		return proposedText + ". Its admins are told once you have left.", s.propose(ctx, ws.user.ID, ip, c)
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.teamPageData(ctx, ws, project)
		if err != nil {
			data = s.page(ws, "projects")
		}
		return data, teamParts, nil
	})
}

// webTeamDelete deletes an archived project's data from the server.
func (s *Server) webTeamDelete(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	s.pageForm(w, r, "/projects", func(ctx context.Context, ws *webSession) (string, error) {
		if r.PostForm.Get("confirm") != project {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Type the project's id to delete it.")
		}
		return "Deleted " + project + " from the server. Its keys stay in your keyrings.", s.deleteProject(ctx, project, ws.user.ID, s.clientIP(r))
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		return s.page(ws, "projects"), nil, nil
	})
}

func (s *Server) apiDeleteProject(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	project, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	if err := s.deleteProject(r.Context(), project, c.user.ID, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// deleteProject removes an archived project's chain, members, grants and
// everything waiting in it, for one of its admins. The project's audit log
// stays. Nothing a device holds changes: the keys stay in keyrings, and a
// device that saw the project forgets it once it sees it gone.
func (s *Server) deleteProject(ctx context.Context, project, user, ip string) error {
	st, _, err := s.memberState(ctx, project, user)
	if err != nil {
		return err
	}
	if !st.Admin(user) {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "only an admin of %s deletes it", project)
	}
	if !st.Archived {
		return clientErr(http.StatusConflict, wire.ErrConflict, "archive %s first; then it can be deleted", project)
	}
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM project_links WHERE project = ?`,
			`DELETE FROM project_members WHERE project = ?`,
			`DELETE FROM project_machines WHERE project = ?`,
			`DELETE FROM project_grants WHERE project = ?`,
			`DELETE FROM project_holdings WHERE project = ?`,
			`DELETE FROM project_groups WHERE project = ?`,
			`DELETE FROM changes WHERE scope = 'project' AND target = ?`,
			`DELETE FROM invites WHERE scope = 'project' AND target = ?`,
			`DELETE FROM access_requests WHERE project = ?`,
			`DELETE FROM access_expiries WHERE project = ?`,
			`DELETE FROM access_reviews WHERE project = ?`,
			`DELETE FROM projects WHERE id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, project); err != nil {
				return err
			}
		}
		return s.db.projectAudit(ctx, tx, project, user, ip, "project_deleted", "", now)
	})
}
