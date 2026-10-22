package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// The web side of access requests and timed access (timed.go).

// requestEnvs reads environment names from a form: ticked boxes, or a list
// typed as text.
func requestEnvs(r *http.Request) []string {
	envs := r.PostForm["env"]
	for _, f := range strings.FieldsFunc(r.PostForm.Get("envs"), func(c rune) bool { return c == ',' || c == ' ' }) {
		envs = append(envs, strings.ToLower(f))
	}
	return team.SortEnvs(envs)
}

// webAskAccess asks the admins of any project for environments.
func (s *Server) webAskAccess(w http.ResponseWriter, r *http.Request) {
	s.pageForm(w, r, "/access", func(ctx context.Context, ws *webSession) (string, error) {
		project := strings.TrimSpace(r.PostForm.Get("project"))
		envs := requestEnvs(r)
		if _, err := s.newRequest(ctx, ws.user.ID, s.clientIP(r), wire.AccessRequestNew{Project: project, Envs: envs, Reason: strings.TrimSpace(r.PostForm.Get("reason"))}); err != nil {
			return "", err
		}
		return "Asked. If " + project + " is a shared project on this server, its admins see your request on its page and on their devices.", nil
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.accessPageData(ctx, ws)
		return data, []string{"access-requests"}, err
	})
}

// webWithdrawRequest withdraws one of the viewer's own requests.
func (s *Server) webWithdrawRequest(w http.ResponseWriter, r *http.Request) {
	s.pageForm(w, r, "/access", func(ctx context.Context, ws *webSession) (string, error) {
		var asker string
		err := s.db.sql.QueryRowContext(ctx, `SELECT user_id FROM access_requests WHERE id = ?`, r.PathValue("id")).Scan(&asker)
		if errors.Is(err, sql.ErrNoRows) || asker != ws.user.ID {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "no such request")
		}
		if err != nil {
			return "", err
		}
		return "Withdrawn.", s.closeRequest(ctx, r.PathValue("id"), false, ws.user.ID, s.clientIP(r))
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.accessPageData(ctx, ws)
		return data, []string{"access-requests"}, err
	})
}

// webTeamAsk lets a member of a project ask for more of it.
func (s *Server) webTeamAsk(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("org") + "/" + r.PathValue("repo")
	s.pageForm(w, r, "/teams/"+project, func(ctx context.Context, ws *webSession) (string, error) {
		if _, err := s.newRequest(ctx, ws.user.ID, s.clientIP(r), wire.AccessRequestNew{Project: project, Envs: requestEnvs(r), Reason: strings.TrimSpace(r.PostForm.Get("reason"))}); err != nil {
			return "", err
		}
		return "Asked. The project's admins see it here and on their devices.", nil
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.teamPageData(ctx, ws, project)
		return data, teamParts, err
	})
}

// openRequest loads an open request of a project.
func (s *Server) openRequest(ctx context.Context, project, id string) (*wire.AccessRequest, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request id")
	}
	list, err := s.projectRequests(ctx, project)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == n {
			return &list[i], nil
		}
	}
	return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no open request %s", id)
}

// webTeamGrantRequest proposes the access a request asks for, for the
// admin's passkey or device to sign, and closes the request.
func (s *Server) webTeamGrantRequest(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		q, err := s.openRequest(ctx, st.Project, r.PathValue("id"))
		if err != nil {
			return "", err
		}
		var envs []string
		for _, n := range q.Envs {
			if _, ok := st.Envs[n]; ok {
				envs = append(envs, n)
			}
		}
		if len(envs) == 0 {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s has none of the environments asked for (%s); deny the request", st.Project, strings.Join(q.Envs, ", "))
		}
		c := wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberAdd, Subject: q.Login, Envs: envs}
		if m := memberOf(st, q.Login); m != nil {
			if m.Admin {
				return "", clientErr(http.StatusConflict, wire.ErrConflict, "%s is an admin and reads everything already", m.Login)
			}
			c = wire.Change{Scope: wire.ScopeProject, Target: st.Project, Kind: wire.ChangeMemberSet, Subject: m.Login, Envs: team.SortEnvs(append(slices.Clone(m.Envs), envs...))}
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), c); err != nil {
			return "", err
		}
		if err := s.closeRequest(ctx, r.PathValue("id"), true, ws.user.ID, s.clientIP(r)); err != nil {
			return "", err
		}
		return "Proposed giving " + q.Login + " " + strings.Join(envs, ", ") + ". Sign it with your passkey on the Changes page, or on a device: esec vault changes", nil
	})
}

// webTeamDenyRequest turns a request down.
func (s *Server) webTeamDenyRequest(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		q, err := s.openRequest(ctx, st.Project, r.PathValue("id"))
		if err != nil {
			return "", err
		}
		return "Turned down " + q.Login + "'s request.", s.closeRequest(ctx, r.PathValue("id"), false, ws.user.ID, s.clientIP(r))
	})
}

// webTeamCancelExpiry keeps timed access instead of ending it.
func (s *Server) webTeamCancelExpiry(w http.ResponseWriter, r *http.Request) {
	s.teamForm(w, r, func(ctx context.Context, ws *webSession, st *team.State) (string, error) {
		return "The access no longer ends by itself.", s.cancelExpiry(ctx, st.Project, r.PathValue("id"), ws.user.ID, s.clientIP(r))
	})
}

// requestNotices tells admins of the requests waiting for them.
func (s *Server) requestNotices(ctx context.Context, user string) ([]notice, error) {
	list, err := s.requestsToDecide(ctx, user)
	if err != nil {
		return nil, err
	}
	var out []notice
	for _, q := range list {
		out = append(out, notice{Level: "info", Text: q.Login + " asks for " + strings.Join(q.Envs, ", ") + " of " + q.Project + reasonText(q.Reason) + ".", Command: "esec vault access requests --project " + q.Project, Link: "/teams/" + q.Project + "#requests", LinkTo: "Answer"})
	}
	return out, nil
}

func reasonText(r string) string {
	if r == "" {
		return ""
	}
	return ` ("` + r + `")`
}
