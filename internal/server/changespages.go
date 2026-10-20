package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/mscno/esec-vault/internal/wire"
)

// webChanges lists the web changes waiting for the person's devices.
func (s *Server) webChanges(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.changesPageData(r.Context(), ws)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "changes.html", data)
}

func (s *Server) webChangesLive(w http.ResponseWriter, r *http.Request) {
	ws := s.dsSession(w, r)
	if ws == nil {
		return
	}
	data, err := s.changesPageData(r.Context(), ws)
	if err != nil {
		s.dsFail(w, r, err)
		return
	}
	s.dsPatch(w, r, data, "changes-list")
}

func (s *Server) changesPageData(ctx context.Context, ws *webSession) (map[string]any, error) {
	cs, err := s.adminChanges(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	data := s.page(ws, "changes")
	data["Changes"] = cs
	s.addPasskeys(ctx, ws, data)
	return data, nil
}

// webDismissChange dismisses a change from the changes page.
func (s *Server) webDismissChange(w http.ResponseWriter, r *http.Request) {
	s.pageForm(w, r, "/changes", func(ctx context.Context, ws *webSession) (string, error) {
		return s.dismiss(ctx, ws, r)
	}, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.changesPageData(ctx, ws)
		return data, []string{"changes-list"}, err
	})
}

// dismiss dismisses the change a form names in its path.
func (s *Server) dismiss(ctx context.Context, ws *webSession, r *http.Request) (string, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid change id")
	}
	return "Dismissed.", s.closeChange(ctx, id, false, ws.user.ID, s.clientIP(r))
}
