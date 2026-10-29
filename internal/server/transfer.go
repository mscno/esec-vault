package server

import (
	"context"
	"database/sql"
	"net/http"
	"slices"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// A cross-tenant move is accepted by a destination tenant admin (or the
// personal owner), not merely somebody who may create a project there.
func (s *Server) transferTarget(ctx context.Context, q queryer, dest, user string) error {
	org := team.OrgOf(dest)
	n, err := namespace(ctx, q, org)
	if err != nil {
		return err
	}
	if n == nil || n.Kind == "legacy" {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "destination tenant %s is not approved", org)
	}
	if n.Kind == "personal" {
		return s.requireNamespaceOwner(ctx, q, org, user)
	}
	os, _, err := s.db.orgState(ctx, q, org)
	if err != nil {
		return err
	}
	if os == nil || !os.Owner(user) {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "a transfer requires ownership of destination tenant %s; set up its signed chain first", org)
	}
	return nil
}

func (s *Server) apiProjectTransfer(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	from, err := projectParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	var req wire.ProjectTransfer
	if err := decodeStrict(c.body, &req); err != nil || team.ValidProject(req.Destination) != nil || req.Destination == from || len(req.Links) == 0 || len(req.Links) > team.MaxMembers+1 || slices.Contains(req.Links, nil) || req.Archive == nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid transfer")
		return
	}
	same, err := sameTenant(r.Context(), s.db.sql, from, req.Destination)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cross := !same
	if cross && len(req.Links) != 1 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "cross-tenant transfers do not copy source access")
		return
	}
	var wake []string
	ctx := r.Context()
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		var err error
		wake, err = s.transferProject(ctx, tx, c, from, &req)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, u := range wake {
		s.notify.wake(u)
	}
	s.kickAlerts()
	writeJSON(w, http.StatusOK, struct{}{})
}

func checkTransferInit(req *wire.ProjectTransfer, old *team.State) error {
	first, err := team.PeekLink(req.Links[0])
	if err != nil || first.Type != team.TypeInit {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "destination must begin with init")
	}
	var init team.InitBody
	if err := envelope.DecodeStrict(first.Body, &init); err != nil || init.Predecessor == nil || init.Predecessor.Project != old.Project || init.Predecessor.Root != old.Root() {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "destination must sign the source chain root")
	}
	if len(init.Envs) != len(old.Envs) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "transfer must preserve environment keys")
	}
	seen := map[string]bool{}
	for _, e := range init.Envs {
		v, ok := old.Envs[e.Name]
		if !ok || v.PublicKey != e.PublicKey || seen[e.Name] {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "transfer must preserve environment keys")
		}
		seen[e.Name] = true
	}
	return nil
}

func checkTransferArchive(req *wire.ProjectTransfer, dest *team.State) error {
	l, err := team.PeekLink(req.Archive)
	if err != nil || l.Type != team.TypeArchive {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "source must be archived")
	}
	var archive team.ArchiveBody
	if err := envelope.DecodeStrict(l.Body, &archive); err != nil || archive.Successor == nil || archive.Successor.Project != req.Destination || archive.Successor.Root != dest.Root() {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "source must sign the destination chain root")
	}
	return nil
}

func (s *Server) transferProject(ctx context.Context, tx *sql.Tx, c *reqCtx, from string, req *wire.ProjectTransfer) ([]string, error) {
	return s.completeTransfer(ctx, tx, c, c, from, req)
}

func (s *Server) transferSource(ctx context.Context, q queryer, source, user string) error {
	n, err := namespace(ctx, q, team.OrgOf(source))
	if err != nil {
		return err
	}
	if n == nil || n.Kind == "legacy" {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "source tenant ownership must be established before transferring")
	}
	if n.Kind == "personal" {
		return s.requireNamespaceOwner(ctx, q, team.OrgOf(source), user)
	}
	os, _, err := s.db.orgState(ctx, q, n.Canonical)
	if err != nil {
		return err
	}
	if os == nil {
		if n.Owner == user {
			return nil
		}
	} else if os.Owner(user) {
		return nil
	}
	return clientErr(http.StatusForbidden, wire.ErrForbidden, "source tenant owner authorization is required")
}

func (s *Server) completeTransfer(ctx context.Context, tx *sql.Tx, c, receiver *reqCtx, from string, req *wire.ProjectTransfer) ([]string, error) {
	old, _, err := s.db.projectState(ctx, tx, from)
	if err != nil {
		return nil, err
	}
	if old == nil || !old.Admin(c.user.ID) {
		return nil, clientErr(http.StatusForbidden, wire.ErrForbidden, "only a source project admin can transfer it")
	}
	if old.Archived {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "source project is archived")
	}
	same, err := sameTenant(ctx, tx, from, req.Destination)
	if err != nil {
		return nil, err
	}
	if !same {
		if len(req.Links) != 1 {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "cross-tenant transfers do not copy access")
		}
		if err := s.transferSource(ctx, tx, from, c.user.ID); err != nil {
			return nil, err
		}
		if err := s.transferTarget(ctx, tx, req.Destination, receiver.user.ID); err != nil {
			return nil, err
		}
	}
	if err := checkTransferInit(req, old); err != nil {
		return nil, err
	}
	_, wake, err := s.projectCommit(ctx, tx, receiver, req.Destination, &wire.ProjectCommit{Links: req.Links}, true)
	if err != nil {
		return nil, err
	}
	dest, _, err := s.db.projectState(ctx, tx, req.Destination)
	if err != nil {
		return nil, err
	}
	if err := checkTransferArchive(req, dest); err != nil {
		return nil, err
	}
	_, users, err := s.projectCommit(ctx, tx, c, from, &wire.ProjectCommit{Links: []*envelope.Envelope{req.Archive}}, true)
	if err != nil {
		return nil, err
	}
	err = s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "project_transfer", from+" -> "+req.Destination, s.now())
	return append(wake, users...), err
}
