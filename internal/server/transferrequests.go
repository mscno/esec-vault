package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

type transferRow struct {
	wire.TransferSummary

	Raw []byte
}

func readTransfer(ctx context.Context, q queryer, id, user string) (*transferRow, error) {
	if !validTransferID(id) {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no such transfer")
	}
	var row transferRow
	err := q.QueryRowContext(ctx, `SELECT id,source,sender,recipient,expires_at,status,offer FROM transfer_requests WHERE id=? AND (sender=? OR recipient=?)`, id, user, user).Scan(&row.ID, &row.Source, &row.Sender, &row.Recipient, &row.Expires, &row.Status, &row.Raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no such transfer")
	}
	return &row, err
}

func (s *Server) validateOffer(ctx context.Context, q queryer, e *envelope.Envelope) (*team.TransferOffer, error) { //nolint:gocyclo // ordered signature, tenant-binding and ownership checks
	if e == nil {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "missing transfer offer")
	}
	var peek team.TransferOffer
	if err := e.Decode(&peek); err != nil {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid offer")
	}
	st, _, err := s.db.projectState(ctx, q, peek.Source)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "source project not found")
	}
	o, err := team.CheckTransferOffer(e, st, s.db.userChains(ctx, q), s.now())
	if err != nil {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "transfer is invalid or stale: %v", err)
	}
	if err := s.transferSource(ctx, q, o.Source, o.Sender); err != nil {
		return nil, err
	}
	if err := s.transferTarget(ctx, q, o.Destination, o.Recipient); err != nil {
		return nil, err
	}
	from, err := namespace(ctx, q, team.OrgOf(o.Source))
	if err != nil {
		return nil, err
	}
	to, err := namespace(ctx, q, team.OrgOf(o.Destination))
	if err != nil {
		return nil, err
	}
	if from == nil || to == nil || from.TenantID != o.SourceTenant || to.TenantID != o.DestinationTenant || from.TenantID == to.TenantID {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "transfer tenant identities do not match")
	}
	sourceOrg, _, err := s.db.orgState(ctx, q, from.Canonical)
	if err != nil {
		return nil, err
	}
	destOrg, _, err := s.db.orgState(ctx, q, to.Canonical)
	if err != nil {
		return nil, err
	}
	if sourceOrg == nil || !sourceOrg.Owner(o.Sender) || sourceOrg.Root() != o.SourceOrgRoot || destOrg == nil || destOrg.Root() != o.DestinationOrgRoot {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "transfer requires both signed tenants and their current owners")
	}
	if err := checkTransferInit(&wire.ProjectTransfer{Destination: o.Destination, Links: []*envelope.Envelope{o.Init}, Archive: o.Archive}, st); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Server) apiRequestTransfer(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.TransferRequest
	if err := decodeStrict(c.body, &req); err != nil || req.Offer == nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid offer")
		return
	}
	ctx := r.Context()
	id := "tr_" + req.Offer.Hash()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		o, err := s.validateOffer(ctx, tx, req.Offer)
		if err != nil {
			return err
		}
		if o.Sender != c.user.ID {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "offer must be signed by you")
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM transfer_requests WHERE sender=? AND status='pending' AND expires_at>?`, c.user.ID, s.now().Unix()).Scan(&pending); err != nil {
			return err
		}
		if pending >= 20 {
			return clientErr(http.StatusTooManyRequests, wire.ErrRateLimited, "too many pending transfers")
		}
		raw, err := json.Marshal(req.Offer)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO transfer_requests(id,source,sender,recipient,offer,expires_at,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, id, o.Source, o.Sender, o.Recipient, raw, o.Expires.Unix(), s.now().Unix()); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "transfer_requested", id+" "+o.Source+" -> "+o.Destination, s.now())
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ID string `json:"id"`
	}{id})
}

func (s *Server) apiTransfers(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	out := []wire.TransferSummary{}
	err := scanAll(r.Context(), s.db.sql, `SELECT id,source,sender,recipient,expires_at,status,offer FROM transfer_requests WHERE (sender=? OR recipient=?) AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 100`, []any{c.user.ID, c.user.ID, s.now().Unix()}, func(rows *sql.Rows) error {
		var v wire.TransferSummary
		var raw []byte
		if err := rows.Scan(&v.ID, &v.Source, &v.Sender, &v.Recipient, &v.Expires, &v.Status, &raw); err != nil {
			return err
		}
		var e envelope.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		var o team.TransferOffer
		if err := e.Decode(&o); err != nil {
			return err
		}
		v.Destination = o.Destination
		out = append(out, v)
		return nil
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiTransfer(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	row, err := readTransfer(ctx, s.db.sql, r.PathValue("id"), c.user.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if row.Status != "pending" {
		s.fail(w, r, clientErr(http.StatusConflict, wire.ErrConflict, "transfer is no longer pending"))
		return
	}
	if row.Expires <= s.now().Unix() {
		s.fail(w, r, clientErr(http.StatusConflict, wire.ErrConflict, "transfer expired"))
		return
	}
	var e envelope.Envelope
	if err := json.Unmarshal(row.Raw, &e); err != nil {
		s.internalError(w, r, err)
		return
	}
	var o team.TransferOffer
	if err := e.Decode(&o); err != nil {
		s.internalError(w, r, err)
		return
	}
	st, links, err := s.db.projectState(ctx, s.db.sql, o.Source)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if st == nil {
		s.fail(w, r, clientErr(http.StatusNotFound, wire.ErrNotFound, "source no longer exists"))
		return
	}
	chains, err := s.db.signerChains(ctx, s.db.sql, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.addChains(ctx, s.db.sql, chains, o.Recipient); err != nil {
		s.internalError(w, r, err)
		return
	}
	os, olinks, err := s.db.orgState(ctx, s.db.sql, team.OrgOf(o.Source))
	if err != nil || os == nil {
		if err == nil {
			err = clientErr(http.StatusConflict, wire.ErrConflict, "source tenant no longer exists")
		}
		s.fail(w, r, err)
		return
	}
	oc := wire.OrgChain{Canonical: os.Org, Links: olinks, Chains: map[string][]*envelope.Envelope{}}
	if err := s.db.addChains(ctx, s.db.sql, oc.Chains, orgSigners(os)...); err != nil {
		s.internalError(w, r, err)
		return
	}
	row.Destination = o.Destination
	writeJSON(w, http.StatusOK, wire.TransferView{Summary: row.TransferSummary, Offer: &e, Project: wire.ProjectChain{Links: links, Chains: chains}, SourceTenant: oc})
}

func userInQuery(ctx context.Context, q queryer, id string) (*userRow, error) {
	var u userRow
	err := q.QueryRowContext(ctx, `SELECT id,github_id,login FROM users WHERE id=?`, id).Scan(&u.ID, &u.GitHubID, &u.Login)
	return &u, err
}

func (s *Server) apiAcceptTransfer(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.TransferAccept
	if err := decodeStrict(c.body, &req); err != nil || req.Init == nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "missing signed init")
		return
	}
	ctx := r.Context()
	var wake []string
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		row, err := readTransfer(ctx, tx, r.PathValue("id"), c.user.ID)
		if err != nil {
			return err
		}
		if row.Recipient != c.user.ID {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "only the selected recipient can accept")
		}
		if row.Status != "pending" {
			return clientErr(http.StatusConflict, wire.ErrConflict, "transfer is no longer pending")
		}
		if row.Expires <= s.now().Unix() {
			return clientErr(http.StatusConflict, wire.ErrConflict, "transfer expired")
		}
		var e envelope.Envelope
		if err := json.Unmarshal(row.Raw, &e); err != nil {
			return err
		}
		o, err := s.validateOffer(ctx, tx, &e)
		if err != nil {
			return err
		}
		if req.Init.Hash() != o.Init.Hash() {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "acceptance changed the authorized init")
		}
		sender, err := userInQuery(ctx, tx, o.Sender)
		if err != nil {
			return err
		}
		if !s.cfg.Allowed(sender.GitHubID) {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "sender is no longer allowlisted")
		}
		sourceCtx := &reqCtx{user: sender, device: &deviceRow{}, ip: c.ip}
		wake, err = s.completeTransfer(ctx, tx, sourceCtx, c, o.Source, &wire.ProjectTransfer{Destination: o.Destination, Links: []*envelope.Envelope{req.Init}, Archive: o.Archive})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE transfer_requests SET status='accepted' WHERE id=?`, row.ID); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "transfer_accepted", row.ID, s.now())
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

func (s *Server) apiCancelTransfer(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		row, err := readTransfer(ctx, tx, r.PathValue("id"), c.user.ID)
		if err != nil {
			return err
		}
		if row.Status != "pending" {
			return clientErr(http.StatusConflict, wire.ErrConflict, "transfer is no longer pending")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE transfer_requests SET status='cancelled' WHERE id=?`, row.ID); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "transfer_cancelled", row.ID, s.now())
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// Transfer IDs are content addressed; they are not authorization credentials.
func validTransferID(id string) bool { return strings.HasPrefix(id, "tr_") && len(id) == 67 }
