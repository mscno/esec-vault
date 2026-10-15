package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/wire"
)

// Size bounds for stored objects.
const (
	maxBoxSize    = 4 << 10
	maxLinksPer   = 8
	maxBoxesPer   = 64
	maxSlotsPer   = 16
	maxVaultBytes = 12 << 20
)

// apiError is a client error raised inside a transaction.
type apiError struct {
	status int
	code   string
	desc   string
}

func (e *apiError) Error() string { return e.desc }

func clientErr(status int, code, format string, args ...any) error {
	return &apiError{status: status, code: code, desc: fmt.Sprintf(format, args...)}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeErr(w, ae.status, ae.code, ae.desc)
		return
	}
	s.internalError(w, r, err)
}

func (s *Server) apiChain(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if r.URL.Query().Get("after") == "" {
		after, err = 0, nil
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid after")
		return
	}
	links, err := s.db.chainLinks(r.Context(), s.db.sql, c.user.ID, after)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if links == nil {
		links = []*envelope.Envelope{}
	}
	writeJSON(w, http.StatusOK, wire.Chain{Links: links})
}

func (s *Server) apiDeviceProof(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.DeviceProofUpload
	if err := decodeStrict(c.body, &req); err != nil || req.Proof == nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	proof, err := chain.VerifyProof(req.Proof)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	if proof.User != c.user.ID || !matchesRow(proof.Device, c.device) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "proof does not describe this device")
		return
	}
	raw, err := json.Marshal(req.Proof)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := s.now()
	ctx := r.Context()
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET proof = ? WHERE id = ?`, raw, c.device.ID); err != nil {
			return err
		}
		return s.db.addEvent(ctx, tx, c.user.ID, wire.EventDevicePending, c.device.ID, now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.notify.wake(c.user.ID)
	writeJSON(w, http.StatusOK, struct{}{})
}

func matchesRow(d chain.Device, row *deviceRow) bool {
	return d.ID == row.ID && d.Name == row.Name && d.Platform == row.Platform && d.EncPub == row.EncPub && d.SignPub == row.SignPub && d.Created.Equal(row.Created)
}

func (s *Server) apiDeviceBox(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var b wire.DeviceBox
	err := s.db.sql.QueryRowContext(r.Context(), `SELECT ukey_version, box FROM device_boxes WHERE device_id = ? ORDER BY ukey_version DESC LIMIT 1`, c.device.ID).Scan(&b.UKeyVersion, &b.Box)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no user key for this device yet")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	b.DeviceID = c.device.ID
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) apiIdentity(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var b wire.IdentityBlob
	err := s.db.sql.QueryRowContext(r.Context(), `SELECT ukey_version, blob FROM identity_blobs WHERE user_id = ? ORDER BY ukey_version DESC LIMIT 1`, c.user.ID).Scan(&b.UKeyVersion, &b.Blob)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "no identity stored for this account")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.audit(r.Context(), s.db.sql, c.user.ID, c.device.ID, c.ip, "identity_read", "", s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) apiAgentSlots(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	now := s.now()
	if !s.limits.allow("slots:"+c.user.ID, 10, time.Hour, now) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many agent slot reads; try again later")
		return
	}
	slots, err := s.slots(r.Context(), c.user.ID, now, false)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.audit(r.Context(), s.db.sql, c.user.ID, c.device.ID, c.ip, "agent_slots_read", strconv.Itoa(len(slots)), now); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.AgentSlots{Slots: slots})
}

func (s *Server) slots(ctx context.Context, userID string, now time.Time, all bool) ([]wire.AgentSlot, error) {
	q := `SELECT id, ssh_key_fp, salt, box, ukey_version, expires_at, disabled_at FROM agent_slots WHERE user_id = ?`
	if !all {
		q += ` AND disabled_at = 0 AND expires_at > ` + strconv.FormatInt(now.Unix(), 10)
	}
	rows, err := s.db.sql.QueryContext(ctx, q+` ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wire.AgentSlot{}
	for rows.Next() {
		var sl wire.AgentSlot
		var expires, disabled int64
		if err := rows.Scan(&sl.SlotID, &sl.SSHKeyFP, &sl.Salt, &sl.Box, &sl.UKeyVersion, &expires, &disabled); err != nil {
			return nil, err
		}
		sl.Expires, sl.Disabled = fromUnix(expires), disabled != 0
		out = append(out, sl)
	}
	return out, rows.Err()
}

func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, err := s.db.devicesOf(r.Context(), s.db.sql, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := wire.Devices{Devices: []wire.DeviceInfo{}}
	now := s.now()
	for _, d := range rows {
		if d.Status == wire.DevicePending && !now.Before(d.PendingExpires) {
			continue
		}
		out.Devices = append(out.Devices, d.wire(true))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiSuspend(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := r.PathValue("id")
	if id == c.device.ID {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "a device cannot suspend itself; use logout")
		return
	}
	if err := s.suspend(r.Context(), c.user.ID, c.device.ID, id, c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// suspend blocks a device at once: its sessions end and its API access stops.
// Cryptographic revocation (a device_revoke link plus key rotation) is done
// by a client; until then the device is shown as suspended.
func (s *Server) suspend(ctx context.Context, userID, actorDevice, target, ip string) error {
	now := s.now()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE devices SET status = ? WHERE id = ? AND user_id = ? AND status IN (?, ?)`, wire.DeviceSuspended, target, userID, wire.DeviceActive, wire.DevicePending)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "no active or pending device %s", target)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at = 0`, now.Unix(), target); err != nil {
			return err
		}
		if err := s.db.addEvent(ctx, tx, userID, wire.EventDeviceStatus, target, now); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, userID, actorDevice, ip, "device_suspended", target, now)
	})
	if err == nil {
		s.notify.wake(userID)
	}
	return err
}

func (s *Server) apiDisableSlot(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	if err := s.disableSlot(r.Context(), c.user.ID, c.device.ID, r.PathValue("id"), c.ip); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) disableSlot(ctx context.Context, userID, actor, slotID, ip string) error {
	now := s.now()
	return s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE agent_slots SET disabled_at = ? WHERE id = ? AND user_id = ? AND disabled_at = 0`, now.Unix(), slotID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return clientErr(http.StatusNotFound, wire.ErrNotFound, "no enabled slot %s", slotID)
		}
		return s.db.audit(ctx, tx, userID, actor, ip, "agent_slot_disabled", slotID, now)
	})
}

// ---- vault ----

func (s *Server) apiVaultGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	v, err := s.vaultVersion(r.Context(), c.user.ID, 0, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) apiVaultVersion(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	n, err := strconv.ParseUint(r.PathValue("version"), 10, 64)
	if err != nil || n == 0 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid version")
		return
	}
	v, err := s.vaultVersion(r.Context(), c.user.ID, n, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) vaultVersion(ctx context.Context, userID string, version uint64, withBlob bool) (*wire.Vault, error) {
	q := `SELECT version, blob, sig, sha256, pushed_by, created_at FROM vault_versions WHERE user_id = ?`
	args := []any{userID}
	if version != 0 {
		q += ` AND version = ?`
		args = append(args, version)
	}
	var v wire.Vault
	var created int64
	err := s.db.sql.QueryRowContext(ctx, q+` ORDER BY version DESC LIMIT 1`, args...).Scan(&v.Version, &v.Blob, &v.Sig, &v.SHA256, &v.PushedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "no vault stored")
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt, v.Size = fromUnix(created), len(v.Blob)
	if !withBlob {
		v.Blob, v.Sig = nil, nil
	}
	return &v, nil
}

func (s *Server) apiVaultVersions(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, err := s.db.sql.QueryContext(r.Context(), `SELECT version, sha256, length(blob), pushed_by, created_at FROM vault_versions WHERE user_id = ? ORDER BY version DESC`, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := wire.VaultVersions{Versions: []wire.Vault{}}
	for rows.Next() {
		var v wire.Vault
		var created int64
		if err := rows.Scan(&v.Version, &v.SHA256, &v.Size, &v.PushedBy, &created); err != nil {
			s.internalError(w, r, err)
			return
		}
		v.CreatedAt = fromUnix(created)
		out.Versions = append(out.Versions, v)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVaultPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.VaultPut
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	var out *wire.Vault
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		v, err := s.putVault(ctx, tx, c, &req, nil)
		out = v
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.notify.wake(c.user.ID)
	writeJSON(w, http.StatusOK, out)
}

// putVault stores a new vault version if IfMatch names the current one.
func (s *Server) putVault(ctx context.Context, tx *sql.Tx, c *reqCtx, req *wire.VaultPut, state *chain.State) (*wire.Vault, error) {
	if len(req.Blob) == 0 || len(req.Blob) > maxVaultBytes {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "vault blob is empty or too large")
	}
	if err := vaultfile.CheckFraming(req.Blob); err != nil {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "not a vault blob: %v", err)
	}
	if state == nil {
		stored, err := s.db.chainLinks(ctx, tx, c.user.ID, 0)
		if err != nil {
			return nil, err
		}
		if state, err = chain.Verify(c.user.ID, stored); err != nil {
			return nil, fmt.Errorf("stored chain for %s does not verify: %w", c.user.ID, err)
		}
	}
	if state.Seq == 0 || !ed25519.Verify(state.SignPub, wire.VaultMessage(c.user.ID, req.Blob), req.Sig) {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "vault blob is not signed by the current user key")
	}
	var index []byte
	if len(req.Index) > 0 {
		if !ed25519.Verify(state.SignPub, wire.IndexMessage(c.user.ID, req.Index), req.IndexSig) {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "vault index is not signed by the current user key")
		}
		if err := checkIndex(req.Index); err != nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid vault index: %v", err)
		}
		index = req.Index
	}
	var current sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM vault_versions WHERE user_id = ?`, c.user.ID).Scan(&current); err != nil {
		return nil, err
	}
	cur := uint64(0)
	if current.Valid && current.Int64 > 0 {
		cur = uint64(current.Int64)
	}
	if req.IfMatch != cur {
		return nil, clientErr(http.StatusConflict, wire.ErrConflict, "vault changed on the server (version %d); pull and merge first", cur)
	}
	now := s.now()
	sum := sha256.Sum256(req.Blob)
	v := &wire.Vault{Version: cur + 1, SHA256: hex.EncodeToString(sum[:]), Size: len(req.Blob), CreatedAt: now.UTC().Truncate(time.Second), PushedBy: c.device.ID}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vault_versions (user_id, version, blob, sig, index_json, sha256, pushed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.user.ID, v.Version, req.Blob, req.Sig, index, v.SHA256, v.PushedBy, now.Unix()); err != nil {
		return nil, err
	}
	keepFrom := int64(v.Version) - int64(s.cfg.VaultHistory) //nolint:gosec // versions are small positive counters
	if _, err := tx.ExecContext(ctx, `DELETE FROM vault_versions WHERE user_id = ? AND version <= ?`, c.user.ID, keepFrom); err != nil {
		return nil, err
	}
	if err := s.db.addEvent(ctx, tx, c.user.ID, wire.EventVault, strconv.FormatUint(v.Version, 10), now); err != nil {
		return nil, err
	}
	if err := s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "vault_put", strconv.FormatUint(v.Version, 10), now); err != nil {
		return nil, err
	}
	return v, nil
}

// ---- events and audit ----

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	wait, _ := strconv.Atoi(q.Get("wait"))
	wait = min(max(wait, 0), 30)
	ctx := r.Context()
	if after < 0 {
		last, err := s.db.lastEventID(ctx, c.user.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, wire.Events{Events: []wire.Event{}, Next: last})
		return
	}
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	for {
		ch := s.notify.wait(c.user.ID)
		events, err := s.db.events(ctx, c.user.ID, after)
		if err != nil {
			s.notify.cancel(c.user.ID, ch)
			s.internalError(w, r, err)
			return
		}
		if len(events) > 0 || wait == 0 {
			s.notify.cancel(c.user.ID, ch)
			next := after
			if len(events) > 0 {
				next = events[len(events)-1].ID
			} else {
				events = []wire.Event{}
			}
			writeJSON(w, http.StatusOK, wire.Events{Events: events, Next: next})
			return
		}
		select {
		case <-ch:
		case <-deadline.C:
			s.notify.cancel(c.user.ID, ch)
			writeJSON(w, http.StatusOK, wire.Events{Events: []wire.Event{}, Next: after})
			return
		case <-ctx.Done():
			s.notify.cancel(c.user.ID, ch)
			return
		}
	}
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	entries, err := s.db.auditEntries(r.Context(), c.user.ID, limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if entries == nil {
		entries = []wire.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, wire.Audit{Entries: entries})
}

// ---- commit ----

func (s *Server) apiCommit(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req wire.Commit
	if err := decodeStrict(c.body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if len(req.Links) > maxLinksPer || len(req.DeviceBoxes) > maxBoxesPer || len(req.AgentSlots) > maxSlotsPer {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "commit too large")
		return
	}
	var result wire.CommitResult
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := s.commit(ctx, tx, c, &req)
		if res != nil {
			result = *res
		}
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.notify.wake(c.user.ID)
	writeJSON(w, http.StatusOK, result)
}

// commit applies a commit inside tx. It re-verifies the stored chain, applies
// every new link with the same rules clients use, mirrors the result into the
// device table, and enforces that every active device can read the current
// user key.
func (s *Server) commit(ctx context.Context, tx *sql.Tx, c *reqCtx, req *wire.Commit) (*wire.CommitResult, error) { //nolint:gocyclo,maintidx // one linear validation pass over a commit, kept together for review
	now := s.now()
	stored, err := s.db.chainLinks(ctx, tx, c.user.ID, 0)
	if err != nil {
		return nil, err
	}
	state, err := chain.Verify(c.user.ID, stored)
	if err != nil {
		return nil, fmt.Errorf("stored chain for %s does not verify: %w", c.user.ID, err)
	}
	pending := c.device.Status == wire.DevicePending
	if pending {
		if err := checkPendingCommit(state, c, req); err != nil {
			return nil, err
		}
	}
	slotData := map[string]wire.AgentSlot{}
	for _, sl := range req.AgentSlots {
		if _, dup := slotData[sl.SlotID]; dup {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "duplicate agent slot")
		}
		slotData[sl.SlotID] = sl
	}
	usedSlots := map[string]bool{}
	var initOrRotate bool
	for _, e := range req.Links {
		if e == nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "empty link")
		}
		next, err := state.Next(e)
		if err != nil {
			if l, derr := peekLink(e); derr == nil && l.Seq != state.Seq+1 {
				return nil, clientErr(http.StatusConflict, wire.ErrConflict, "chain changed on the server; refresh and retry")
			}
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "chain link rejected: %v", err)
		}
		l := next.Links[len(next.Links)-1]
		switch l.Type {
		case chain.TypeInit:
			initOrRotate = true
		case chain.TypeUKeyRotate:
			initOrRotate = true
			if err := s.applyRotate(ctx, tx, c.user.ID, next, now); err != nil {
				return nil, err
			}
		case chain.TypeDeviceAdd:
			if err := s.applyDeviceAdd(ctx, tx, c, l, now); err != nil {
				return nil, err
			}
		case chain.TypeDeviceRevoke:
			var b chain.DeviceRevokeBody
			if err := json.Unmarshal(l.Body, &b); err != nil {
				return nil, err
			}
			if err := s.setRevoked(ctx, tx, c.user.ID, b.DeviceID, now); err != nil {
				return nil, err
			}
		case chain.TypeDeviceRename:
			var b chain.DeviceRenameBody
			if err := json.Unmarshal(l.Body, &b); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ? AND user_id = ?`, b.Name, b.DeviceID, c.user.ID); err != nil {
				return nil, err
			}
		case chain.TypeAgentSlotAdd:
			var b chain.AgentSlotAddBody
			if err := json.Unmarshal(l.Body, &b); err != nil {
				return nil, err
			}
			sl, ok := slotData[b.SlotID]
			if !ok || sl.SSHKeyFP != b.SSHKeyFP || !sl.Expires.Equal(b.Expires) || sl.UKeyVersion != next.UKeyVersion || len(sl.Salt) != 32 || len(sl.Box) == 0 || len(sl.Box) > maxBoxSize {
				return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "agent slot %s does not match its chain link", b.SlotID)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO agent_slots (id, user_id, ssh_key_fp, salt, box, ukey_version, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				sl.SlotID, c.user.ID, sl.SSHKeyFP, sl.Salt, sl.Box, sl.UKeyVersion, sl.Expires.Unix(), now.Unix()); err != nil {
				return nil, err
			}
			usedSlots[b.SlotID] = true
		case chain.TypeAgentSlotRemove:
			var b chain.AgentSlotRemoveBody
			if err := json.Unmarshal(l.Body, &b); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE agent_slots SET disabled_at = ? WHERE id = ? AND user_id = ? AND disabled_at = 0`, now.Unix(), b.SlotID, c.user.ID); err != nil {
				return nil, err
			}
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO chain_links (user_id, seq, hash, envelope, created_at) VALUES (?, ?, ?, ?, ?)`, c.user.ID, l.Seq, e.Hash(), raw, now.Unix()); err != nil {
			return nil, err
		}
		if err := s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "chain_"+l.Type, strconv.FormatUint(l.Seq, 10), now); err != nil {
			return nil, err
		}
		state = next
	}
	if len(usedSlots) != len(slotData) {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "agent slot data without a matching chain link")
	}
	for _, b := range req.DeviceBoxes {
		if _, ok := state.ActiveDevice(b.DeviceID); !ok || b.UKeyVersion != state.UKeyVersion || len(b.Box) == 0 || len(b.Box) > maxBoxSize {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "device box for %s is not for an active device at the current key version", b.DeviceID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_boxes (device_id, ukey_version, box, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(device_id, ukey_version) DO UPDATE SET box = excluded.box, created_at = excluded.created_at`, b.DeviceID, b.UKeyVersion, b.Box, now.Unix()); err != nil {
			return nil, err
		}
	}
	if initOrRotate && len(req.Identity) == 0 {
		return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "a new user key needs its master-wrapped identity")
	}
	if len(req.Identity) > 0 {
		if err := checkIdentityBlob(req.Identity, state); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO identity_blobs (user_id, ukey_version, blob, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(user_id, ukey_version) DO UPDATE SET blob = excluded.blob`, c.user.ID, state.UKeyVersion, req.Identity, now.Unix()); err != nil {
			return nil, err
		}
	}
	// Every active device must be able to open the current user key.
	for _, d := range state.ActiveDevices() {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_boxes WHERE device_id = ? AND ukey_version = ?`, d.ID, state.UKeyVersion).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "active device %s has no box for key version %d", d.ID, state.UKeyVersion)
		}
	}
	result := &wire.CommitResult{ChainSeq: state.Seq}
	if req.Vault != nil {
		v, err := s.putVault(ctx, tx, c, req.Vault, state)
		if err != nil {
			return nil, err
		}
		result.VaultVersion = v.Version
	} else if rotated(req, state) {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_versions WHERE user_id = ?`, c.user.ID).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "a key rotation must re-seal the vault")
		}
	}
	if len(req.Links) > 0 {
		if err := s.db.addEvent(ctx, tx, c.user.ID, wire.EventChain, strconv.FormatUint(state.Seq, 10), now); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func rotated(req *wire.Commit, _ *chain.State) bool {
	for _, e := range req.Links {
		if l, err := peekLink(e); err == nil && l.Type == chain.TypeUKeyRotate {
			return true
		}
	}
	return false
}

func peekLink(e *envelope.Envelope) (*chain.Link, error) {
	var l chain.Link
	if err := json.Unmarshal(e.Body, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// checkPendingCommit limits what an unapproved device may commit: creating
// the account (init plus itself as first device), or adding only itself with
// the recovery phrase or an agent slot. Everything it may write is useless
// without the user key, which the chain signatures prove it holds.
func checkPendingCommit(state *chain.State, c *reqCtx, req *wire.Commit) error {
	deny := func(why string) error {
		return clientErr(http.StatusForbidden, wire.ErrForbidden, "an unapproved device %s", why)
	}
	if len(req.AgentSlots) > 0 {
		return deny("cannot add agent slots")
	}
	for _, b := range req.DeviceBoxes {
		if b.DeviceID != c.device.ID {
			return deny("can only store its own device box")
		}
	}
	types := make([]string, 0, len(req.Links))
	for _, e := range req.Links {
		l, err := peekLink(e)
		if err != nil {
			return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid link")
		}
		types = append(types, l.Type)
		if l.Type == chain.TypeDeviceAdd {
			var b chain.DeviceAddBody
			if err := json.Unmarshal(l.Body, &b); err != nil || b.Device.ID != c.device.ID {
				return deny("can only add itself")
			}
		}
	}
	switch {
	case state.Seq == 0 && len(types) == 2 && types[0] == chain.TypeInit && types[1] == chain.TypeDeviceAdd:
		return nil
	case state.Seq > 0 && len(types) == 1 && types[0] == chain.TypeDeviceAdd:
		if req.Vault != nil || len(req.Identity) > 0 {
			return deny("cannot replace the vault or identity")
		}
		return nil
	}
	return deny("can only create the account or add itself")
}

func (s *Server) applyDeviceAdd(ctx context.Context, tx *sql.Tx, c *reqCtx, l chain.Link, now time.Time) error {
	var b chain.DeviceAddBody
	if err := json.Unmarshal(l.Body, &b); err != nil {
		return err
	}
	row, err := s.db.device(ctx, tx, b.Device.ID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (row.UserID != c.user.ID || row.Status != wire.DevicePending || !matchesRow(b.Device, row))) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "device %s is not a pending device of this account", b.Device.ID)
	}
	if err != nil {
		return err
	}
	if !now.Before(row.PendingExpires) {
		return clientErr(http.StatusBadRequest, wire.ErrPendingExpired, "device %s was not approved in time; it must sign in again", b.Device.ID)
	}
	if b.Method == chain.MethodSSHAgent {
		var disabled, expires int64
		err := tx.QueryRowContext(ctx, `SELECT disabled_at, expires_at FROM agent_slots WHERE id = ? AND user_id = ?`, b.Slot, c.user.ID).Scan(&disabled, &expires)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (disabled != 0 || now.Unix() >= expires)) {
			return clientErr(http.StatusForbidden, wire.ErrForbidden, "agent slot %s is disabled or expired", b.Slot)
		}
		if err != nil {
			return err
		}
	}
	proof, err := json.Marshal(b.Proof)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET status = ?, method = ?, proof = ?, pending_expires = 0 WHERE id = ?`, wire.DeviceActive, b.Method, proof, b.Device.ID); err != nil {
		return err
	}
	if err := s.db.addEvent(ctx, tx, c.user.ID, wire.EventDeviceStatus, b.Device.ID, now); err != nil {
		return err
	}
	return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "device_added", b.Device.ID+" via "+b.Method, now)
}

func (s *Server) setRevoked(ctx context.Context, tx *sql.Tx, userID, deviceID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET status = ? WHERE id = ? AND user_id = ?`, wire.DeviceRevoked, deviceID, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at = 0`, now.Unix(), deviceID); err != nil {
		return err
	}
	return s.db.addEvent(ctx, tx, userID, wire.EventDeviceStatus, deviceID, now)
}

func (s *Server) applyRotate(ctx context.Context, tx *sql.Tx, userID string, next *chain.State, now time.Time) error {
	rows, err := s.db.devicesOf(ctx, tx, userID)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if (r.Status == wire.DeviceActive || r.Status == wire.DeviceSuspended) && next.Devices[r.ID] != nil && next.Devices[r.ID].Status == chain.StatusRevoked {
			if err := s.setRevoked(ctx, tx, userID, r.ID, now); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE agent_slots SET disabled_at = ? WHERE user_id = ? AND disabled_at = 0`, now.Unix(), userID)
	return err
}

// checkIdentityBlob checks that a master-wrapped identity names the chain's
// current user key and master key. Its content is encrypted; the header is
// what the server can check.
func checkIdentityBlob(blob []byte, state *chain.State) error {
	if len(blob) > maxBoxSize {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "identity blob too large")
	}
	h, err := identity.ReadHeader(blob)
	if err != nil {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid identity blob: %v", err)
	}
	if h.Version != 3 || h.IdentityPublic != state.EncPub || !bytes.Equal(h.SignPublic[:], state.SignPub) || h.MasterPublic != state.MasterPub {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "identity blob does not match the current user key")
	}
	return nil
}

var (
	indexEnvName = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	indexPubKey  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// checkIndex validates a published index. It is shown in the web UI, so
// every string is constrained, and its size is bounded.
func checkIndex(raw []byte) error {
	if len(raw) > 512<<10 {
		return errors.New("too large")
	}
	var idx wire.VaultIndex
	if err := decodeStrict(raw, &idx); err != nil {
		return err
	}
	if len(idx.Projects) > 1000 {
		return errors.New("too many projects")
	}
	for _, p := range idx.Projects {
		if p.ID != "default" && projectfile.ValidateOrgRepo(p.ID) != nil {
			return fmt.Errorf("invalid project id %q", p.ID)
		}
		if len(p.Environments) > 200 || p.OtherKeys < 0 || p.OtherKeys > 10000 {
			return fmt.Errorf("project %s has too many keys", p.ID)
		}
		for _, e := range p.Environments {
			if len(e.Name) > 128 || !indexEnvName.MatchString(e.Name) || !indexPubKey.MatchString(e.PublicKey) {
				return fmt.Errorf("invalid environment in %s", p.ID)
			}
		}
	}
	return nil
}

// latestIndex returns the newest published index and when it was pushed.
func (s *Server) latestIndex(ctx context.Context, userID string) (*wire.VaultIndex, *wire.Vault, error) {
	var raw []byte
	var v wire.Vault
	var created int64
	err := s.db.sql.QueryRowContext(ctx, `SELECT version, index_json, pushed_by, created_at FROM vault_versions WHERE user_id = ? ORDER BY version DESC LIMIT 1`, userID).Scan(&v.Version, &raw, &v.PushedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	v.CreatedAt = fromUnix(created)
	if len(raw) == 0 {
		return nil, &v, nil
	}
	var idx wire.VaultIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, nil, err
	}
	return &idx, &v, nil
}
