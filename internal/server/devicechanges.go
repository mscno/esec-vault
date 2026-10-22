package server

// Device changes started on the web. Adding, renaming and revoking a device
// are links of the person's own user chain, which only their user key
// signs, on one of their devices: the page proposes them, and the device
// shows each and signs it (esec vault changes, or its dialog). To approve a
// new device, the person types the words that device shows into the
// approving device; the page never takes them, since the server could
// swap the device it proposes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/wire"
)

// deviceForm runs a form about one of the viewer's devices.
func (s *Server) deviceForm(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, ws *webSession, d *deviceRow) (string, error)) {
	id := r.PathValue("id")
	s.pageForm(w, r, "/devices/"+id, func(ctx context.Context, ws *webSession) (string, error) {
		d, err := s.db.device(ctx, s.db.sql, id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && d.UserID != ws.user.ID) {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "There is no such device on your account.")
		}
		if err != nil {
			return "", err
		}
		return fn(ctx, ws, d)
	}, func(_ context.Context, ws *webSession) (map[string]any, []string, error) {
		return s.page(ws, "account"), nil, nil
	})
}

func (s *Server) webDeviceApproveChange(w http.ResponseWriter, r *http.Request) {
	s.deviceForm(w, r, func(ctx context.Context, ws *webSession, d *deviceRow) (string, error) {
		if d.Status != wire.DevicePending || !s.now().Before(d.PendingExpires) {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "That device is not waiting for approval.")
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDeviceApprove, Subject: d.ID}); err != nil {
			return "", err
		}
		return "Asked your devices. On one of them, run esec vault changes and type the words " + d.Name + " shows on its own screen.", nil
	})
}

func (s *Server) webDeviceRenameChange(w http.ResponseWriter, r *http.Request) {
	s.deviceForm(w, r, func(ctx context.Context, ws *webSession, d *deviceRow) (string, error) {
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if chain.ValidDeviceName(name) != nil {
			return "", clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "A device name is 1-64 letters, digits, spaces or ._()'- characters.")
		}
		if d.Status != wire.DeviceActive {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "Only an active device is renamed.")
		}
		data, err := json.Marshal(map[string]string{"name": name})
		if err != nil {
			return "", err
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDeviceRename, Subject: d.ID, Data: data}); err != nil {
			return "", err
		}
		return "Asked your devices; one signs the new name (esec vault changes).", nil
	})
}

func (s *Server) webDeviceRevokeChange(w http.ResponseWriter, r *http.Request) {
	s.deviceForm(w, r, func(ctx context.Context, ws *webSession, d *deviceRow) (string, error) {
		if d.Method == "" || (d.Status != wire.DeviceActive && d.Status != wire.DeviceSuspended) {
			return "", clientErr(http.StatusConflict, wire.ErrConflict, "That device was never approved: suspending it is enough.")
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDeviceRevoke, Subject: d.ID}); err != nil {
			return "", err
		}
		return "Asked your other devices; one revokes it and gives your account a new user key (esec vault changes). Suspend it too, to block it at once.", nil
	})
}
