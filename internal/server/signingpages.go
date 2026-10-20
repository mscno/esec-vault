package server

import (
	"context"
	"net/http"
	"slices"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/wire"
)

// passkeyView is a passkey as the signing page shows it.
type passkeyView struct {
	*chain.DelegateState

	Words string
}

// pendingDelegate is a delegate waiting for a device to add or remove it.
type pendingDelegate struct {
	wire.Change

	Delegate *chain.Delegate
	Words    string
}

// webSigning shows the ways a person can sign changes without a terminal:
// their devices' dialogs, passkeys, and the server for removals.
func (s *Server) webSigning(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	data, err := s.signingPageData(r.Context(), ws)
	if err != nil {
		s.webFail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "signing.html", data)
}

func (s *Server) signingPageData(ctx context.Context, ws *webSession) (map[string]any, error) {
	data := s.page(ws, "account")
	first, err := s.db.firstLink(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	if first == nil {
		data["NoAccount"] = true
		return data, nil
	}
	ds, err := s.delegatesOf(ctx, ws.user.ID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]passkeyView, 0, len(ds.passkeys))
	for _, d := range ds.passkeys {
		passkeys = append(passkeys, passkeyView{DelegateState: d, Words: chain.DelegateWords(d.Delegate)})
	}
	changes, err := s.db.openChanges(ctx, wire.ScopeAccount, ws.user.ID)
	if err != nil {
		return nil, err
	}
	var pending []pendingDelegate
	for _, c := range changes {
		p := pendingDelegate{Change: c}
		if c.Kind == wire.ChangeDelegateAdd {
			var d chain.Delegate
			if err := jsonUnmarshal(c.Data, &d); err == nil {
				p.Delegate, p.Words = &d, chain.DelegateWords(d)
			}
		}
		pending = append(pending, p)
	}
	data["Passkeys"] = passkeys
	data["Server"] = ds.server
	data["Pending"] = pending
	data["ServerPending"] = slices.ContainsFunc(changes, func(c wire.Change) bool { return c.Kind == wire.ChangeDelegateServer })
	return data, nil
}

// signingForm runs a form of the signing page.
func (s *Server) signingForm(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, ws *webSession) (string, error)) {
	s.pageForm(w, r, "/account/signing", fn, func(ctx context.Context, ws *webSession) (map[string]any, []string, error) {
		data, err := s.signingPageData(ctx, ws)
		return data, []string{"signing-body"}, err
	})
}

// webDelegateServer proposes letting the server sign removals.
func (s *Server) webDelegateServer(w http.ResponseWriter, r *http.Request) {
	s.signingForm(w, r, func(ctx context.Context, ws *webSession) (string, error) {
		return "Now allow it from one of your devices: esec vault changes", s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDelegateServer, Subject: "server"})
	})
}

// webDelegateRemove proposes removing a delegate. Removing one is signed
// by the user key, so it waits for a device too.
func (s *Server) webDelegateRemove(w http.ResponseWriter, r *http.Request) {
	s.signingForm(w, r, func(ctx context.Context, ws *webSession) (string, error) {
		id := r.PathValue("id")
		ds, err := s.delegatesOf(ctx, ws.user.ID)
		if err != nil {
			return "", err
		}
		d, ok := ds.cs.Delegates[id]
		if !ok || !d.Active {
			return "", clientErr(http.StatusNotFound, wire.ErrNotFound, "No such passkey.")
		}
		return "Now remove it from one of your devices: esec vault changes", s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDelegateRemove, Subject: id})
	})
}

// addPasskeys adds the person's passkeys to a page that lists changes, so
// it can offer to sign them.
func (s *Server) addPasskeys(ctx context.Context, ws *webSession, data map[string]any) {
	if ds, err := s.delegatesOf(ctx, ws.user.ID); err == nil {
		data["Passkeys"] = ds.passkeys
	}
}
