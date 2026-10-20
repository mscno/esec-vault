package server

// Passkeys on the web pages. A person registers a passkey in the browser;
// that only proposes it, and one of their devices adds it to their user
// chain as a delegate (esec vault changes). From then on, a change made on
// the pages can be signed with the passkey: the server builds the link, the
// browser asks the passkey to sign its hash, and the server checks the
// signature and commits the link like a device's.
//
// The page's script comes from this server, so a person registering a
// passkey trusts the server at that moment, and a passkey signs what the
// page asks it to. Devices check every signature and the delegate's scope,
// which never covers making an admin or sealing keys, and a member added
// with a passkey gets keys only after an admin's device checked their
// GitHub SSH proof.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/wire"
)

const ceremonyLifetime = 5 * time.Minute

// ceremonies are passkey registrations and signatures in progress, by web
// session.
type ceremonies struct {
	mu   sync.Mutex
	reg  map[string]registration
	sign map[string]signing
}

type registration struct {
	challenge []byte
	expires   time.Time
}

type signing struct {
	change   int64
	delegate string
	links    []*envelope.Envelope
	expires  time.Time
}

func (c *ceremonies) prune(now time.Time) {
	for k, v := range c.reg {
		if now.After(v.expires) {
			delete(c.reg, k)
		}
	}
	for k, v := range c.sign {
		if now.After(v.expires) {
			delete(c.sign, k)
		}
	}
}

// jsonAction runs a JSON request of a page's script: signed in, from this
// site's origin (required), with the page's CSRF token in X-CSRF-Token.
func (s *Server) jsonAction(w http.ResponseWriter, r *http.Request, in any, fn func(ctx context.Context, ws *webSession) (any, error)) {
	fail := func(status int, msg string) {
		writeJSON(w, status, map[string]string{"error": msg})
	}
	ws, err := s.webSession(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if ws == nil {
		fail(http.StatusUnauthorized, "You were signed out. Reload the page to sign in again.")
		return
	}
	got := r.Header.Get("X-Csrf-Token")
	if r.Header.Get("Origin") != s.cfg.BaseURL || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(ws.csrf)) != 1 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(http.StatusForbidden, "The page expired. Reload it and try again.")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		fail(http.StatusBadRequest, "invalid request")
		return
	}
	if in != nil {
		if err := envelope.DecodeStrict(raw, in); err != nil {
			fail(http.StatusBadRequest, "invalid request")
			return
		}
	}
	out, err := fn(r.Context(), ws)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			fail(ae.status, ae.desc)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) rpID() string {
	u, err := url.Parse(s.cfg.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// webPasskeyOptions starts registering a passkey.
func (s *Server) webPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	s.jsonAction(w, r, nil, func(ctx context.Context, ws *webSession) (any, error) {
		first, err := s.db.firstLink(ctx, ws.user.ID)
		if err != nil {
			return nil, err
		}
		if first == nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "Create your vault account on a device first.")
		}
		ds, err := s.delegatesOf(ctx, ws.user.ID)
		if err != nil {
			return nil, err
		}
		challenge := make([]byte, 32)
		_, _ = rand.Read(challenge)
		now := s.now()
		s.webauthn.mu.Lock()
		s.webauthn.prune(now)
		if s.webauthn.reg == nil {
			s.webauthn.reg = map[string]registration{}
		}
		s.webauthn.reg[ws.idHash] = registration{challenge: challenge, expires: now.Add(ceremonyLifetime)}
		s.webauthn.mu.Unlock()
		exclude := []string{}
		for _, d := range ds.passkeys {
			exclude = append(exclude, b64u(d.CredentialID))
		}
		return map[string]any{
			"challenge": b64u(challenge), "rpId": s.rpID(), "rpName": "esec vault",
			"userId": b64u([]byte(ws.user.ID)), "userName": ws.user.Login, "exclude": exclude,
		}, nil
	})
}

// passkeyRegistration is what the page sends once the browser made a
// passkey.
type passkeyRegistration struct {
	Name           string `json:"name"`
	Scope          string `json:"scope"`
	CredentialID   string `json:"credentialId"`
	PublicKey      string `json:"publicKey"`
	Alg            int    `json:"alg"`
	ClientDataJSON string `json:"clientDataJSON"`
}

// webPasskeyRegister proposes a new passkey for a device to add.
func (s *Server) webPasskeyRegister(w http.ResponseWriter, r *http.Request) {
	var in passkeyRegistration
	s.jsonAction(w, r, &in, func(ctx context.Context, ws *webSession) (any, error) {
		now := s.now()
		s.webauthn.mu.Lock()
		reg, ok := s.webauthn.reg[ws.idHash]
		delete(s.webauthn.reg, ws.idHash)
		s.webauthn.mu.Unlock()
		if !ok || now.After(reg.expires) {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "That took too long. Try again.")
		}
		var cd struct {
			Type      string `json:"type"`
			Challenge string `json:"challenge"`
			Origin    string `json:"origin"`
		}
		raw, err1 := base64.RawURLEncoding.DecodeString(in.ClientDataJSON)
		credID, err2 := base64.RawURLEncoding.DecodeString(in.CredentialID)
		pub, err3 := base64.RawURLEncoding.DecodeString(in.PublicKey)
		if errors.Join(err1, err2, err3) != nil || json.Unmarshal(raw, &cd) != nil || cd.Type != "webauthn.create" || cd.Origin != s.cfg.BaseURL || cd.Challenge != b64u(reg.challenge) {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "The browser's answer does not match. Try again.")
		}
		scope := chain.ScopeManage
		if in.Scope == chain.ScopeRemove {
			scope = chain.ScopeRemove
		}
		d := chain.Delegate{ID: randomID("dl_"), Kind: chain.DelegatePasskey, Name: strings.TrimSpace(in.Name), Scope: scope, Alg: in.Alg, PublicKey: pub, CredentialID: credID, RPID: s.rpID(), Origin: s.cfg.BaseURL, Created: now.UTC().Truncate(time.Second)}
		if err := chain.ValidateDelegate(d); err != nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "%s", err.Error())
		}
		data, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		if err := s.propose(ctx, ws.user.ID, s.clientIP(r), wire.Change{Scope: wire.ScopeAccount, Target: ws.user.ID, Kind: wire.ChangeDelegateAdd, Subject: d.ID, Data: data}); err != nil {
			return nil, err
		}
		return map[string]string{"words": chain.DelegateWords(d), "message": "Now add it from one of your devices: esec vault changes. Check that it shows the same words."}, nil
	})
}

// passkeySign is what the page sends to sign a change.
type passkeySign struct {
	Delegate   string            `json:"delegate"`
	Assertions []passkeyResponse `json:"assertions,omitempty"`
}

type passkeyResponse struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// openChange returns an open change user may sign.
func (s *Server) openChange(ctx context.Context, user string, id int64) (*wire.Change, error) {
	cs, err := s.adminChanges(ctx, user)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.ID == id {
			return &c, nil
		}
	}
	return nil, clientErr(http.StatusNotFound, wire.ErrNotFound, "That change was signed or dismissed already.")
}

// webPasskeyBegin builds the links of a change for a passkey to sign and
// returns what it signs.
func (s *Server) webPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	var in passkeySign
	s.jsonAction(w, r, &in, func(ctx context.Context, ws *webSession) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid change id")
		}
		c, err := s.openChange(ctx, ws.user.ID, id)
		if err != nil {
			return nil, err
		}
		if c.Scope == wire.ScopeAccount {
			return nil, errNeedsDevice
		}
		ds, err := s.delegatesOf(ctx, ws.user.ID)
		if err != nil {
			return nil, err
		}
		d := ds.passkey(in.Delegate)
		if d == nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "That passkey is not one your devices added.")
		}
		links, err := s.changeLinks(ctx, ws.user.ID, ds.cs, d, *c)
		if err != nil {
			return nil, err
		}
		challenges := make([]string, 0, len(links))
		for _, e := range links {
			challenges = append(challenges, b64u(e.Challenge()))
		}
		now := s.now()
		s.webauthn.mu.Lock()
		s.webauthn.prune(now)
		if s.webauthn.sign == nil {
			s.webauthn.sign = map[string]signing{}
		}
		s.webauthn.sign[ws.idHash] = signing{change: id, delegate: d.ID, links: links, expires: now.Add(ceremonyLifetime)}
		s.webauthn.mu.Unlock()
		return map[string]any{"rpId": d.RPID, "credentialId": b64u(d.CredentialID), "challenges": challenges, "text": passkeyDescribe(*c)}, nil
	})
}

// webPasskeyFinish checks the passkey's signatures and commits the change.
func (s *Server) webPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	var in passkeySign
	s.jsonAction(w, r, &in, func(ctx context.Context, ws *webSession) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid change id")
		}
		now := s.now()
		s.webauthn.mu.Lock()
		sg, ok := s.webauthn.sign[ws.idHash]
		delete(s.webauthn.sign, ws.idHash)
		s.webauthn.mu.Unlock()
		if !ok || sg.change != id || now.After(sg.expires) || len(in.Assertions) != len(sg.links) {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "That took too long, or the page changed. Try again.")
		}
		for i, e := range sg.links {
			a := in.Assertions[i]
			var as envelope.Assertion
			var errs [4]error
			as.CredentialID, errs[0] = base64.RawURLEncoding.DecodeString(a.CredentialID)
			as.AuthenticatorData, errs[1] = base64.RawURLEncoding.DecodeString(a.AuthenticatorData)
			as.ClientDataJSON, errs[2] = base64.RawURLEncoding.DecodeString(a.ClientDataJSON)
			as.Signature, errs[3] = base64.RawURLEncoding.DecodeString(a.Signature)
			if errors.Join(errs[:]...) != nil {
				return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid passkey answer")
			}
			e.Passkey = &as
		}
		if err := s.checkDelegateLinks(ctx, sg.links); err != nil {
			return nil, clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "The passkey's signature was refused: %v", err)
		}
		if err := s.commitDelegateLinks(ctx, ws.user.ID, s.clientIP(r), sg.links); err != nil {
			return nil, err
		}
		if err := s.closeChange(ctx, id, true, ws.user.ID, s.clientIP(r)); err != nil {
			return nil, err
		}
		return map[string]string{"message": "Signed with your passkey. Admins' devices send any keys it needs on their next sync."}, nil
	})
}
