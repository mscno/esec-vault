package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/wire"
)

const (
	webSessionTTL   = 12 * time.Hour
	oauthStateTTL   = 10 * time.Minute
	knownBrowserTTL = 180 * 24 * time.Hour
)

// knownBrowser reports whether the request carries the cookie of a browser
// that signed in before, for an account that is still allowed.
func (s *Server) knownBrowser(r *http.Request) bool {
	c, err := r.Cookie(s.cookieName("esec_known"))
	if err != nil || c.Value == "" {
		return false
	}
	var userID string
	var expires int64
	if err := s.db.sql.QueryRowContext(r.Context(), `SELECT user_id, expires_at FROM known_browsers WHERE token_hash = ?`, hashHex(c.Value)).Scan(&userID, &expires); err != nil {
		return false
	}
	if s.now().Unix() >= expires {
		return false
	}
	u, err := s.db.user(r.Context(), userID)
	return err == nil && s.cfg.Allowed(u.GitHubID)
}

type webSession struct {
	user *userRow
	csrf string
}

func (s *Server) cookieName(base string) string {
	if s.cfg.Secure() {
		return "__Host-" + base
	}
	return base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set whenever the server runs on https; plain http is allowed only on localhost
		Name:     s.cookieName(name),
		Value:    value,
		Path:     path,
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name, path string) {
	s.setCookie(w, name, "", path, -time.Second)
}

// webSession returns the signed-in browser session, or nil.
func (s *Server) webSession(r *http.Request) (*webSession, error) {
	c, err := r.Cookie(s.cookieName("esec_session"))
	if errors.Is(err, http.ErrNoCookie) || (err == nil && c.Value == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var userID, csrf string
	var expires int64
	err = s.db.sql.QueryRowContext(r.Context(), `SELECT user_id, csrf, expires_at FROM web_sessions WHERE id_hash = ?`, hashHex(c.Value)).Scan(&userID, &csrf, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.now().Unix() >= expires {
		return nil, nil
	}
	u, err := s.db.user(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	if !s.cfg.Allowed(u.GitHubID) {
		return nil, nil
	}
	return &webSession{user: u, csrf: csrf}, nil
}

// checkForm verifies the CSRF token and, when present, the Origin header.
func (s *Server) checkForm(r *http.Request, ws *webSession) bool {
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.BaseURL {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	got := r.PostForm.Get("csrf")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(ws.csrf)) == 1
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template failed", "template", name, "error", err)
	}
}

func (s *Server) webError(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "error.html", map[string]any{"Message": msg})
}

// safeNext accepts only same-site paths the login flow may return to.
func safeNext(next string) string {
	if next == "/projects" {
		return next
	}
	if next == "" {
		return "/account"
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return "/account"
	}
	switch u.Path {
	case "/account":
		return "/account"
	case "/device":
		return "/device"
	}
	return "/account"
}

func (s *Server) requireWeb(w http.ResponseWriter, r *http.Request) *webSession {
	ws, err := s.webSession(r)
	if err != nil {
		s.internalError(w, r, err)
		return nil
	}
	if ws == nil {
		http.Redirect(w, r, "/auth/github?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
		return nil
	}
	return ws
}

func (s *Server) webIndex(w http.ResponseWriter, r *http.Request) {
	ws, err := s.webSession(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if ws != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "index.html", map[string]any{})
}

func (s *Server) webGitHubStart(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if !s.allowAnon("oauth", s.clientIP(r), 30, 300, time.Hour) {
		s.webError(w, http.StatusTooManyRequests, "Too many sign-in attempts from this address. Try again later.")
		return
	}
	var open int
	if err := s.db.sql.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM oauth_states WHERE created_at > ?`, now.Add(-oauthStateTTL).Unix()).Scan(&open); err != nil {
		s.internalError(w, r, err)
		return
	}
	if open >= s.maxOAuthStates && !s.knownBrowser(r) {
		s.webError(w, http.StatusServiceUnavailable, "Too many sign-ins in progress. Try again in a few minutes.")
		return
	}
	state := randomToken("")
	verifier := randomToken("")
	next := safeNext(r.URL.Query().Get("next"))
	if _, err := s.db.sql.ExecContext(r.Context(), `INSERT INTO oauth_states (state_hash, verifier, next, created_at) VALUES (?, ?, ?, ?)`, hashHex(state), verifier, next, now.Unix()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setCookie(w, "esec_oauth", state, "/", oauthStateTTL)
	http.Redirect(w, r, s.github.AuthorizeURL(s.cfg.BaseURL+"/auth/github/callback", state, pkceChallenge(verifier)), http.StatusSeeOther)
}

func (s *Server) webGitHubCallback(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ctx := r.Context()
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	cookie, err := r.Cookie(s.cookieName("esec_oauth"))
	s.clearCookie(w, "esec_oauth", "/")
	if err != nil || state == "" || code == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.webError(w, http.StatusBadRequest, "The sign-in link is invalid or was opened in another browser. Start again.")
		return
	}
	var verifier, next string
	var created int64
	err = s.db.sql.QueryRowContext(ctx, `DELETE FROM oauth_states WHERE state_hash = ? RETURNING verifier, next, created_at`, hashHex(state)).Scan(&verifier, &next, &created)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && now.Sub(fromUnix(created)) > oauthStateTTL) {
		s.webError(w, http.StatusBadRequest, "The sign-in attempt expired. Start again.")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	exCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	gh, err := s.github.Exchange(exCtx, s.cfg.BaseURL+"/auth/github/callback", code, verifier)
	if err != nil {
		s.log.Warn("github exchange failed", "error", err)
		s.webError(w, http.StatusBadGateway, "GitHub sign-in failed. Start again.")
		return
	}
	ip := s.clientIP(r)
	if !s.cfg.Allowed(gh.ID) {
		if err := s.db.audit(ctx, s.db.sql, "", "", ip, "login_denied", userID(gh.ID)+" "+gh.Login, now); err != nil {
			s.internalError(w, r, err)
			return
		}
		s.webError(w, http.StatusForbidden, "This GitHub account is not allowed on this server. Ask the server owner to add its numeric GitHub ID.")
		return
	}
	u, err := s.db.upsertUser(ctx, gh.ID, gh.Login, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sid := randomToken("")
	if _, err := s.db.sql.ExecContext(ctx, `INSERT INTO web_sessions (id_hash, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hashHex(sid), u.ID, randomToken(""), now.Unix(), now.Add(webSessionTTL).Unix()); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.db.audit(ctx, s.db.sql, u.ID, "", ip, "web_login", gh.Login, now); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setCookie(w, "esec_session", sid, "/", webSessionTTL)
	// Remember this browser: during a flood of sign-in attempts, browsers
	// that signed in before skip the server-wide cap.
	known := randomToken("")
	if _, err := s.db.sql.ExecContext(ctx, `INSERT INTO known_browsers (token_hash, user_id, expires_at) VALUES (?, ?, ?)`, hashHex(known), u.ID, now.Add(knownBrowserTTL).Unix()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setCookie(w, "esec_known", known, "/", knownBrowserTTL)
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) webLogout(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	if c, err := r.Cookie(s.cookieName("esec_session")); err == nil {
		if _, err := s.db.sql.ExecContext(r.Context(), `DELETE FROM web_sessions WHERE id_hash = ?`, hashHex(c.Value)); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if c, err := r.Cookie(s.cookieName("esec_known")); err == nil {
		if _, err := s.db.sql.ExecContext(r.Context(), `DELETE FROM known_browsers WHERE token_hash = ?`, hashHex(c.Value)); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.clearCookie(w, "esec_session", "/")
	s.clearCookie(w, "esec_known", "/")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) webDevice(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	// A code in the link is ignored on purpose: the person must type the
	// code shown in their own terminal, so a link someone else sends cannot
	// carry the attacker's code.
	s.render(w, http.StatusOK, "device.html", map[string]any{"User": ws.user, "CSRF": ws.csrf})
}

// allowCode reserves one code attempt for the address and the signed-in
// user, on both the entry and the confirmation form. The reservation is
// counted before the lookup, so parallel requests cannot overshoot; a code
// that turns out valid gives it back (see goodCode), so only wrong codes
// add up.
func (s *Server) allowCode(r *http.Request, ws *webSession) bool {
	now := s.now()
	if !s.limits.allow("code:user:"+ws.user.ID, 10, 10*time.Minute, now) {
		return false
	}
	if !s.limits.allow("code:ip:"+rateKey(s.clientIP(r)), 30, time.Hour, now) {
		s.limits.refund("code:user:" + ws.user.ID)
		return false
	}
	return true
}

// goodCode refunds the reservation of a valid code.
func (s *Server) goodCode(r *http.Request, ws *webSession) {
	s.limits.refund("code:ip:" + rateKey(s.clientIP(r)))
	s.limits.refund("code:user:" + ws.user.ID)
}

// pendingCode is a device code waiting for confirmation, with its device.
type pendingCode struct {
	code     string
	device   *deviceRow
	existing *deviceRow
}

func (s *Server) lookupCode(ctx context.Context, userIDv, input string) (*pendingCode, error) {
	norm := normalizeUserCode(input)
	if norm == "" {
		return nil, nil
	}
	var deviceID, status string
	var expires int64
	err := s.db.sql.QueryRowContext(ctx, `SELECT device_id, status, expires_at FROM device_codes WHERE user_code_hash = ?`, hashHex(norm)).Scan(&deviceID, &status, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != "pending" || s.now().Unix() >= expires {
		return nil, nil
	}
	dev, err := s.db.device(ctx, s.db.sql, deviceID)
	if err != nil {
		return nil, err
	}
	pc := &pendingCode{code: formatUserCode(norm), device: dev}
	mine, err := s.db.devicesOf(ctx, s.db.sql, userIDv)
	if err != nil {
		return nil, err
	}
	for _, d := range mine {
		if d.SignPub == dev.SignPub && d.EncPub == dev.EncPub && d.ID != dev.ID {
			pc.existing = d
		}
	}
	return pc, nil
}

func (s *Server) webDeviceLookup(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	if !s.allowCode(r, ws) {
		s.webError(w, http.StatusTooManyRequests, "Too many codes entered. Wait a few minutes and try again.")
		return
	}
	pc, err := s.lookupCode(r.Context(), ws.user.ID, r.PostForm.Get("code"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if pc == nil {
		s.render(w, http.StatusOK, "device.html", map[string]any{"User": ws.user, "CSRF": ws.csrf, "Error": "That code is not valid or has expired. Check the code in your terminal."})
		return
	}
	s.goodCode(r, ws)
	s.render(w, http.StatusOK, "confirm.html", map[string]any{
		"User":     ws.user,
		"CSRF":     ws.csrf,
		"Code":     pc.code,
		"Device":   pc.device,
		"Existing": pc.existing,
		"Words":    devicekey.Words(pc.device.EncPub, pc.device.SignPub),
	})
}

func (s *Server) webDeviceConfirm(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	if !s.allowCode(r, ws) {
		s.webError(w, http.StatusTooManyRequests, "Too many codes entered. Wait a few minutes and try again.")
		return
	}
	ctx := r.Context()
	now := s.now()
	pc, err := s.lookupCode(ctx, ws.user.ID, r.PostForm.Get("code"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if pc == nil {
		s.webError(w, http.StatusBadRequest, "That code is no longer valid. Run 'esec vault login' again.")
		return
	}
	s.goodCode(r, ws)
	approve := r.PostForm.Get("decision") == "approve"
	status, action := "denied", "device_code_denied"
	if approve {
		status, action = "confirmed", "device_code_confirmed"
	}
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE device_codes SET status = ?, user_id = ? WHERE user_code_hash = ? AND status = 'pending'`, status, ws.user.ID, hashHex(normalizeUserCode(pc.code)))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return clientErr(http.StatusConflict, wire.ErrConflict, "code already used")
		}
		return s.db.audit(ctx, tx, ws.user.ID, pc.device.ID, s.clientIP(r), action, pc.device.Name, now)
	})
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			s.webError(w, http.StatusConflict, "That code was already used.")
			return
		}
		s.internalError(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "done.html", map[string]any{"User": ws.user, "Approved": approve, "Existing": pc.existing, "Device": pc.device})
}

type deviceView struct {
	*deviceRow

	Sessions int
	Words    string
}

func (s *Server) webAccount(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	rows, err := s.db.devicesOf(ctx, s.db.sql, ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var devices []deviceView
	for _, d := range rows {
		if d.Status == wire.DeviceRegistering || (d.Status == wire.DevicePending && !now.Before(d.PendingExpires)) {
			continue
		}
		var n int
		if err := s.db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE device_id = ? AND revoked_at = 0 AND expires_at > ?`, d.ID, now.Unix()).Scan(&n); err != nil {
			s.internalError(w, r, err)
			return
		}
		devices = append(devices, deviceView{deviceRow: d, Sessions: n, Words: devicekey.Words(d.EncPub, d.SignPub)})
	}
	slots, err := s.slots(ctx, ws.user.ID, now, true)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	audit, err := s.db.auditEntries(ctx, ws.user.ID, 100)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	links, err := s.db.chainLinks(ctx, s.db.sql, ws.user.ID, 0)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	accountWords := ""
	if st, err := chain.Verify(ws.user.ID, links); err == nil {
		accountWords = st.AccountWords()
	}
	s.render(w, http.StatusOK, "account.html", map[string]any{
		"User": ws.user, "CSRF": ws.csrf, "Devices": devices, "Slots": slots, "Audit": audit,
		"AccountWords": accountWords, "Now": now,
	})
}

// webAction runs a CSRF-checked account form action and returns to the
// account page.
func (s *Server) webAction(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, ws *webSession) error) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	if err := fn(r.Context(), ws); err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			s.webError(w, ae.status, ae.desc)
			return
		}
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) webSuspendDevice(w http.ResponseWriter, r *http.Request) {
	s.webAction(w, r, func(ctx context.Context, ws *webSession) error {
		return s.suspend(ctx, ws.user.ID, "", r.PathValue("id"), s.clientIP(r))
	})
}

func (s *Server) webEndSessions(w http.ResponseWriter, r *http.Request) {
	s.webAction(w, r, func(ctx context.Context, ws *webSession) error {
		now := s.now()
		device := r.PathValue("device")
		return s.db.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE device_id = ? AND user_id = ? AND revoked_at = 0`, now.Unix(), device, ws.user.ID); err != nil {
				return err
			}
			return s.db.audit(ctx, tx, ws.user.ID, "", s.clientIP(r), "sessions_ended", device, now)
		})
	})
}

func (s *Server) webDisableSlot(w http.ResponseWriter, r *http.Request) {
	s.webAction(w, r, func(ctx context.Context, ws *webSession) error {
		return s.disableSlot(ctx, ws.user.ID, "", r.PathValue("id"), s.clientIP(r))
	})
}

func (s *Server) webProjects(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	idx, v, err := s.latestIndex(r.Context(), ws.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := map[string]any{"User": ws.user, "CSRF": ws.csrf, "Index": idx, "Vault": v}
	if v != nil {
		if d, err := s.db.device(r.Context(), s.db.sql, v.PushedBy); err == nil {
			data["PushedBy"] = d.Name
		}
	}
	s.render(w, http.StatusOK, "projects.html", data)
}
