package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

// alertAddresses returns an account's confirmed alert address and one that
// waits for confirmation.
func (d *DB) alertAddresses(ctx context.Context, userID string, now time.Time) (email, pending string, err error) {
	var expires int64
	err = d.sql.QueryRowContext(ctx, `SELECT alert_email, alert_email_pending, alert_email_expires FROM users WHERE id = ?`, userID).Scan(&email, &pending, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if now.Unix() >= expires {
		pending = ""
	}
	return email, pending, err
}

// webSetAlertEmail starts confirming a new alert address: the address gets a
// link, and alerts go there only once it is opened.
func (s *Server) webSetAlertEmail(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	if !s.cfg.Alerts.Email() {
		s.webError(w, http.StatusNotFound, "This server does not send email alerts.")
		return
	}
	addr, err := parseEmail(strings.TrimSpace(r.PostForm.Get("email")))
	if err != nil {
		s.webError(w, http.StatusBadRequest, "That is not an email address. Give one such as name@example.com.")
		return
	}
	now := s.now()
	if !s.limits.allow("alert-email:"+ws.user.ID, 5, time.Hour, now) {
		s.webError(w, http.StatusTooManyRequests, "Too many confirmation emails. Wait an hour and try again.")
		return
	}
	ctx := r.Context()
	token := randomToken("")
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET alert_email_pending = ?, alert_email_token = ?, alert_email_expires = ? WHERE id = ?`,
			addr, hashHex(token), now.Add(confirmTTL).Unix(), ws.user.ID); err != nil {
			return err
		}
		a := s.emailAlert(ws.user, alertEmailConfirm, addr, s.cfg.BaseURL+"/alerts/confirm?token="+token, now)
		if err := s.queueEmail(ctx, tx, a, addr); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, ws.user.ID, "", s.clientIP(r), "alert_email_requested", addr, now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.kickAlerts()
	http.Redirect(w, r, "/account#alerts", http.StatusSeeOther)
}

// webRemoveAlertEmail stops alert emails to the account's address, and tells
// that address.
func (s *Server) webRemoveAlertEmail(w http.ResponseWriter, r *http.Request) {
	ws := s.requireWeb(w, r)
	if ws == nil {
		return
	}
	if !s.checkForm(r, ws) {
		s.webError(w, http.StatusForbidden, "The form expired. Reload the page and try again.")
		return
	}
	ctx := r.Context()
	now := s.now()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT alert_email FROM users WHERE id = ?`, ws.user.ID).Scan(&old); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET alert_email = '', alert_email_pending = '', alert_email_token = '', alert_email_expires = 0 WHERE id = ?`, ws.user.ID); err != nil {
			return err
		}
		if old != "" && s.cfg.Alerts.Email() {
			if err := s.queueEmail(ctx, tx, s.emailAlert(ws.user, alertEmailChanged, "", "", now), old); err != nil {
				return err
			}
		}
		return s.db.audit(ctx, tx, ws.user.ID, "", s.clientIP(r), "alert_email_removed", old, now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.kickAlerts()
	http.Redirect(w, r, "/account#alerts", http.StatusSeeOther)
}

// pendingConfirm finds the account whose confirmation link carries token.
func (s *Server) pendingConfirm(ctx context.Context, token string, now time.Time) (*userRow, string, error) {
	if token == "" || len(token) > 128 {
		return nil, "", nil
	}
	u := &userRow{}
	var addr string
	err := s.db.sql.QueryRowContext(ctx, `SELECT id, github_id, login, alert_email_pending FROM users WHERE alert_email_token = ? AND alert_email_expires > ? AND alert_email_pending != ''`,
		hashHex(token), now.Unix()).Scan(&u.ID, &u.GitHubID, &u.Login, &addr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return u, addr, nil
}

// webAlertConfirmPage shows what opening the link confirms. It changes
// nothing: mail scanners fetch links, so confirming takes the button.
func (s *Server) webAlertConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	u, addr, err := s.pendingConfirm(r.Context(), token, s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if u == nil {
		s.webError(w, http.StatusNotFound, "This confirmation link expired or was already used. Ask for a new one on the overview page.")
		return
	}
	// The token stays out of the referrer and any cache.
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusOK, "alertconfirm.html", map[string]any{"Login": u.Login, "Email": addr, "Token": token})
}

func (s *Server) webAlertConfirm(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.BaseURL {
		s.webError(w, http.StatusForbidden, "The form expired. Open the link from the email again.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.webError(w, http.StatusBadRequest, "Invalid form.")
		return
	}
	ctx := r.Context()
	now := s.now()
	u, addr, err := s.pendingConfirm(ctx, r.PostForm.Get("token"), now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if u == nil {
		s.webError(w, http.StatusNotFound, "This confirmation link expired or was already used. Ask for a new one on the overview page.")
		return
	}
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT alert_email FROM users WHERE id = ?`, u.ID).Scan(&old); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET alert_email = ?, alert_email_pending = '', alert_email_token = '', alert_email_expires = 0 WHERE id = ? AND alert_email_token = ?`,
			addr, u.ID, hashHex(r.PostForm.Get("token")))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errAlreadyConfirmed
		}
		if old != "" && !strings.EqualFold(old, addr) {
			if err := s.queueEmail(ctx, tx, s.emailAlert(u, alertEmailChanged, addr, "", now), old); err != nil {
				return err
			}
		}
		return s.db.audit(ctx, tx, u.ID, "", s.clientIP(r), "alert_email_confirmed", addr, now)
	})
	if errors.Is(err, errAlreadyConfirmed) {
		s.webError(w, http.StatusConflict, "This address was already confirmed.")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.kickAlerts()
	s.render(w, http.StatusOK, "alertconfirm.html", map[string]any{"Login": u.Login, "Email": addr, "Done": true})
}

var errAlreadyConfirmed = errors.New("already confirmed")

// alertStats summarizes the outbox for the admin page.
type alertStats struct {
	Sent, Waiting, Failed int
	// The newest alert whose delivery failed: when it was queued, and the
	// error (which names the channel).
	LastFailure time.Time
	LastError   string
	// Addresses is the number of accounts with a confirmed alert address.
	Addresses int
}

func (d *DB) alertStats(ctx context.Context, since time.Time) (*alertStats, error) {
	st := &alertStats{}
	err := d.sql.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(sent_at > 0), 0), COALESCE(SUM(sent_at = 0 AND failed_at = 0), 0), COALESCE(SUM(failed_at > 0), 0)
		FROM alert_outbox WHERE created_at >= ? OR (sent_at = 0 AND failed_at = 0)`, since.Unix()).Scan(&st.Sent, &st.Waiting, &st.Failed)
	if err != nil {
		return nil, err
	}
	var at int64
	// Delivered alerts clear their error, so this is a failed alert or one
	// still being retried.
	err = d.sql.QueryRowContext(ctx, `SELECT created_at, last_error FROM alert_outbox
		WHERE last_error != '' ORDER BY id DESC LIMIT 1`).Scan(&at, &st.LastError)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		st.LastFailure = time.Unix(at, 0)
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE alert_email != ''`).Scan(&st.Addresses); err != nil {
		return nil, err
	}
	return st, nil
}
