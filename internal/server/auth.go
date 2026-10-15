package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/apisig"
	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/wire"
)

// Device authorization grant parameters.
const (
	deviceCodeTTL   = 10 * time.Minute
	pollInterval    = 5 * time.Second
	pendingDeviceTT = 15 * time.Minute
	// maxOpenRegistrations caps unconfirmed registrations server-wide.
	maxOpenRegistrations = 200000
	// maxOpenOAuthStates caps GitHub sign-ins started per 10 minutes.
	maxOpenOAuthStates = 200000
)

// checkRegistration verifies that the registrant holds the private key it
// registers (so nobody can register, or use the known-device path with,
// someone else's keys), that the request is recent, and that it was not
// seen before.
func (s *Server) checkRegistration(ctx context.Context, req *wire.DeviceRegisterRequest, now time.Time) error {
	signPub, err := chain.ParseSignKey(strings.ToLower(req.SignPub))
	if err != nil || !ed25519.Verify(signPub, wire.RegistrationMessage(req), req.Sig) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "registration is not signed by the device key")
	}
	if d := now.Sub(time.Unix(req.Timestamp, 0)); d > apisig.MaxSkew || d < -apisig.MaxSkew {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "registration time is too far from the server's clock; check this machine's clock")
	}
	if !registrationNonce.MatchString(req.Nonce) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid registration nonce")
	}
	res, err := s.db.sql.ExecContext(ctx, `INSERT INTO nonces (device_id, nonce, seen_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, "register:"+strings.ToLower(req.SignPub), req.Nonce, now.Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "registration replayed")
	}
	return nil
}

var registrationNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// errReplay marks a request whose nonce was already used.
var errReplay = errors.New("request replayed")

// signatureFailure maps verifySignature errors to a response: client errors
// are 401 with our own message, anything else is an internal error.
func (s *Server) signatureFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, apisig.ErrInvalid) || errors.Is(err, errReplay) {
		writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, err.Error())
		return
	}
	s.internalError(w, r, err)
}

// crockford is Crockford's base32 alphabet: no I, L, O or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newUserCode returns an 8-character code (40 bits) formatted XXXX-XXXX.
func newUserCode() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, crockford[v&31])
	}
	return string(out)
}

// normalizeUserCode maps typed input onto the canonical code: case-folded,
// O read as 0, I and L read as 1, dashes and spaces removed. It returns ""
// for anything that cannot be a code.
func normalizeUserCode(in string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(crockford, r) {
			return ""
		}
		b.WriteRune(r)
	}
	if b.Len() != 8 {
		return ""
	}
	return b.String()
}

func formatUserCode(norm string) string { return norm[:4] + "-" + norm[4:] }

// reqCtx carries the authenticated caller of an API request.
type reqCtx struct {
	user    *userRow
	device  *deviceRow
	session string
	body    []byte
	ip      string
	expires time.Time
}

type apiHandler func(w http.ResponseWriter, r *http.Request, c *reqCtx)

// api authenticates a request: a live session, an allowlisted user, a device
// in the right state, and a valid device signature with a fresh nonce.
func (s *Server) api(allowPending bool, h apiHandler) http.Handler { //nolint:gocyclo // every check is a separate, ordered gate
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := s.now()
		ctx := r.Context()
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "missing session token; run 'esec vault login'")
			return
		}
		var userIDv, deviceID string
		var created, lastUsed, expires, revoked int64
		err := s.db.sql.QueryRowContext(ctx, `SELECT user_id, device_id, created_at, last_used_at, expires_at, revoked_at FROM sessions WHERE token_hash = ?`, hashHex(token)).
			Scan(&userIDv, &deviceID, &created, &lastUsed, &expires, &revoked)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (revoked != 0 || now.Unix() >= expires || now.Sub(fromUnix(lastUsed)) > s.cfg.Sessions.Idle.Duration)) {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "session expired or ended; run 'esec vault login'")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		user, err := s.db.user(ctx, userIDv)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !s.cfg.Allowed(user.GitHubID) {
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, "this GitHub account is no longer allowed on this server")
			return
		}
		dev, err := s.db.device(ctx, s.db.sql, deviceID)
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "this device is no longer registered; run 'esec vault login'")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if dev.UserID != user.ID {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "session does not match its device")
			return
		}
		switch dev.Status {
		case wire.DeviceActive:
		case wire.DevicePending:
			if !now.Before(dev.PendingExpires) {
				writeErr(w, http.StatusUnauthorized, wire.ErrPendingExpired, "this device was not approved in time; run 'esec vault login' again")
				return
			}
			if !allowPending {
				writeErr(w, http.StatusForbidden, wire.ErrForbidden, "this device is not approved yet")
				return
			}
		case wire.DeviceRevoked:
			writeErr(w, http.StatusUnauthorized, wire.ErrDeviceRevoked, "this device has been revoked")
			return
		case wire.DeviceSuspended:
			writeErr(w, http.StatusForbidden, wire.ErrForbidden, "this device is suspended; complete or undo the revocation from another device")
			return
		default:
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "device is not registered")
			return
		}
		limit := int64(maxSmallBody)
		if r.URL.Path == "/v1/commit" || r.URL.Path == "/v1/vault" {
			limit = maxLargeBody
		}
		body, err := readBody(w, r, limit)
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
			return
		}
		// Every signed request records a nonce, so requests are limited per
		// device before that write; waiting devices get a tighter limit.
		perMinute := 600
		if dev.Status == wire.DevicePending {
			perMinute = 60
		}
		if !s.limits.allow("api:"+dev.ID, perMinute, time.Minute, now) {
			writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many requests from this device; slow down")
			return
		}
		if err := s.verifySignature(ctx, r, body, dev, now); err != nil {
			s.signatureFailure(w, r, err)
			return
		}
		ip := s.clientIP(r)
		if now.Sub(fromUnix(lastUsed)) > time.Minute || now.Sub(dev.LastSeen) > time.Minute || dev.LastIP != ip {
			_, err1 := s.db.sql.ExecContext(ctx, `UPDATE sessions SET last_used_at = ? WHERE token_hash = ?`, now.Unix(), hashHex(token))
			_, err2 := s.db.sql.ExecContext(ctx, `UPDATE devices SET last_seen_at = ?, last_ip = ? WHERE id = ?`, now.Unix(), ip, dev.ID)
			if err := errors.Join(err1, err2); err != nil {
				s.internalError(w, r, err)
				return
			}
		}
		h(w, r, &reqCtx{user: user, device: dev, session: hashHex(token), body: body, ip: ip, expires: fromUnix(expires)})
	})
}

// verifySignature checks the device signature and records the nonce so the
// same signed request cannot be replayed.
func (s *Server) verifySignature(ctx context.Context, r *http.Request, body []byte, dev *deviceRow, now time.Time) error {
	signed, err := apisig.Parse(r)
	if err != nil {
		return err
	}
	if signed.DeviceID != dev.ID {
		return apisig.ErrInvalid
	}
	pub, err := chain.ParseSignKey(dev.SignPub)
	if err != nil {
		return apisig.ErrInvalid
	}
	if err := signed.Verify(r, body, pub, now); err != nil {
		return err
	}
	res, err := s.db.sql.ExecContext(ctx, `INSERT INTO nonces (device_id, nonce, seen_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, dev.ID, signed.Nonce, now.Unix())
	if err != nil {
		return fmt.Errorf("record nonce: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errReplay
	}
	return nil
}

func (s *Server) apiDeviceRegister(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ip := s.clientIP(r)
	if !s.allowAnon("register", ip, s.regPerAddr, s.regPerNet, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "too many device registrations from this address")
		return
	}
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.DeviceRegisterRequest
	if err := decodeStrict(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	if err := s.checkRegistration(r.Context(), &req, now); err != nil {
		s.fail(w, r, err)
		return
	}
	// The server-wide cap protects the database from floods of new
	// registrations. A device the server already trusts (signing in again)
	// is never held back by it: a flood can delay new devices only.
	var open int
	if err := s.db.sql.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM devices WHERE status = ? AND created_at > ?`, wire.DeviceRegistering, now.Add(-time.Hour).Unix()).Scan(&open); err != nil {
		s.internalError(w, r, err)
		return
	}
	if open >= s.maxRegistrations {
		var known int
		if err := s.db.sql.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM devices WHERE sign_pub = ? AND enc_pub = ? AND status = ?`, strings.ToLower(req.SignPub), strings.ToLower(req.EncPub), wire.DeviceActive).Scan(&known); err != nil {
			s.internalError(w, r, err)
			return
		}
		if known == 0 {
			writeErr(w, http.StatusServiceUnavailable, wire.ErrRateLimited, "too many sign-ins in progress; try again later")
			return
		}
	}
	created := now.UTC().Truncate(time.Second)
	dev := chain.Device{ID: randomID("d_"), Name: req.Name, Platform: req.Platform, EncPub: strings.ToLower(req.EncPub), SignPub: strings.ToLower(req.SignPub), Created: created}
	if err := chain.ValidateDevice(dev); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, err.Error())
		return
	}
	deviceCode := randomToken("")
	var userCode string
	ctx := r.Context()
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices (id, name, platform, enc_pub, sign_pub, status, created_at, register_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			dev.ID, dev.Name, dev.Platform, dev.EncPub, dev.SignPub, wire.DeviceRegistering, created.Unix(), ip); err != nil {
			return err
		}
		for range 5 {
			userCode = newUserCode()
			_, err := tx.ExecContext(ctx, `INSERT INTO device_codes (device_code_hash, user_code_hash, device_id, status, expires_at, created_at) VALUES (?, ?, ?, 'pending', ?, ?)`,
				hashHex(deviceCode), hashHex(normalizeUserCode(userCode)), dev.ID, now.Add(deviceCodeTTL).Unix(), now.Unix())
			if err == nil {
				return nil
			}
			if !strings.Contains(err.Error(), "UNIQUE") {
				return err
			}
		}
		return errors.New("could not allocate a user code")
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.DeviceRegisterResponse{
		DeviceID:        dev.ID,
		DeviceCreated:   created,
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.cfg.BaseURL + "/device",
		Interval:        int(pollInterval / time.Second),
		ExpiresIn:       int(deviceCodeTTL / time.Second),
	})
}

func (s *Server) apiToken(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo // RFC 8628 state machine plus device matching, kept in order for review
	now := s.now()
	ctx := r.Context()
	body, err := readBody(w, r, maxSmallBody)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "request body too large")
		return
	}
	var req wire.TokenRequest
	if err := decodeStrict(body, &req); err != nil || req.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid request")
		return
	}
	// Polls are cheap to send, so they are limited per address and network,
	// and every check that needs no write runs before the signature check
	// (which records a nonce) and the last-poll update.
	if !s.allowAnon("poll", s.clientIP(r), 60, 600, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, wire.ErrSlowDown, "polling too fast")
		return
	}
	var deviceID, status, confirmedUser string
	var expires, lastPoll int64
	err = s.db.sql.QueryRowContext(ctx, `SELECT device_id, status, user_id, expires_at, last_poll FROM device_codes WHERE device_code_hash = ?`, hashHex(req.DeviceCode)).
		Scan(&deviceID, &status, &confirmedUser, &expires, &lastPoll)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusBadRequest, wire.ErrExpiredToken, "unknown or expired device code")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	switch {
	case now.Unix() >= expires || status == "consumed":
		writeErr(w, http.StatusBadRequest, wire.ErrExpiredToken, "the code expired; run 'esec vault login' again")
		return
	case lastPoll != 0 && now.Sub(fromUnix(lastPoll)) < pollInterval-time.Second:
		writeErr(w, http.StatusBadRequest, wire.ErrSlowDown, "polling too fast")
		return
	}
	reg, err := s.db.device(ctx, s.db.sql, deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusBadRequest, wire.ErrExpiredToken, "unknown or expired device code")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Only the holder of the registered device key may collect the session.
	if err := s.verifySignature(ctx, r, body, reg, now); err != nil {
		s.signatureFailure(w, r, err)
		return
	}
	// Compare-and-swap on last_poll: of concurrent polls, only one passes.
	res, err := s.db.sql.ExecContext(ctx, `UPDATE device_codes SET last_poll = ? WHERE device_code_hash = ? AND last_poll = ?`, now.Unix(), hashHex(req.DeviceCode), lastPoll)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		writeErr(w, http.StatusBadRequest, wire.ErrSlowDown, "polling too fast")
		return
	}
	switch {
	case status == "denied":
		writeErr(w, http.StatusBadRequest, wire.ErrAccessDenied, "sign-in was denied in the browser")
		return
	case status == "pending":
		writeErr(w, http.StatusBadRequest, wire.ErrAuthorizationPending, "waiting for the browser")
		return
	case status != "confirmed":
		writeErr(w, http.StatusBadRequest, wire.ErrExpiredToken, "invalid code state")
		return
	}
	user, err := s.db.user(ctx, confirmedUser)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !s.cfg.Allowed(user.GitHubID) {
		writeErr(w, http.StatusBadRequest, wire.ErrAccessDenied, "this GitHub account is not allowed on this server")
		return
	}
	token := randomToken("esv_")
	sessionExpires := now.Add(s.cfg.Sessions.Absolute.Duration)
	var dev *deviceRow
	var denied string
	err = s.db.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE device_codes SET status = 'consumed' WHERE device_code_hash = ? AND status = 'confirmed'`, hashHex(req.DeviceCode))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			denied = "the code was already used"
			return nil
		}
		existing, err := s.db.devicesOf(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		for _, d := range existing {
			if d.ID == reg.ID || d.SignPub != reg.SignPub || d.EncPub != reg.EncPub {
				continue
			}
			switch d.Status {
			case wire.DeviceRevoked:
				denied = "this device was revoked; remove its keys with 'esec vault logout --forget-device' and sign in again"
				return nil
			case wire.DeviceSuspended:
				denied = "this device is suspended"
				return nil
			case wire.DevicePending:
				if _, err := tx.ExecContext(ctx, `UPDATE devices SET pending_expires = ? WHERE id = ?`, now.Add(pendingDeviceTT).Unix(), d.ID); err != nil {
					return err
				}
				d.PendingExpires = now.Add(pendingDeviceTT)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND status = ?`, reg.ID, wire.DeviceRegistering); err != nil {
				return err
			}
			dev = d
			break
		}
		if dev == nil {
			if reg.Status != wire.DeviceRegistering {
				denied = "device registration is no longer valid"
				return nil
			}
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET user_id = ?, status = ?, pending_expires = ? WHERE id = ?`, user.ID, wire.DevicePending, now.Add(pendingDeviceTT).Unix(), reg.ID); err != nil {
				return err
			}
			reg.UserID, reg.Status, reg.PendingExpires = user.ID, wire.DevicePending, now.Add(pendingDeviceTT)
			dev = reg
			if err := s.db.addEvent(ctx, tx, user.ID, wire.EventDevicePending, dev.ID, now); err != nil {
				return err
			}
			if err := s.db.audit(ctx, tx, user.ID, dev.ID, s.clientIP(r), "device_registered", dev.Name, now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, device_id, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			hashHex(token), user.ID, dev.ID, now.Unix(), now.Unix(), sessionExpires.Unix()); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, user.ID, dev.ID, s.clientIP(r), "login", "", now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if denied != "" {
		writeErr(w, http.StatusBadRequest, wire.ErrAccessDenied, denied)
		return
	}
	s.notify.wake(user.ID)
	writeJSON(w, http.StatusOK, wire.TokenResponse{SessionToken: token, ExpiresAt: sessionExpires, User: user.wire(), Device: dev.wire(false)})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	now := s.now()
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE token_hash = ?`, now.Unix(), c.session); err != nil {
			return err
		}
		return s.db.audit(ctx, tx, c.user.ID, c.device.ID, c.ip, "logout", "", now)
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	seq, err := s.db.chainSeq(r.Context(), s.db.sql, c.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	me := wire.Me{User: c.user.wire(), Device: c.device.wire(false), ChainSeq: seq, SessionExpires: c.expires}
	if seq > 0 {
		// The recovery keys live in the first link; verifying that one link
		// is enough and keeps this cheap for polling devices.
		first, err := s.db.firstLink(r.Context(), c.user.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if st, err := chain.Verify(c.user.ID, []*envelope.Envelope{first}); first != nil && err == nil {
			me.AccountMasterPub, me.AccountMasterSignPub = hex.EncodeToString(st.MasterPub[:]), hex.EncodeToString(st.MasterSignPub)
		}
	}
	if c.device.Status == wire.DevicePending {
		me.PendingExpires = c.device.PendingExpires
	}
	writeJSON(w, http.StatusOK, me)
}
