package server

// Alerts tell people about security events on their account: a device that
// signed in, was approved, suspended or revoked, and a web sign-in from a
// browser the account never used. An alert is queued in the transaction that
// makes the change, so it is never lost and never sent for a change that
// rolled back, and a worker delivers it with retries: by email (through
// Lettermint) to the account's confirmed address and to the operator, and as
// a JSON post to the operator's webhook.
//
// Alerts carry metadata the server already holds (device names, addresses,
// times), never key material or the words a new device shows.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mscno/esec-vault/internal/chain"
)

// Alert kinds. The account kinds go to every channel; the email kinds only to
// the address they are about.
const (
	alertDeviceRegistered = "device.registered"
	alertDeviceAdded      = "device.added"
	alertDeviceSuspended  = "device.suspended"
	alertDeviceRevoked    = "device.revoked"
	alertNewBrowser       = "web.new_browser"
	alertMemberAdded      = "project.member_added"
	alertMemberRemoved    = "project.member_removed"
	alertMachineAdded     = "project.machine_added"
	alertMachineRemoved   = "project.machine_removed"
	alertGroupMachine     = "group.machine_added"
	alertGroupRemoved     = "group.machine_removed"
	alertGroupAdmin       = "group.admin_added"
	alertEmailConfirm     = "email.confirm"
	alertEmailChanged     = "email.changed"
	alertTest             = "test"
)

const (
	channelEmail   = "email"
	channelWebhook = "webhook"
	// alertKeep is how long delivered and failed alerts stay in the outbox.
	alertKeep = 30 * 24 * time.Hour
	// alertBatch is the most alerts one delivery round sends.
	alertBatch = 20
	// confirmTTL is how long an email confirmation link works.
	confirmTTL = 24 * time.Hour
)

// alertRetries are the waits before each retry; after the last, the alert is
// marked failed (about 11 hours after it was queued).
var alertRetries = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour}

// alert is the payload of every channel. Webhooks receive it as JSON; Text is
// a one-paragraph summary that chat services such as Slack show as is.
type alert struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Time    time.Time    `json:"time"`
	Server  string       `json:"server"`
	Account alertAccount `json:"account"`
	Device  *alertDevice `json:"device,omitempty"`
	IP      string       `json:"ip,omitempty"`
	Browser string       `json:"browser,omitempty"`
	// Project is the shared project of a project.* alert.
	Project string `json:"project,omitempty"`
	// Group is the machine group of a group.* alert.
	Group string `json:"group,omitempty"`
	Title string `json:"title"`
	Text  string `json:"text"`
	URL   string `json:"url"`
	// Advice says what to do if the event was not expected; email only.
	Advice string `json:"-"`
	// Link is an email confirmation link. Only email.confirm alerts carry
	// one, and they go only to the address being confirmed.
	Link string `json:"link,omitempty"`
}

type alertAccount struct {
	ID       string `json:"id"`
	GitHubID int64  `json:"github_id"`
	Login    string `json:"github_login"`
}

type alertDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Method   string `json:"method,omitempty"`
}

// stored is an alert as the outbox holds it: the payload plus what only
// email needs.
type stored struct {
	alert

	Advice string `json:"advice,omitempty"`
}

// alertsOn reports whether any channel is configured.
func (s *Server) alertsOn() bool { return s.cfg.Alerts.Email() || s.cfg.Alerts.Webhook() }

// queueAlert queues an account alert for every configured channel. It runs
// inside the transaction that made the change, where there is one.
func (s *Server) queueAlert(ctx context.Context, tx queryer, kind, userID, deviceID, ip, browser string, now time.Time) error {
	if !s.alertsOn() {
		return nil
	}
	a, err := s.buildAlert(ctx, tx, kind, userID, deviceID, ip, browser, now)
	if err != nil {
		return err
	}
	if s.cfg.Alerts.Webhook() {
		if err := s.insertAlert(ctx, tx, a, channelWebhook, ""); err != nil {
			return err
		}
	}
	if !s.cfg.Alerts.Email() {
		return nil
	}
	var own string
	if err := tx.QueryRowContext(ctx, `SELECT alert_email FROM users WHERE id = ?`, userID).Scan(&own); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	seen := map[string]bool{}
	for _, to := range append([]string{own}, s.cfg.Alerts.EmailTo...) {
		if to == "" || seen[strings.ToLower(to)] {
			continue
		}
		seen[strings.ToLower(to)] = true
		if err := s.insertAlert(ctx, tx, a, channelEmail, to); err != nil {
			return err
		}
	}
	return nil
}

// queueEmail queues an email about the alert address itself, to that address
// only.
func (s *Server) queueEmail(ctx context.Context, tx queryer, a *alert, to string) error {
	return s.insertAlert(ctx, tx, a, channelEmail, to)
}

func (s *Server) insertAlert(ctx context.Context, tx queryer, a *alert, channel, to string) error {
	payload, err := json.Marshal(stored{alert: *a, Advice: a.Advice})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO alert_outbox (user_id, kind, channel, recipient, payload, created_at, next_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.Account.ID, a.Type, channel, to, payload, a.Time.Unix(), a.Time.Unix())
	return err
}

// kickAlerts wakes the delivery worker after a transaction that queued
// alerts committed.
func (s *Server) kickAlerts() {
	if !s.alertsOn() {
		return
	}
	select {
	case s.alertKick <- struct{}{}:
	default:
	}
}

// buildAlert describes an account event.
func (s *Server) buildAlert(ctx context.Context, q queryer, kind, userID, deviceID, ip, browser string, now time.Time) (*alert, error) {
	u := &userRow{ID: userID}
	err := q.QueryRowContext(ctx, `SELECT github_id, login FROM users WHERE id = ?`, userID).Scan(&u.GitHubID, &u.Login)
	if err != nil {
		return nil, err
	}
	a := &alert{
		Type: kind, Time: now.UTC().Truncate(time.Second), Server: s.cfg.BaseURL, IP: ip, Browser: browser,
		Account: alertAccount{ID: u.ID, GitHubID: u.GitHubID, Login: u.Login},
		URL:     s.cfg.BaseURL + "/account",
	}
	who := u.Login + "'s"
	if deviceID != "" {
		d, err := s.db.device(ctx, q, deviceID)
		if err != nil {
			return nil, err
		}
		a.Device = &alertDevice{ID: d.ID, Name: d.Name, Platform: d.Platform, Method: d.Method}
		a.URL = s.cfg.BaseURL + "/devices/" + d.ID
	}
	name := ""
	if a.Device != nil {
		name = quoteName(a.Device.Name)
	}
	switch kind {
	case alertDeviceRegistered:
		a.Title = "New device waiting for approval"
		a.Text = fmt.Sprintf("A new device, %s (%s), signed in to %s esec vault account and is waiting for approval.", name, a.Device.Platform, who)
		a.Advice = "If you did not start this sign-in, suspend the device from the Details link, and secure your GitHub account: whoever started it signed in as you. The device cannot read anything until one of your trusted devices approves it."
	case alertDeviceAdded:
		a.Title = "Device approved"
		a.Text = fmt.Sprintf("%s (%s) can now open %s vault. It was added by %s.", name, a.Device.Platform, who, methodLabel(a.Device.Method))
		if a.Device.Method == chain.MethodFirst {
			a.Title = "Account created"
			a.Text = fmt.Sprintf("%s created an esec vault account on %s (%s).", u.Login, name, a.Device.Platform)
		}
		a.Advice = "If you did not approve this device, suspend it from the Details link, then revoke it from a trusted device with 'esec vault devices revoke " + a.Device.ID + "' and rotate the secrets it could read."
	case alertDeviceSuspended:
		a.Title = "Device suspended"
		a.Text = fmt.Sprintf("%s (%s) was suspended on %s account. It can no longer use the server.", name, a.Device.Platform, who)
		a.Advice = "If you did not suspend it, someone else is signed in to your account: review your devices and browsers, and secure your GitHub account."
	case alertDeviceRevoked:
		a.Title = "Device revoked"
		a.Text = fmt.Sprintf("%s (%s) was revoked from %s account and the user key was rotated.", name, a.Device.Platform, who)
		a.Advice = "If you did not revoke it, review your devices from a trusted one."
	case alertNewBrowser:
		a.Title = "Signed in from a new browser"
		a.Text = fmt.Sprintf("Someone signed in to %s esec vault account on the web from a browser it never used: %s.", who, browser)
		a.Advice = "If this was not you, sign that browser out from the overview page, and secure your GitHub account. A browser can see your devices and activity, and can suspend devices, but cannot read your secrets."
	default:
		return nil, fmt.Errorf("unknown alert kind %q", kind)
	}
	return a, nil
}

// emailAlert describes a change of the alert address itself.
func (s *Server) emailAlert(u *userRow, kind, address, link string, now time.Time) *alert {
	a := &alert{
		Type: kind, Time: now.UTC().Truncate(time.Second), Server: s.cfg.BaseURL, Link: link,
		Account: alertAccount{ID: u.ID, GitHubID: u.GitHubID, Login: u.Login},
		URL:     s.cfg.BaseURL + "/account#alerts",
	}
	switch kind {
	case alertEmailConfirm:
		a.Title = "Confirm your alert address"
		a.Text = fmt.Sprintf("Open the link below to get alerts about %s's esec vault account at this address. The link works for %s.", u.Login, durationText(confirmTTL))
		a.Advice = "If you did not ask for this, ignore this email: nothing is sent here unless the link is opened."
	case alertEmailChanged:
		a.Title = "Alerts no longer go to this address"
		a.Text = fmt.Sprintf("Alerts about %s's esec vault account no longer go to this address.", u.Login)
		if address != "" {
			a.Text = fmt.Sprintf("Alerts about %s's esec vault account now go to %s instead of this address.", u.Login, address)
		}
		a.Advice = "If you did not change this, someone else is signed in to your account: review your browsers and devices, and secure your GitHub account."
	}
	return a
}

// quoteName quotes a device name for an alert. Names are chosen by whoever
// registers the device, so they are cut short and stripped of anything but
// printable characters.
func quoteName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	return strconv.Quote(truncate(s, 60))
}

// ---- delivery ----

// alertWorker delivers queued alerts until ctx is cancelled.
func (s *Server) alertWorker(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		if err := s.DeliverAlerts(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("alert delivery failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.alertKick:
		}
	}
}

// DeliverAlerts sends the alerts that are due. Run calls it in the
// background; tests call it directly.
func (s *Server) DeliverAlerts(ctx context.Context) error {
	for {
		n, err := s.deliverBatch(ctx)
		if err != nil || n < alertBatch {
			return err
		}
	}
}

type outboxRow struct {
	id                int64
	kind, channel, to string
	payload           []byte
	attempts          int
	created           time.Time
}

func (s *Server) deliverBatch(ctx context.Context) (int, error) {
	due, err := s.dueAlerts(ctx, s.now())
	if err != nil {
		return 0, err
	}
	for _, r := range due {
		sendCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := s.deliverAlert(sendCtx, r)
		cancel()
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		now := s.now()
		var q string
		var args []any
		switch {
		case err == nil:
			q, args = `UPDATE alert_outbox SET sent_at = ?, attempts = attempts + 1, last_error = '' WHERE id = ?`, []any{now.Unix(), r.id}
		case isPermanent(err) || r.attempts >= len(alertRetries):
			s.log.Warn("alert not delivered", "id", r.id, "kind", r.kind, "channel", r.channel, "error", err)
			q, args = `UPDATE alert_outbox SET failed_at = ?, attempts = attempts + 1, last_error = ? WHERE id = ?`, []any{now.Unix(), truncate(err.Error(), 300), r.id}
		default:
			q, args = `UPDATE alert_outbox SET next_at = ?, attempts = attempts + 1, last_error = ? WHERE id = ?`, []any{now.Add(alertRetries[r.attempts]).Unix(), truncate(err.Error(), 300), r.id}
		}
		if _, err := s.db.sql.ExecContext(ctx, q, args...); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}

func (s *Server) deliverAlert(ctx context.Context, r outboxRow) error {
	var st stored
	if err := json.Unmarshal(r.payload, &st); err != nil {
		return permanent(fmt.Errorf("bad payload: %w", err))
	}
	a := st.alert
	a.Advice = st.Advice
	a.ID = "alt_" + strconv.FormatInt(r.id, 10)
	// The idempotency key stays the same across retries, so a send that
	// succeeded but whose answer was lost is not repeated.
	key := "esec-vault-" + strconv.FormatInt(r.id, 10) + "-" + strconv.FormatInt(r.created.Unix(), 10)
	switch r.channel {
	case channelEmail:
		if !s.cfg.Alerts.Email() {
			return permanent(errors.New("email alerts are not configured"))
		}
		return s.sendEmail(ctx, key, r.to, &a)
	case channelWebhook:
		if !s.cfg.Alerts.Webhook() {
			return permanent(errors.New("webhook alerts are not configured"))
		}
		return s.postWebhook(ctx, &a)
	}
	return permanent(fmt.Errorf("unknown channel %q", r.channel))
}

func (s *Server) dueAlerts(ctx context.Context, now time.Time) ([]outboxRow, error) {
	rows, err := s.db.sql.QueryContext(ctx, `SELECT id, kind, channel, recipient, payload, attempts, created_at FROM alert_outbox WHERE sent_at = 0 AND failed_at = 0 AND next_at <= ? ORDER BY id LIMIT ?`, now.Unix(), alertBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var due []outboxRow
	for rows.Next() {
		var r outboxRow
		var created int64
		if err := rows.Scan(&r.id, &r.kind, &r.channel, &r.to, &r.payload, &r.attempts, &created); err != nil {
			return nil, err
		}
		r.created = time.Unix(created, 0)
		due = append(due, r)
	}
	return due, rows.Err()
}

// deliveryError is a failed delivery; permanent ones are not retried.
type deliveryError struct {
	err       error
	permanent bool
}

func (e *deliveryError) Error() string { return e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

func permanent(err error) error { return &deliveryError{err: err, permanent: true} }

func isPermanent(err error) bool {
	var de *deliveryError
	return errors.As(err, &de) && de.permanent
}

// httpFailure classifies an HTTP error status: client errors are permanent,
// except timeouts, conflicts (Lettermint's idempotency key still in use) and
// rate limits.
func httpFailure(service string, status int, detail string) error {
	err := fmt.Errorf("%s: HTTP %d%s", service, status, detail)
	switch {
	case status >= 500, status == http.StatusRequestTimeout, status == http.StatusConflict, status == http.StatusTooManyRequests:
		return err
	}
	return permanent(err)
}

// transportError drops the URL from a client error: a webhook URL is a
// secret, and the error ends up in logs and on the admin page.
func transportError(service string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("%s: %w", service, err)
}

// sendEmail sends one alert through Lettermint's sending API.
func (s *Server) sendEmail(ctx context.Context, key, to string, a *alert) error {
	cfg := s.cfg.Alerts
	body := map[string]any{
		"from":    cfg.EmailFrom,
		"to":      []string{to},
		"subject": "esec vault: " + a.Title,
		"text":    emailText(a),
		"tag":     "esec-vault-alert",
		// Security mail carries links people should be able to read as is.
		"settings": map[string]any{"track_opens": false, "track_clicks": false},
		"metadata": map[string]string{"alert": a.ID, "type": a.Type},
	}
	if cfg.LettermintRoute != "" {
		body["route"] = cfg.LettermintRoute
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return permanent(err)
	}
	endpoint := strings.TrimRight(cmp.Or(cfg.LettermintAPIURL, "https://api.lettermint.co/v1"), "/") + "/send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "esec-vault-server/"+s.version)
	req.Header.Set("X-Lettermint-Token", cfg.LettermintToken)
	req.Header.Set("Idempotency-Key", key)
	resp, err := s.alertHTTP.Do(req)
	if err != nil {
		return transportError("lettermint", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return httpFailure("lettermint", resp.StatusCode, lettermintError(out))
}

// lettermintError extracts the message of a Lettermint error response.
func lettermintError(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	msg := strings.TrimSpace(strings.Join([]string{e.Error.Code, cmp.Or(e.Error.Message, e.Message)}, " "))
	if msg == "" {
		return ""
	}
	return ": " + truncate(msg, 200)
}

// emailText renders an alert as a plain-text email.
func emailText(a *alert) string {
	var b strings.Builder
	b.WriteString(a.Text + "\n\n")
	if a.Link != "" {
		b.WriteString(a.Link + "\n\n")
	}
	if a.Account.GitHubID != 0 {
		fmt.Fprintf(&b, "Account:  %s (GitHub ID %d)\n", a.Account.Login, a.Account.GitHubID)
	}
	if a.Device != nil {
		fmt.Fprintf(&b, "Device:   %s, %s (%s)\n", quoteName(a.Device.Name), a.Device.Platform, a.Device.ID)
	}
	if a.Browser != "" {
		fmt.Fprintf(&b, "Browser:  %s\n", a.Browser)
	}
	if a.IP != "" {
		fmt.Fprintf(&b, "Address:  %s\n", a.IP)
	}
	fmt.Fprintf(&b, "Time:     %s\n", a.Time.Format("2006-01-02 15:04:05 UTC"))
	if a.Link == "" {
		fmt.Fprintf(&b, "Details:  %s\n", a.URL)
	}
	if a.Advice != "" {
		b.WriteString("\n" + a.Advice + "\n")
	}
	fmt.Fprintf(&b, "\n--\nesec vault at %s\n", a.Server)
	if a.Type != alertEmailConfirm && a.Type != alertEmailChanged && a.Type != alertTest {
		fmt.Fprintf(&b, "Change where alerts go: %s/account#alerts\n", a.Server)
	}
	return b.String()
}

// postWebhook posts one alert to the operator's webhook. With a webhook
// secret, X-Esec-Vault-Signature is "sha256=" and the hex HMAC-SHA256 of the
// timestamp header, a ".", and the body.
func (s *Server) postWebhook(ctx context.Context, a *alert) error {
	cfg := s.cfg.Alerts
	body, err := json.Marshal(webhookBody(a))
	if err != nil {
		return permanent(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return permanent(errors.New("webhook: invalid URL"))
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "esec-vault-server/"+s.version)
	req.Header.Set("X-Esec-Vault-Event", a.Type)
	req.Header.Set("X-Esec-Vault-Delivery", a.ID)
	req.Header.Set("X-Esec-Vault-Timestamp", ts)
	if cfg.WebhookSecret != "" {
		req.Header.Set("X-Esec-Vault-Signature", WebhookSignature(cfg.WebhookSecret, ts, body))
	}
	resp, err := s.alertHTTP.Do(req)
	if err != nil {
		return transportError("webhook", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return httpFailure("webhook", resp.StatusCode, "")
}

// webhookBody is the JSON a webhook receives: the alert, with Text holding
// the whole message so chat services show it in one line. Device names are
// already limited to plain characters; Text still escapes "&", "<" and ">"
// as Slack expects, so nothing in it can turn into a link.
func webhookBody(a *alert) alert {
	out := *a
	out.Link = ""
	text := a.Text
	if a.IP != "" {
		text += " (from " + a.IP + ")"
	}
	out.Text = "esec vault: " + chatEscape.Replace(text) + " " + a.URL
	return out
}

var chatEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// WebhookSignature is the X-Esec-Vault-Signature of a webhook post: receivers
// recompute it with the shared secret and compare in constant time.
func WebhookSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// SendTestAlert sends a test alert to the operator's channels right away,
// without the outbox, and reports each result. The operator runs it to check
// the setup (esec-vault-server -test-alert).
func SendTestAlert(ctx context.Context, cfg *Config, version string) []error {
	s := &Server{cfg: cfg, now: time.Now, version: version, alertHTTP: newAlertClient()}
	a := &alert{
		ID: "alt_test", Type: alertTest, Time: time.Now().UTC().Truncate(time.Second), Server: cfg.BaseURL,
		URL:   cfg.BaseURL + "/admin",
		Title: "Test alert", Text: "This is a test alert from the esec vault server. Alerts reach this channel.",
	}
	var errs []error
	if !s.alertsOn() {
		return []error{errors.New("no alert channel is configured")}
	}
	if cfg.Alerts.Webhook() {
		if err := s.postWebhook(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	if !cfg.Alerts.Webhook() && len(cfg.Alerts.EmailTo) == 0 {
		return []error{errors.New("the operator has no alert channel: set alerts.email_to or ESEC_SERVER_ALERT_WEBHOOK_URL")}
	}
	if cfg.Alerts.Email() {
		for i, to := range cfg.Alerts.EmailTo {
			key := fmt.Sprintf("esec-vault-test-%d-%d", a.Time.Unix(), i)
			if err := s.sendEmail(ctx, key, to, a); err != nil {
				errs = append(errs, fmt.Errorf("email to %s: %w", to, err))
			}
		}
	}
	return errs
}

func newAlertClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		// A redirect would send the token or the body somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
