package server_test

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/server"
	"github.com/mscno/esec-vault/internal/servertest"
)

// sink records the requests a fake Lettermint or webhook receives and
// answers with the queued status codes (202 or 200 once they run out).
type sink struct {
	*httptest.Server

	mu       sync.Mutex
	reqs     []sinkReq
	statuses []int
}

type sinkReq struct {
	header http.Header
	body   []byte
}

func newSink(t *testing.T, ok int) *sink {
	t.Helper()
	s := &sink{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, sinkReq{header: r.Header.Clone(), body: body})
		status := ok
		if len(s.statuses) > 0 {
			status, s.statuses = s.statuses[0], s.statuses[1:]
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status >= 400 {
			_, _ = io.WriteString(w, `{"error":{"code":"VALIDATION_ERROR","message":"the from address is not verified"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"message_id":"m1","status":"pending"}`)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *sink) answer(statuses ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, statuses...)
}

func (s *sink) all() []sinkReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkReq(nil), s.reqs...)
}

type sentMail struct {
	From     string            `json:"from"`
	To       []string          `json:"to"`
	Subject  string            `json:"subject"`
	Text     string            `json:"text"`
	Settings map[string]bool   `json:"settings"`
	Metadata map[string]string `json:"metadata"`
}

func (s *sink) mails(t *testing.T) []sentMail {
	t.Helper()
	reqs := s.all()
	out := make([]sentMail, 0, len(reqs))
	for _, r := range reqs {
		var m sentMail
		if err := json.Unmarshal(r.body, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// mailTo returns the newest mail to an address whose subject contains want.
func (s *sink) mailTo(t *testing.T, to, want string) sentMail {
	t.Helper()
	ms := s.mails(t)
	for i := len(ms) - 1; i >= 0; i-- {
		if len(ms[i].To) == 1 && ms[i].To[0] == to && strings.Contains(ms[i].Subject, want) {
			return ms[i]
		}
	}
	t.Fatalf("no mail to %s about %q in %+v", to, want, ms)
	return sentMail{}
}

type hookAlert struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Text    string `json:"text"`
	URL     string `json:"url"`
	Link    string `json:"link"`
	Account struct {
		Login string `json:"github_login"`
	} `json:"account"`
	Device *struct {
		Name   string `json:"name"`
		Method string `json:"method"`
	} `json:"device"`
}

func (s *sink) hooks(t *testing.T, secret string) []hookAlert {
	t.Helper()
	reqs := s.all()
	out := make([]hookAlert, 0, len(reqs))
	for _, r := range reqs {
		ts := r.header.Get("X-Esec-Vault-Timestamp")
		if want := server.WebhookSignature(secret, ts, r.body); !hmac.Equal([]byte(want), []byte(r.header.Get("X-Esec-Vault-Signature"))) {
			t.Fatalf("bad webhook signature %q", r.header.Get("X-Esec-Vault-Signature"))
		}
		var a hookAlert
		if err := json.Unmarshal(r.body, &a); err != nil {
			t.Fatal(err)
		}
		if r.header.Get("X-Esec-Vault-Event") != a.Type || r.header.Get("X-Esec-Vault-Delivery") != a.ID {
			t.Fatalf("headers do not match the body: %v", r.header)
		}
		out = append(out, a)
	}
	return out
}

func hookTypes(hs []hookAlert) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.Type)
	}
	return out
}

func alertHarness(t *testing.T, alerts server.AlertsConfig) *servertest.Harness {
	t.Helper()
	h := servertest.StartConfig(t, nil, func(c *server.Config) {
		c.Alerts = alerts
		c.Access.AdminGitHubIDs = []int64{ownerID}
	}, ownerID)
	h.GitHub.AddUser(ownerID, "mscno")
	return h
}

func deliver(t *testing.T, h *servertest.Harness) {
	t.Helper()
	if err := h.Server.DeliverAlerts(context.Background()); err != nil {
		t.Fatal(err)
	}
}

var confirmLink = regexp.MustCompile(`https?://\S+/alerts/confirm\?token=\S+`)

func TestAlertsReachEmailAndWebhook(t *testing.T) { //nolint:gocyclo // one sequential story
	mail, hook := newSink(t, http.StatusAccepted), newSink(t, http.StatusOK)
	const secret = "hook-secret"
	h := alertHarness(t, server.AlertsConfig{
		EmailFrom: "esec vault <vault@example.com>", EmailTo: []string{"ops@example.com"},
		LettermintAPIURL: mail.URL, LettermintToken: "lm_test",
		WebhookURL: hook.URL + "/hook", WebhookSecret: secret,
	})

	// The first web sign-in is from a new browser.
	b := h.Browser("mscno")
	page := getPage(t, b, "/account")
	mustContain(t, page, "Set up email alerts", `id="alerts"`, "The server operator also receives these alerts")
	deliver(t, h)
	m := mail.mailTo(t, "ops@example.com", "Signed in from a new browser")
	if m.From != "esec vault <vault@example.com>" || m.Settings["track_clicks"] || m.Settings["track_opens"] || !strings.Contains(m.Text, "mscno") {
		t.Fatalf("browser mail: %+v", m)
	}
	if got := hookTypes(hook.hooks(t, secret)); len(got) != 1 || got[0] != "web.new_browser" {
		t.Fatalf("webhook: %v", got)
	}
	for _, r := range mail.all() {
		if r.header.Get("X-Lettermint-Token") != "lm_test" || !strings.HasPrefix(r.header.Get("Idempotency-Key"), "esec-vault-") {
			t.Fatalf("lettermint headers: %v", r.header)
		}
	}

	// Ask for alerts at an address: only that address gets the link.
	status, page, err := b.Post("/account/alerts", servertest.CSRF(page), url.Values{"email": {"me@example.com"}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("set address: %d %v", status, err)
	}
	mustContain(t, page, "Waiting for you to confirm <strong>me@example.com</strong>")
	deliver(t, h)
	m = mail.mailTo(t, "me@example.com", "Confirm your alert address")
	link := confirmLink.FindString(m.Text)
	if link == "" {
		t.Fatalf("no link in %q", m.Text)
	}
	if n := len(hook.all()); n != 1 {
		t.Fatalf("the webhook got the confirmation: %d posts", n)
	}
	for _, m := range mail.mails(t) {
		if m.To[0] != "me@example.com" && strings.Contains(m.Text, "token=") {
			t.Fatalf("the link went to %v", m.To)
		}
	}

	// Opening the link changes nothing: mail scanners open links too.
	anon := &http.Client{Timeout: 10 * time.Second}
	resp, err := anon.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Confirm your alert address") {
		t.Fatalf("confirm page: %d %s", resp.StatusCode, body)
	}
	if mustAddress(t, h) != "" {
		t.Fatal("opening the link confirmed the address")
	}
	token, _ := url.Parse(link)
	post := func() int {
		req, _ := http.NewRequest(http.MethodPost, h.URL+"/alerts/confirm", strings.NewReader(url.Values{"token": {token.Query().Get("token")}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", h.URL)
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := post(); s != http.StatusOK {
		t.Fatalf("confirm: %d", s)
	}
	if mustAddress(t, h) != "me@example.com" {
		t.Fatal("address not confirmed")
	}
	if s := post(); s != http.StatusNotFound {
		t.Fatalf("link reused: %d", s)
	}
	mustContain(t, getPage(t, b, "/account"), "Alerts go to <strong>me@example.com</strong>")

	// A new device: the account and the operator get an email, the
	// webhook a post.
	owner := signIn(t, h, nil, "laptop")
	deliver(t, h)
	for _, to := range []string{"me@example.com", "ops@example.com"} {
		m := mail.mailTo(t, to, "New device waiting for approval")
		if !strings.Contains(m.Text, `"laptop"`) || !strings.Contains(m.Text, h.URL+"/devices/") || !strings.Contains(m.Text, "suspend the device") {
			t.Fatalf("device mail: %s", m.Text)
		}
	}
	create(t, owner)
	deliver(t, h)
	mail.mailTo(t, "me@example.com", "Account created")
	vm := signIn(t, h, nil, "vm")
	if err := owner.c.Suspend(context.Background(), vm.info.ID); err != nil {
		t.Fatal(err)
	}
	deliver(t, h)
	mail.mailTo(t, "me@example.com", "Device suspended")
	hooks := hook.hooks(t, secret)
	var types []string
	for _, a := range hooks {
		if a.Link != "" {
			t.Fatal("a webhook post carries a confirmation link")
		}
		if a.Type == "web.new_browser" {
			continue
		}
		types = append(types, a.Type)
		if a.Account.Login != "mscno" || a.Device == nil || !strings.HasPrefix(a.Text, "esec vault: ") {
			t.Fatalf("webhook alert: %+v", a)
		}
	}
	if strings.Join(types, " ") != "device.registered device.added device.registered device.suspended" {
		t.Fatalf("webhook alerts: %v", types)
	}

	// Turning alerts off tells the old address.
	page = getPage(t, b, "/account")
	if status, _, err := b.Post("/account/alerts/remove", servertest.CSRF(page), nil); err != nil || status != http.StatusOK {
		t.Fatalf("remove: %d %v", status, err)
	}
	deliver(t, h)
	mail.mailTo(t, "me@example.com", "Alerts no longer go to this address")
	mustContain(t, getPage(t, b, "/activity?category=alerts"), "Alert address confirmed", "Email alerts turned off")
}

func mustAddress(t *testing.T, h *servertest.Harness) string {
	t.Helper()
	var addr string
	if err := h.DB.SQL().QueryRow(`SELECT alert_email FROM users WHERE id = ?`, user).Scan(&addr); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestAlertsAreRetriedAndFailuresShown(t *testing.T) {
	mail := newSink(t, http.StatusAccepted)
	h := alertHarness(t, server.AlertsConfig{
		EmailFrom: "vault@example.com", EmailTo: []string{"ops@example.com"},
		LettermintAPIURL: mail.URL, LettermintToken: "lm_test",
	})
	// A server error is retried with the same idempotency key.
	mail.answer(http.StatusInternalServerError)
	b := h.Browser("mscno")
	getPage(t, b, "/account")
	deliver(t, h)
	h.Advance(10 * time.Second)
	deliver(t, h)
	if n := len(mail.all()); n != 1 {
		t.Fatalf("retried too early: %d requests", n)
	}
	h.Advance(30 * time.Second)
	deliver(t, h)
	reqs := mail.all()
	if len(reqs) != 2 || reqs[0].header.Get("Idempotency-Key") != reqs[1].header.Get("Idempotency-Key") {
		t.Fatalf("retry: %d requests", len(reqs))
	}

	// A rejected email is not retried, and the admin page shows why.
	mail.answer(http.StatusUnprocessableEntity)
	other := h.Browser("mscno")
	getPage(t, other, "/account")
	deliver(t, h)
	h.Advance(24 * time.Hour)
	deliver(t, h)
	if n := len(mail.all()); n != 3 {
		t.Fatalf("a rejected email was retried: %d requests", n)
	}
	admin := getPage(t, b, "/admin")
	mustContain(t, admin, "1 sent", "1 failed", "lettermint: HTTP 422: VALIDATION_ERROR the from address is not verified", "-test-alert")
}

func TestWebhookErrorsHideTheURL(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	h := alertHarness(t, server.AlertsConfig{WebhookURL: deadURL + "/services/T000/SECRET"})
	getPage(t, h.Browser("mscno"), "/account")
	deliver(t, h)
	var lastErr string
	if err := h.DB.SQL().QueryRow(`SELECT last_error FROM alert_outbox`).Scan(&lastErr); err != nil {
		t.Fatal(err)
	}
	if lastErr == "" || strings.Contains(lastErr, "SECRET") || strings.Contains(lastErr, deadURL) {
		t.Fatalf("stored error: %q", lastErr)
	}
}

func TestNoAlertsWithoutChannels(t *testing.T) {
	h := alertHarness(t, server.AlertsConfig{})
	page := getPage(t, h.Browser("mscno"), "/account")
	mustContain(t, page, "This server does not send email alerts.")
	if strings.Contains(page, "Set up email alerts") {
		t.Fatal("offers alerts the server cannot send")
	}
	var n int
	if err := h.DB.SQL().QueryRow(`SELECT COUNT(*) FROM alert_outbox`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("queued %d alerts without a channel: %v", n, err)
	}
}
