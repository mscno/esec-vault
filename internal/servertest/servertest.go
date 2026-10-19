// Package servertest runs an esec vault server against a fake GitHub for
// tests, and drives the browser side of sign-in like a person would.
package servertest

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/server"
)

// BootstrapSecret is the bootstrap secret of test servers.
const BootstrapSecret = "test-bootstrap-secret"

// BootstrapToken is the account creation token of the test owner (GitHub id
// 53101343).
var BootstrapToken = server.UserBootstrapToken(BootstrapSecret, 53101343)

// Harness is a running test server.
type Harness struct {
	URL    string
	Server *server.Server
	DB     *server.DB
	GitHub *FakeGitHub
	Config *server.Config
	clock  *Clock
	ts     *httptest.Server
}

// Clock is an adjustable clock.
type Clock struct {
	mu     sync.Mutex
	offset time.Duration
}

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

// Advance moves the server clock forward.
func (h *Harness) Advance(d time.Duration) { h.clock.Advance(d) }

// Now returns the server's clock.
func (h *Harness) Now() time.Time { return h.clock.Now() }

// FakeGitHub implements the parts of GitHub's OAuth web flow the server uses.
type FakeGitHub struct {
	URL   string
	mu    sync.Mutex
	users map[string]server.GitHubUser // login -> user
	codes map[string]string            // code -> login
	// pending is the login the next authorize request signs in as.
	pending string
	// Challenges records PKCE challenges by state, to check the exchange.
	challenges map[string]string
	verifiers  map[string]string
}

// AddUser registers a GitHub account.
func (g *FakeGitHub) AddUser(id int64, login string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.users[login] = server.GitHubUser{ID: id, Login: login}
}

func newFakeGitHub(t *testing.T) *FakeGitHub {
	g := &FakeGitHub{users: map[string]server.GitHubUser{}, codes: map[string]string{}, challenges: map[string]string{}, verifiers: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		g.mu.Lock()
		login := g.pending
		code := fmt.Sprintf("code-%d", len(g.codes)+1)
		g.codes[code] = login
		g.challenges[code] = q.Get("code_challenge")
		g.mu.Unlock()
		if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "test-client" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		u, _ := url.Parse(q.Get("redirect_uri"))
		v := u.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // fake GitHub in tests
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		g.mu.Lock()
		login, ok := g.codes[code]
		challenge := g.challenges[code]
		delete(g.codes, code)
		g.mu.Unlock()
		if !ok || r.PostForm.Get("client_secret") != "test-secret" || !pkceOK(challenge, r.PostForm.Get("code_verifier")) {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_" + login})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		login := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer gho_")
		g.mu.Lock()
		u, ok := g.users[login]
		g.mu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	g.URL = ts.URL
	return g
}

// Start runs a server that allows the given GitHub ids.
func Start(t *testing.T, allowed ...int64) *Harness {
	t.Helper()
	return StartWith(t, nil, allowed...)
}

// StartWith is Start with extra server options.
func StartWith(t *testing.T, opts []server.Option, allowed ...int64) *Harness {
	t.Helper()
	return StartConfig(t, opts, nil, allowed...)
}

// StartConfig is StartWith with a function that adjusts the configuration
// before it is validated.
func StartConfig(t *testing.T, opts []server.Option, edit func(*server.Config), allowed ...int64) *Harness {
	t.Helper()
	gh := newFakeGitHub(t)
	clock := &Clock{}
	db, err := server.OpenDB(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &Harness{GitHub: gh, DB: db, clock: clock}
	h.ts = httptest.NewUnstartedServer(nil)
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	h.URL = h.ts.URL
	cfg := &server.Config{
		BaseURL:      h.URL,
		DBPath:       "unused",
		VaultHistory: 50,
		GitHub:       server.GitHubConfig{ClientID: "test-client", ClientSecret: "test-secret", WebURL: gh.URL, APIURL: gh.URL},
		Access:       server.AccessConfig{AllowedGitHubIDs: allowed},
	}
	cfg.BootstrapToken = BootstrapSecret
	cfg.Sessions.Idle.Duration = 30 * 24 * time.Hour
	cfg.Sessions.Absolute.Duration = 90 * 24 * time.Hour
	if edit != nil {
		edit(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Config = cfg
	srv, err := server.New(cfg, db, slog.New(slog.DiscardHandler), append([]server.Option{server.WithClock(clock.Now)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	h.Server = srv
	h.ts.Config.Handler = srv.Handler()
	return h
}

// Browser is a cookie-holding web client signed in as one GitHub user.
type Browser struct {
	h      *Harness
	login  string
	client *http.Client
	// policy is the referrer policy of the last page, which decides the
	// Origin header the browser sends with a form on it.
	policy string
}

// Browser returns a browser that signs in as login.
func (h *Harness) Browser(login string) *Browser {
	jar, _ := cookiejar.New(nil)
	return &Browser{h: h, login: login, client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

// Client returns the browser's HTTP client.
func (b *Browser) Client() *http.Client { return b.client }

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// Get fetches a page, signing in through the fake GitHub when redirected.
func (b *Browser) Get(path string) (int, string, error) {
	b.h.GitHub.mu.Lock()
	b.h.GitHub.pending = b.login
	b.h.GitHub.mu.Unlock()
	resp, err := b.client.Get(b.h.URL + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	b.notePolicy(resp, body)
	return resp.StatusCode, string(body), err
}

// Post submits a form with the page's CSRF token.
func (b *Browser) Post(path, csrf string, form url.Values) (int, string, error) {
	if form == nil {
		form = url.Values{}
	}
	if csrf != "" {
		form.Set("csrf", csrf)
	}
	req, err := http.NewRequest(http.MethodPost, b.h.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.origin())
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	b.notePolicy(resp, body)
	return resp.StatusCode, string(body), err
}

// CSRF extracts the CSRF token from a page.
func CSRF(page string) string {
	m := csrfPattern.FindStringSubmatch(page)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

// Confirm signs in (if needed) and confirms or denies a device code.
func (b *Browser) Confirm(code string, approve bool) error {
	status, page, err := b.Get("/device")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("device page: HTTP %d: %s", status, page)
	}
	csrf := CSRF(page)
	status, page, err = b.Post("/device", csrf, url.Values{"code": {code}})
	if err != nil {
		return err
	}
	if status != http.StatusOK || !strings.Contains(page, "Confirm this sign-in") {
		return fmt.Errorf("code lookup: HTTP %d: %s", status, page)
	}
	decision := "deny"
	if approve {
		decision = "approve"
	}
	status, page, err = b.Post("/device/confirm", csrf, url.Values{"code": {code}, "decision": {decision}})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("confirm: HTTP %d: %s", status, page)
	}
	return nil
}

var metaReferrer = regexp.MustCompile(`<meta name="referrer" content="([^"]+)">`)

// notePolicy records a page's referrer policy: the meta tag wins over the
// header, as in browsers.
func (b *Browser) notePolicy(resp *http.Response, body []byte) {
	b.policy = resp.Header.Get("Referrer-Policy")
	if m := metaReferrer.FindSubmatch(body); m != nil {
		b.policy = string(m[1])
	}
}

// origin is the Origin header a browser sends with a same-origin form post:
// under "no-referrer" it sends "null" (Fetch, "serializing a request
// origin").
func (b *Browser) origin() string {
	if b.policy == "no-referrer" {
		return "null"
	}
	return b.h.URL
}

func pkceOK(challenge, verifier string) bool {
	return challenge != "" && verifier != "" && server.PKCEChallenge(verifier) == challenge
}
