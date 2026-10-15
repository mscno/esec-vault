// Package server implements the esec vault server: a GitHub-authenticated
// store for ciphertext and signed device chains. It never sees a private key
// or a plaintext secret, and clients verify everything it returns.
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/wire"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server is the HTTP server.
type Server struct {
	cfg    *Config
	db     *DB
	log    *slog.Logger
	tmpl   *template.Template
	github GitHub
	now    func() time.Time
	// anon rate-limits unauthenticated requests and limits signed-in ones.
	// They are separate so anonymous floods cannot evict signed-in counters.
	anon   *limiter
	limits *limiter
	notify *notifier
	mux    *http.ServeMux
	// Server-wide caps on open sign-ins; see WithSignInCaps.
	maxRegistrations int
	maxOAuthStates   int
}

// Option customizes a Server, mainly for tests.
type Option func(*Server)

// WithClock overrides the clock.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithSignInCaps overrides the server-wide caps on open registrations (per
// hour) and open GitHub sign-ins (per 10 minutes). Tests use small values.
func WithSignInCaps(registrations, oauthStates int) Option {
	return func(s *Server) { s.maxRegistrations, s.maxOAuthStates = registrations, oauthStates }
}

// WithGitHub overrides the GitHub client.
func WithGitHub(g GitHub) Option { return func(s *Server) { s.github = g } }

// New builds a server around an open database.
func New(cfg *Config, db *DB, log *slog.Logger, opts ...Option) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"short": func(s string) string {
			if len(s) > 16 {
				return s[:16] + "…"
			}
			return s
		},
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, db: db, log: log, tmpl: tmpl, now: time.Now, anon: newLimiter(), limits: newLimiter(), notify: newNotifier(), maxRegistrations: maxOpenRegistrations, maxOAuthStates: maxOpenOAuthStates}
	s.github = &githubClient{cfg: cfg.GitHub, http: &http.Client{Timeout: 15 * time.Second}}
	for _, o := range opts {
		o(s)
	}
	s.routes()
	return s, nil
}

// Handler returns the root handler with security headers.
func (s *Server) Handler() http.Handler { return s.secure(s.mux) }

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go s.housekeeping(ctx)
	if s.cfg.ClientIPHeader == "" && s.cfg.Secure() {
		s.log.Warn("client_ip_header is not set: rate limits and audit addresses use the TCP peer; behind a reverse proxy that is the proxy, so set client_ip_header")
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	s.log.Info("esec vault server listening", "addr", s.cfg.Listen, "base_url", s.cfg.BaseURL)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errc:
		return err
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		if err := s.db.cleanup(ctx, s.now()); err != nil && ctx.Err() == nil {
			s.log.Warn("cleanup failed", "error", err)
		}
		s.limits.prune(s.now())
		s.anon.prune(s.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })

	// Web.
	m.HandleFunc("GET /{$}", s.webIndex)
	m.HandleFunc("GET /auth/github", s.webGitHubStart)
	m.HandleFunc("GET /auth/github/callback", s.webGitHubCallback)
	m.HandleFunc("POST /auth/logout", s.webLogout)
	m.HandleFunc("GET /device", s.webDevice)
	m.HandleFunc("POST /device", s.webDeviceLookup)
	m.HandleFunc("POST /device/confirm", s.webDeviceConfirm)
	m.HandleFunc("GET /account", s.webAccount)
	m.HandleFunc("GET /projects", s.webProjects)
	m.HandleFunc("POST /account/devices/{id}/suspend", s.webSuspendDevice)
	m.HandleFunc("POST /account/sessions/{device}/end", s.webEndSessions)
	m.HandleFunc("POST /account/slots/{id}/disable", s.webDisableSlot)

	// API: device authorization grant.
	m.HandleFunc("POST /v1/auth/device", s.apiDeviceRegister)
	m.HandleFunc("POST /v1/auth/token", s.apiToken)

	// API: authenticated. "pending" routes are open to devices that are not
	// yet approved; every other route requires an active device.
	m.Handle("POST /v1/auth/logout", s.api(true, s.apiLogout))
	m.Handle("GET /v1/me", s.api(true, s.apiMe))
	m.Handle("GET /v1/chain", s.api(true, s.apiChain))
	m.Handle("POST /v1/devices/self/proof", s.api(true, s.apiDeviceProof))
	m.Handle("GET /v1/devices/self/box", s.api(true, s.apiDeviceBox))
	m.Handle("GET /v1/identity", s.api(true, s.apiIdentity))
	m.Handle("GET /v1/agent-slots", s.api(true, s.apiAgentSlots))
	m.Handle("POST /v1/commit", s.api(true, s.apiCommit))
	m.Handle("GET /v1/devices", s.api(false, s.apiDevices))
	m.Handle("POST /v1/devices/{id}/suspend", s.api(false, s.apiSuspend))
	m.Handle("GET /v1/vault", s.api(false, s.apiVaultGet))
	m.Handle("PUT /v1/vault", s.api(false, s.apiVaultPut))
	m.Handle("GET /v1/vault/versions", s.api(false, s.apiVaultVersions))
	m.Handle("GET /v1/vault/versions/{version}", s.api(false, s.apiVaultVersion))
	m.Handle("DELETE /v1/agent-slots/{id}", s.api(false, s.apiDisableSlot))
	m.Handle("GET /v1/events", s.api(false, s.apiEvents))
	m.Handle("GET /v1/audit", s.api(false, s.apiAudit))
	s.mux = m
}

// secure adds security headers to every response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Device codes appear in URLs; never leak them through Referer.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if s.cfg.Secure() {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the caller's address.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.ClientIPHeader != "" {
		// A proxy that appends to a list puts the address it saw last; the
		// earlier entries come from the client and cannot be trusted.
		values := strings.Split(r.Header.Get(s.cfg.ClientIPHeader), ",")
		if ip := net.ParseIP(strings.TrimSpace(values[len(values)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateKey groups addresses for rate limiting: IPv4 per address, IPv6 per /64,
// since one IPv6 user usually controls a whole /64.
func rateKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// prefixKey groups addresses by network: IPv4 /24, IPv6 /48. It bounds what
// one network can do with many addresses.
func prefixKey(ip string) string {
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil:
		return ip
	case parsed.To4() != nil:
		return parsed.Mask(net.CIDRMask(24, 32)).String() + "/24"
	default:
		return parsed.Mask(net.CIDRMask(48, 128)).String() + "/48"
	}
}

// allowAnon counts an unauthenticated request per address and per network.
// The network is checked first, so requests from a blocked network create no
// per-address counters.
func (s *Server) allowAnon(kind, ip string, perAddr, perNet int, period time.Duration) bool {
	now := s.now()
	return s.anon.allow(kind+":net:"+prefixKey(ip), perNet, period, now) && s.anon.allow(kind+":"+rateKey(ip), perAddr, period, now)
}

// ---- JSON helpers ----

const maxSmallBody = 64 << 10

// maxLargeBody bounds commits and vault uploads.
const maxLargeBody = 16 << 20

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func decodeStrict(b []byte, v any) error { return envelope.DecodeStrict(b, v) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("response write failed", "error", err)
	}
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, wire.Error{Code: code, Description: desc})
}

// ---- identifiers and secrets ----

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func randomID(prefix string) string {
	var b [15]byte
	_, _ = rand.Read(b[:])
	return prefix + idEncoding.EncodeToString(b[:])
}

func randomToken(prefix string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}

// ---- rate limiting ----

type window struct {
	start time.Time
	count int
	limit int
}

// exhausted reports whether the window has used up its limit.
func (w *window) exhausted() bool { return w.count >= w.limit }

// limiter is a fixed-window counter per key. It is in memory: the server is
// a single instance, and a restart resetting counters is acceptable.
type limiter struct {
	mu sync.Mutex
	m  map[string]*window
	// quietUntil pauses eviction scans after one found only exhausted
	// windows, so such a table does not cost a full scan per request.
	quietUntil time.Time
}

// maxLimiterKeys is the size at which the limiter evicts entries. Exhausted
// windows are never evicted, so flooding the table cannot reset a limit that
// was reached; hardLimiterKeys bounds memory if an attacker exhausts that
// many keys, after which new keys are refused.
const (
	maxLimiterKeys  = 100000
	hardLimiterKeys = 1000000
)

func newLimiter() *limiter { return &limiter{m: map[string]*window{}} }

// allow counts one event for key and reports whether it is within limit per
// period.
func (l *limiter) allow(key string, limit int, period time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.m[key]
	if !ok && len(l.m) >= maxLimiterKeys {
		l.evict(now)
		if len(l.m) >= hardLimiterKeys {
			return false
		}
	}
	if !ok || now.Sub(w.start) >= period {
		w = &window{start: now, limit: limit}
		l.m[key] = w
	}
	w.count++
	return w.count <= limit
}

// refund takes back one counted event, for attempts that turned out fine.
func (l *limiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w, ok := l.m[key]; ok && w.count > 0 {
		w.count--
	}
}

// evict drops expired windows, then windows that have not reached their
// limit (lowest counts first) until the table is back to nine tenths of
// maxLimiterKeys. Exhausted windows are kept. When exhausted windows alone
// exceed that target, it frees every other window and pauses scanning for a
// minute, so such a table costs at most one scan per minute.
func (l *limiter) evict(now time.Time) {
	if now.Before(l.quietUntil) {
		return
	}
	for k, w := range l.m {
		if now.Sub(w.start) > 2*time.Hour {
			delete(l.m, k)
		}
	}
	target := maxLimiterKeys * 9 / 10
	if len(l.m) <= target {
		return
	}
	type entry struct {
		key string
		w   *window
	}
	var candidates []entry
	for k, w := range l.m {
		if !w.exhausted() {
			candidates = append(candidates, entry{k, w})
		}
	}
	if len(l.m)-len(candidates) > target {
		// Exhausted windows alone exceed the target: free the windows that
		// are less than half used and pause, rather than rescanning for one
		// or two slots per key. Windows near their limit are kept, so a sweep
		// cannot be used to reset them.
		for _, c := range candidates {
			if 2*c.w.count < c.w.limit {
				delete(l.m, c.key)
			}
		}
		l.quietUntil = now.Add(time.Minute)
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].w.count != candidates[j].w.count {
			return candidates[i].w.count < candidates[j].w.count
		}
		return candidates[i].w.start.Before(candidates[j].w.start)
	})
	for _, c := range candidates {
		if len(l.m) <= target {
			break
		}
		delete(l.m, c.key)
	}
}

func (l *limiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.m {
		if now.Sub(w.start) > 2*time.Hour {
			delete(l.m, k)
		}
	}
}

// ---- change notification for long polls ----

type notifier struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func newNotifier() *notifier { return &notifier{waiters: map[string][]chan struct{}{}} }

func (n *notifier) wait(user string) chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := make(chan struct{})
	n.waiters[user] = append(n.waiters[user], c)
	return c
}

func (n *notifier) cancel(user string, c chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list := n.waiters[user]
	for i, w := range list {
		if w == c {
			n.waiters[user] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(n.waiters[user]) == 0 {
		delete(n.waiters, user)
	}
}

func (n *notifier) wake(user string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.waiters[user] {
		close(c)
	}
	delete(n.waiters, user)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "internal error")
}
