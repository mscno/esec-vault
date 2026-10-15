// Package server implements the esec vault server: a GitHub-authenticated
// store for ciphertext and signed device chains. It never sees a private key
// or a plaintext secret, and clients verify everything it returns.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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
	limits *limiter
	notify *notifier
	mux    *http.ServeMux
}

// Option customizes a Server, mainly for tests.
type Option func(*Server)

// WithClock overrides the clock.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithGitHub overrides the GitHub client.
func WithGitHub(g GitHub) Option { return func(s *Server) { s.github = g } }

// New builds a server around an open database.
func New(cfg *Config, db *DB, log *slog.Logger, opts ...Option) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
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
	s := &Server{cfg: cfg, db: db, log: log, tmpl: tmpl, now: time.Now, limits: newLimiter(), notify: newNotifier()}
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
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	s.log.Info("esec vault server listening", "addr", s.cfg.Listen, "base_url", s.cfg.BaseURL)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errc:
		return err
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if err := s.db.cleanup(ctx, s.now()); err != nil && ctx.Err() == nil {
			s.log.Warn("cleanup failed", "error", err)
		}
		s.limits.prune(s.now())
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
		if v := strings.TrimSpace(r.Header.Get(s.cfg.ClientIPHeader)); v != "" {
			if ip := net.ParseIP(v); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
}

// limiter is a fixed-window counter per key. It is in memory: the server is
// a single instance, and a restart resetting counters is acceptable.
type limiter struct {
	mu sync.Mutex
	m  map[string]*window
}

func newLimiter() *limiter { return &limiter{m: map[string]*window{}} }

// allow counts one event for key and reports whether it is within max per
// period.
func (l *limiter) allow(key string, max int, period time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.m[key]
	if !ok || now.Sub(w.start) >= period {
		w = &window{start: now}
		l.m[key] = w
	}
	w.count++
	return w.count <= max
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

func errorf(format string, args ...any) error { return fmt.Errorf(format, args...) }
