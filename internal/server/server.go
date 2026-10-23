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
	"slices"
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
	// Bounds on the memory request bodies hold; see bodies.go.
	bodies, pendingSmall, pendingLarge *bodyBudget
	mux                                *http.ServeMux
	// Server-wide caps on open sign-ins; see WithSignInCaps.
	maxRegistrations int
	maxOAuthStates   int
	// Per-address and per-network registrations per hour.
	regPerAddr, regPerNet int
	// version and started are shown on the admin page.
	version string
	started time.Time
	// alertKick wakes the alert worker; alertHTTP delivers alerts.
	alertKick chan struct{}
	alertHTTP *http.Client
	// oidc checks machines' OIDC tokens.
	oidc *oidcIssuers
	// signer is the server's own key, which people may let sign removals.
	signer serverSigner
	// webauthn holds passkey ceremonies in progress.
	webauthn ceremonies
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

// WithRegistrationLimits overrides the per-address and per-network
// registration limits (per hour). Tests that sign in many devices from
// localhost raise them.
func WithRegistrationLimits(perAddr, perNet int) Option {
	return func(s *Server) { s.regPerAddr, s.regPerNet = perAddr, perNet }
}

// WithVersion sets the version the admin page shows.
func WithVersion(v string) Option { return func(s *Server) { s.version = v } }

// WithSignerURL sets the passkey signer page's origin, for tests.
func WithSignerURL(origin string) Option { return func(s *Server) { s.cfg.SignerURL = origin } }

// WithGitHub overrides the GitHub client.
func WithGitHub(g GitHub) Option { return func(s *Server) { s.github = g } }

// New builds a server around an open database.
func New(cfg *Config, db *DB, log *slog.Logger, opts ...Option) (*Server, error) {
	s := &Server{cfg: cfg, db: db, log: log, now: time.Now, version: "dev", anon: newLimiter(), limits: newLimiter(), notify: newNotifier(), bodies: newBodyBudget(maxBodyActive, maxBodyPerAccount), pendingSmall: newBodyBudget(maxPendingSmall, maxPendingPerDevice), pendingLarge: newBodyBudget(maxPendingLarge, maxLargeBody), maxRegistrations: maxOpenRegistrations, maxOAuthStates: maxOpenOAuthStates, regPerAddr: 10, regPerNet: 100}
	s.github = &githubClient{cfg: cfg.GitHub, http: &http.Client{Timeout: 15 * time.Second}}
	s.alertKick, s.alertHTTP = make(chan struct{}, 1), newAlertClient()
	s.oidc = newOIDCIssuers()
	for _, o := range opts {
		o(s)
	}
	s.started = s.now()
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
		"when":       func(t time.Time) template.HTML { return whenHTML(s.now(), t) },
		"ago":        func(t time.Time) string { return relTime(s.now(), t) },
		"bytes":      byteSize,
		"plural":     plural,
		"method":     methodLabel,
		"browser":    browserSummary,
		"dur":        durationText,
		"key":        keyBadge,
		"trimPrefix": strings.TrimPrefix,
		"dsPost":     dsPost,
		"dsLive":     dsLive,
		"int":        func(n uint64) int { return int(n) }, //nolint:gosec // chain lengths are small
		"hasEnv":     slices.Contains[[]string],
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tmpl = tmpl
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
	if s.alertsOn() {
		go s.alertWorker(ctx)
	}
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
		s.expireAccess(ctx)
		s.redeemWaitingInvites(ctx)
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
	m.HandleFunc("GET /activity", s.webActivity)
	m.HandleFunc("GET /activity/export", s.webActivityExport)
	m.HandleFunc("GET /vault", s.webVault)
	m.HandleFunc("GET /devices/{id}", s.webDevicePage)
	m.HandleFunc("POST /account/devices/{id}/suspend", s.webSuspendDevice)
	m.HandleFunc("POST /devices/{id}/approve", s.webDeviceApproveChange)
	m.HandleFunc("POST /devices/{id}/rename", s.webDeviceRenameChange)
	m.HandleFunc("POST /devices/{id}/revoke", s.webDeviceRevokeChange)
	m.HandleFunc("POST /account/sessions/{device}/end", s.webEndSessions)
	m.HandleFunc("POST /account/slots/{id}/disable", s.webDisableSlot)
	m.HandleFunc("POST /account/browsers/{id}/end", s.webEndBrowser)
	m.HandleFunc("POST /account/alerts", s.webSetAlertEmail)
	m.HandleFunc("POST /account/alerts/remove", s.webRemoveAlertEmail)
	m.HandleFunc("GET /alerts/confirm", s.webAlertConfirmPage)
	m.HandleFunc("POST /alerts/confirm", s.webAlertConfirm)
	m.HandleFunc("GET /admin", s.webAdmin)
	m.HandleFunc("GET /admin/users/{id}", s.webAdminUser)
	m.HandleFunc("GET /teams/{org}/{repo}", s.webTeam)
	m.HandleFunc("GET /teams/{org}/{repo}/live", s.webTeamLive)
	m.HandleFunc("GET /teams/{org}/{repo}/export", s.webTeamExport)
	m.HandleFunc("POST /teams/{org}/{repo}/members", s.webTeamAdd)
	m.HandleFunc("POST /teams/{org}/{repo}/members/set", s.webTeamSet)
	m.HandleFunc("POST /teams/{org}/{repo}/invites/{id}/cancel", s.webTeamCancelInvite)
	m.HandleFunc("POST /teams/{org}/{repo}/ask", s.webTeamAsk)
	m.HandleFunc("POST /teams/{org}/{repo}/requests/{id}/grant", s.webTeamGrantRequest)
	m.HandleFunc("POST /teams/{org}/{repo}/requests/{id}/deny", s.webTeamDenyRequest)
	m.HandleFunc("POST /teams/{org}/{repo}/expiries/{id}/cancel", s.webTeamCancelExpiry)
	m.HandleFunc("POST /teams/{org}/{repo}/archive", s.webTeamArchive)
	m.HandleFunc("POST /teams/{org}/{repo}/unarchive", s.webTeamUnarchive)
	m.HandleFunc("POST /teams/{org}/{repo}/move", s.webTeamMove)
	m.HandleFunc("POST /teams/{org}/{repo}/handover", s.webTeamHandover)
	m.HandleFunc("POST /teams/{org}/{repo}/leave", s.webTeamLeave)
	m.HandleFunc("POST /teams/{org}/{repo}/delete", s.webTeamDelete)
	m.HandleFunc("POST /access/ask", s.webAskAccess)
	m.HandleFunc("POST /access/requests/{id}/withdraw", s.webWithdrawRequest)
	m.HandleFunc("POST /teams/{org}/{repo}/changes/{id}/dismiss", s.webTeamDismiss)
	m.HandleFunc("GET /groups", s.webGroups)
	m.HandleFunc("GET /groups/live", s.webGroupsLive)
	m.HandleFunc("GET /changes", s.webChanges)
	m.HandleFunc("GET /changes/live", s.webChangesLive)
	m.HandleFunc("POST /changes/{id}/dismiss", s.webDismissChange)
	m.HandleFunc("GET /account/signing", s.webSigning)
	m.HandleFunc("POST /account/delegates/server", s.webDelegateServer)
	m.HandleFunc("POST /account/delegates/{id}/remove", s.webDelegateRemove)
	m.HandleFunc("GET /groups/{org}/{name}", s.webGroup)
	m.HandleFunc("GET /groups/{org}/{name}/live", s.webGroupLive)
	m.HandleFunc("GET /groups/{org}/{name}/export", s.webGroupExport)
	m.HandleFunc("GET /access", s.webAccess)
	m.HandleFunc("GET /people/{login}", s.webPerson)
	m.HandleFunc("POST /people/{login}/offboard", s.webOffboard)
	m.HandleFunc("GET /orgs/{org}", s.webOrg)
	m.HandleFunc("POST /orgs/{org}/policy", s.webOrgPolicy)
	m.HandleFunc("GET /teams/{org}/{repo}/review", s.webReviewPage)
	m.HandleFunc("POST /teams/{org}/{repo}/review", s.webReview)
	m.HandleFunc("POST /groups/{org}/{name}/access", s.webGroupAccess)
	m.HandleFunc("POST /groups/{org}/{name}/remove", s.webGroupRemove)
	m.HandleFunc("POST /groups/{org}/{name}/members", s.webGroupAddMember)
	m.HandleFunc("POST /groups/{org}/{name}/members/remove", s.webGroupRemoveMember)
	m.HandleFunc("POST /groups/{org}/{name}/invites/{id}/cancel", s.webGroupCancelInvite)
	m.HandleFunc("POST /groups/{org}/{name}/joins/{id}/reject", s.webGroupRejectJoin)
	m.HandleFunc("POST /groups/{org}/{name}/changes/{id}/dismiss", s.webGroupDismiss)

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
	m.Handle("GET /v1/identity", s.api(false, s.apiIdentity))
	m.Handle("GET /v1/agent-slots", s.api(false, s.apiAgentSlots))
	m.Handle("POST /v1/recovery", s.api(true, s.apiRecovery))
	m.Handle("POST /v1/agent-slots/unlock", s.api(true, s.apiAgentUnlock))
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

	// API: shared projects and machines.
	m.Handle("GET /v1/users", s.api(false, s.apiPerson))
	m.Handle("GET /v1/users/{id}", s.api(false, s.apiPerson))
	m.Handle("PUT /v1/account/proof", s.api(false, s.apiPutProof))
	m.Handle("GET /v1/projects", s.api(false, s.apiProjects))
	m.Handle("GET /v1/projects/{org}/{repo}/chain", s.api(false, s.apiProjectChain))
	m.Handle("GET /v1/projects/{org}/{repo}/status", s.api(false, s.apiProjectStatus))
	m.Handle("POST /v1/projects/{org}/{repo}/commit", s.api(false, s.apiProjectCommit))
	m.Handle("DELETE /v1/projects/{org}/{repo}", s.api(false, s.apiDeleteProject))
	m.Handle("GET /v1/projects/{org}/{repo}/expiries", s.api(false, s.apiExpiries))
	m.Handle("POST /v1/projects/{org}/{repo}/expiries", s.api(false, s.apiSetExpiry))
	m.Handle("DELETE /v1/projects/{org}/{repo}/expiries/{id}", s.api(false, s.apiDeleteExpiry))
	m.Handle("GET /v1/requests", s.api(false, s.apiRequests))
	m.Handle("GET /v1/orgs/{org}/policy", s.api(false, s.apiOrgPolicy))
	m.Handle("GET /v1/projects/{org}/{repo}/review", s.api(false, s.apiReview))
	m.Handle("POST /v1/projects/{org}/{repo}/review", s.api(false, s.apiRecordReview))
	m.Handle("POST /v1/requests", s.api(false, s.apiNewRequest))
	m.Handle("POST /v1/requests/{id}/close", s.api(false, s.apiCloseRequest))
	m.Handle("GET /v1/grants", s.api(false, s.apiGrants))
	m.Handle("POST /v1/grants/ack", s.api(false, s.apiGrantAck))
	m.HandleFunc("POST /v1/machines/keys", s.apiMachineKeys)
	m.Handle("GET /v1/groups", s.api(false, s.apiGroups))
	m.Handle("GET /v1/groups/{org}/{name}/chain", s.api(false, s.apiGroupChain))
	m.Handle("GET /v1/groups/{org}/{name}/status", s.api(false, s.apiGroupStatus))
	m.Handle("GET /v1/groups/{org}/{name}/key", s.api(false, s.apiGroupKeyGrants))
	m.Handle("GET /v1/groups/{org}/{name}/keys", s.api(false, s.apiGroupKeys))
	m.Handle("POST /v1/groups/{org}/{name}/commit", s.api(false, s.apiGroupCommit))
	m.Handle("POST /v1/groups/{org}/{name}/joins/{id}/reject", s.api(false, s.apiGroupRejectJoin))
	m.Handle("GET /v1/changes", s.api(false, s.apiChanges))
	m.Handle("POST /v1/changes/{id}/close", s.api(false, s.apiCloseChange))
	m.HandleFunc("POST /v1/fleet/join", s.apiFleetJoin)
	m.HandleFunc("POST /v1/fleet/join/status", s.apiFleetJoinStatus)
	m.HandleFunc("POST /v1/fleet/enroll", s.apiFleetEnroll)
	m.HandleFunc("POST /v1/fleet/keys", s.apiFleetKeys)
	m.HandleFunc("GET /v1/server/key", s.apiServerKey)
	// The passkey signer page, hosted apart (passkeys.go).
	m.HandleFunc("OPTIONS /signer/v1/", s.signerCORS(func(http.ResponseWriter, *http.Request) {}))
	m.HandleFunc("GET /signer/v1/me", s.signerCORS(s.signerMe))
	m.HandleFunc("GET /signer/v1/changes", s.signerCORS(s.signerChanges))
	m.HandleFunc("POST /signer/v1/passkeys/options", s.signerCORS(s.webPasskeyOptions))
	m.HandleFunc("POST /signer/v1/passkeys", s.signerCORS(s.webPasskeyRegister))
	m.HandleFunc("POST /signer/v1/changes/{id}/begin", s.signerCORS(s.webPasskeyBegin))
	m.HandleFunc("POST /signer/v1/changes/{id}/finish", s.signerCORS(s.webPasskeyFinish))
	s.mux = m
}

// secure adds security headers to every response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Never send a Referer to other sites. Not "no-referrer": under it
		// browsers send "Origin: null" on this site's own form posts, which
		// the CSRF origin check must refuse.
		h.Set("Referrer-Policy", "same-origin")
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
		// Several header lines mean the same as one comma-joined line, and
		// some proxies add their own line rather than extend the client's.
		values := strings.Split(strings.Join(r.Header.Values(s.cfg.ClientIPHeader), ","), ",")
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
