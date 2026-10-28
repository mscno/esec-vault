// Package broker implements the esec-vault agent: a daemon holding decrypted
// project keys in memory and answering policy-checked requests over a unix
// socket. It never returns key material — only decrypted secret values.
package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec"

	"github.com/mscno/esec-vault/internal/policy"
)

// Ops supported by the broker protocol.
const (
	OpPing       = "ping"
	OpListEnvs   = "list_envs"
	OpGetSecrets = "get_secrets"
	OpApprove    = "approve"
)

// Request is a single JSON-lines protocol request.
type Request struct {
	Op      string `json:"op"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
	Path    string `json:"path,omitempty"`   // get_secrets: absolute path of the encrypted secrets file
	Format  string `json:"format,omitempty"` // get_secrets: esec file format, e.g. ".ejson"
	ID      string `json:"id,omitempty"`     // approve: pending request id
	// Session labels the agent session a request comes from (ESEC_VAULT_SESSION).
	Session string `json:"session,omitempty"`
	// Content is the encrypted secrets file itself, for a request forwarded
	// from another machine, where Path names a file on that machine.
	Content []byte `json:"content,omitempty"`
	// Host names the machine a forwarded request comes from.
	Host string `json:"host,omitempty"`
}

// GuardRequest is a read of a guarded key, as the guard is asked for it.
type GuardRequest struct {
	Project, Env, PublicKey string
	// Path is the secrets file to decrypt; Host is set for a forwarded one.
	Path, Host string
	UID, PID   uint32
	// Caller is the asking program and its parents.
	Caller  string
	Session string
}

// Guarder opens guarded keys: it asks the person, then waits for the
// hardware touch.
type Guarder interface {
	// Has reports whether project holds a guarded key for env or pub.
	Has(project, env, pub string) bool
	// Key returns the private key, after the person allowed it.
	Key(req GuardRequest) (priv string, how string, err error)
}

// Response is a single JSON-lines protocol response.
type Response struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Envs     []string          `json:"envs,omitempty"`    // list_envs
	Secrets  map[string]string `json:"secrets,omitempty"` // get_secrets
	VaultEnv map[string]string `json:"-"`                 // unused
	Pending  string            `json:"pending,omitempty"` // informational
}

// Server is the broker daemon.
type Server struct {
	// Keys maps project → keyring entries (ESEC_PRIVATE_KEY_DEV → hex).
	Keys map[string]map[string]string

	Policy *policy.Policy
	Audit  *AuditLogger
	Logger *slog.Logger

	// ApproveTimeout bounds how long an "ask" request waits for approval.
	ApproveTimeout time.Duration

	mu      sync.Mutex
	pending map[string]chan bool
	keysMu  sync.RWMutex
	locked  bool
	expires time.Time
	epoch   uint64
	timer   *time.Timer
	// ControlOnlyApproval reserves approvals for the daemon control socket.
	ControlOnlyApproval bool
	// Guard opens guarded keys; nil serves none.
	Guard Guarder
	// Forwarded marks a broker reached from other machines (esec vault
	// forward): every read asks the person, and files come in requests.
	Forwarded bool
	// Chain describes the program behind a pid; tests replace it.
	Chain func(pid uint32) string
}

// NewServer returns a broker server.
func NewServer(keys map[string]map[string]string, pol *policy.Policy, audit *AuditLogger, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if keys == nil {
		keys = map[string]map[string]string{}
	}
	return &Server{
		Keys:           keys,
		Policy:         pol,
		Audit:          audit,
		Logger:         logger,
		ApproveTimeout: 5 * time.Minute,
		pending:        map[string]chan bool{},
	}
}

// Serve listens on the socket and serves until ctx is cancelled. The socket
// file is removed on shutdown.
func (s *Server) Serve(ctx context.Context, sockPath string) error {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		return err
	}
	// Refuse to serve over a live socket; clean up a stale one.
	if info, err := os.Lstat(sockPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing non-socket at %s", sockPath)
		}
		if c, derr := net.DialTimeout("unix", sockPath, 200*time.Millisecond); derr == nil {
			c.Close()
			return fmt.Errorf("broker already running at %s", sockPath)
		}
		if err := os.Remove(sockPath); err != nil {
			return err
		}
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		ln.Close()
		return err
	}
	defer func() {
		ln.Close()
		os.Remove(sockPath)
	}()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	s.Logger.Info("broker serving", "socket", sockPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// keyFor returns the hex private key for a project environment, resolving via
// the shared chain (environment suffixes, then the file's public key).
func (s *Server) keyFor(project, env string, pubkey *[32]byte) (string, error) {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	if s.locked || (!s.expires.IsZero() && !time.Now().Before(s.expires)) {
		return "", fmt.Errorf("vault is locked; run 'esec vault unlock'")
	}
	entries, ok := s.Keys[project]
	if !ok {
		return "", fmt.Errorf("no keys held for project %q", project)
	}
	key, _, ok := esec.ResolveKey(entries, esec.KeySuffixes(env), pubkey)
	if !ok {
		return "", fmt.Errorf("no key for env %q (or the file's public key) held for project %q", env, project)
	}
	return key, nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	uid, pid, err := peerCredentials(uc)
	if err != nil {
		s.Logger.Warn("refusing connection without peer credentials", "error", err)
		return
	}

	dec := json.NewDecoder(io.LimitReader(conn, 1<<20))
	enc := json.NewEncoder(conn)
	var req Request
	if err := dec.Decode(&req); err != nil {
		return
	}
	resp := s.dispatch(uid, pid, &req)
	if err := enc.Encode(resp); err != nil {
		s.Logger.Warn("failed to encode response", "error", err)
	}
}

// audit records a decision and reports whether it was persisted. Callers must
// fail closed on error: serving a secret whose allow decision was never
// written would leave no record of the disclosure.
func (s *Server) audit(uid, pid uint32, op, project, env, decision, detail string) error {
	return s.auditEntry(AuditEntry{UID: uid, PID: pid, Op: op, Project: project, Env: env, Decision: decision, Detail: detail})
}

// auditReq records a decision about a request, with its caller and session.
func (s *Server) auditReq(uid, pid uint32, req *Request, decision, detail string) error {
	chain := ""
	if s.Chain != nil {
		chain = s.Chain(pid)
	}
	return s.auditEntry(AuditEntry{UID: uid, PID: pid, Op: req.Op, Project: req.Project, Env: req.Env, Decision: decision, Detail: detail, Caller: chain, Session: req.Session})
}

func (s *Server) auditEntry(e AuditEntry) error {
	if s.Audit == nil {
		return nil
	}
	if err := s.Audit.Log(e); err != nil {
		s.Logger.Error("audit log write failed", "error", err)
		return err
	}
	return nil
}

func (s *Server) dispatch(uid, pid uint32, req *Request) *Response {
	switch req.Op {
	case OpPing:
		return &Response{OK: true}

	case OpListEnvs:
		s.keysMu.RLock()
		defer s.keysMu.RUnlock()
		if s.locked {
			return &Response{Error: "vault is locked"}
		}
		entries, ok := s.Keys[req.Project]
		if !ok {
			// A denied request serves nothing, so a lost audit line cannot
			// cause an unrecorded disclosure.
			_ = s.audit(uid, pid, req.Op, req.Project, "", "deny", "unknown project")
			return &Response{OK: false, Error: fmt.Sprintf("no keys held for project %q", req.Project)}
		}
		var envs []string
		for k := range entries {
			if k == esec.EsecPrivateKey {
				envs = append(envs, "")
				continue
			}
			if rest, ok := strings.CutPrefix(k, esec.EsecPrivateKey+"_"); ok {
				envs = append(envs, strings.ToLower(rest))
			}
		}
		if err := s.audit(uid, pid, req.Op, req.Project, "", "allow", "metadata"); err != nil {
			return auditFailed()
		}
		return &Response{OK: true, Envs: envs}

	case OpGetSecrets:
		return s.handleGetSecrets(uid, pid, req)

	case OpApprove:
		if s.ControlOnlyApproval {
			return &Response{Error: "approval requires the owner control socket"}
		}
		return s.handleApprove(uid, pid, req)

	default:
		return &Response{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// auditFailed refuses a request whose decision could not be recorded, so a
// secret is never disclosed without an audit trail.
func auditFailed() *Response {
	return &Response{OK: false, Error: "audit log unavailable; refusing to serve secrets"}
}

// recordAllow persists an allow decision and reports whether it may proceed.
// Serving secrets without a recorded decision would leave no trace of the
// disclosure, so a failed write refuses the request.
func (s *Server) recordAllow(uid, pid uint32, req *Request, detail string) error {
	return s.auditReq(uid, pid, req, "allow", detail)
}

// authorize applies policy and records the decision. It returns a non-nil
// Response when the request must not proceed.
func (s *Server) authorize(uid, pid uint32, req *Request) *Response {
	s.keysMu.RLock()
	action := s.Policy.Decide(req.Project, req.Env, uid)
	s.keysMu.RUnlock()
	if action == policy.Deny {
		// Denials serve nothing; the audit line is best effort here.
		_ = s.auditReq(uid, pid, req, "deny", "policy")
		return &Response{OK: false, Error: fmt.Sprintf("denied by policy: %s env %q", req.Project, req.Env)}
	}
	if action == policy.Ask {
		id, err := s.newPending()
		if err != nil {
			return &Response{OK: false, Error: err.Error()}
		}
		if err := s.auditReq(uid, pid, req, "ask", id); err != nil {
			return auditFailed()
		}
		if !s.waitPending(id) {
			_ = s.auditReq(uid, pid, req, "deny", "approval "+id+" timed out or rejected")
			return &Response{OK: false, Error: fmt.Sprintf("approval %s was not granted", id)}
		}
		if err := s.recordAllow(uid, pid, req, "approved "+id); err != nil {
			return auditFailed()
		}
		return nil
	}
	if err := s.recordAllow(uid, pid, req, "policy"); err != nil {
		return auditFailed()
	}
	return nil
}

func (s *Server) handleGetSecrets(uid, pid uint32, req *Request) *Response {
	if req.Project == "" || req.Path == "" {
		return &Response{OK: false, Error: "project and path are required"}
	}
	if !filepath.IsAbs(req.Path) {
		return &Response{OK: false, Error: "path must be absolute"}
	}
	if s.Forwarded && len(req.Content) == 0 {
		return &Response{OK: false, Error: "a forwarded request carries its file"}
	}
	data := req.Content
	if !s.Forwarded {
		var err error
		if data, err = os.ReadFile(req.Path); err != nil {
			return &Response{OK: false, Error: fmt.Sprintf("failed to read secrets file: %v", err)}
		}
	}

	format := esec.FileFormat(req.Format)
	// The file's embedded public key is the ground truth for key resolution
	// (monorepo components, rotated keys).
	var pubkey *[32]byte
	pubHex := ""
	if pub, err := esec.ExtractPublicKey(data, format); err == nil {
		pubkey = &pub
		pubHex = hex.EncodeToString(pub[:])
	}

	var key string
	if s.Guard != nil && s.Guard.Has(req.Project, req.Env, pubHex) {
		k, denied := s.guardedKey(uid, pid, req, pubHex)
		if denied != nil {
			return denied
		}
		key = k
	} else {
		if s.Forwarded {
			// Only guarded keys are served to other machines: each read
			// is then one the person sees and touches.
			_ = s.auditEntry(AuditEntry{UID: uid, PID: pid, Op: req.Op, Project: req.Project, Env: req.Env, Decision: "deny", Detail: "forwarded read of an unguarded key", Session: req.Session})
			return &Response{OK: false, Error: fmt.Sprintf("%s %s is not guarded: a forwarded broker serves guarded keys only; give the machine its own key (esec vault group token)", req.Project, req.Env)}
		}
		if denied := s.authorize(uid, pid, req); denied != nil {
			return denied
		}
		var err error
		if key, err = s.keyFor(req.Project, req.Env, pubkey); err != nil {
			return &Response{OK: false, Error: err.Error()}
		}
	}

	var plain bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(data), &plain, "", format, ".", key); err != nil {
		return &Response{OK: false, Error: fmt.Sprintf("decryption failed: %v", err)}
	}

	secrets, err := esec.EnvVars(plain.Bytes(), format)
	if err != nil {
		return &Response{OK: false, Error: err.Error()}
	}
	// Never inject public-key markers or underscore-prefixed metadata.
	for k := range secrets {
		if k == esec.EsecPublicKey || strings.HasPrefix(k, "_") {
			delete(secrets, k)
		}
	}
	return &Response{OK: true, Secrets: secrets}
}

// guardedKey asks the guard for a guarded key. A policy rule that denies
// the environment still denies; otherwise the guard's own dialog and touch
// are the approval, in place of an "ask" rule.
func (s *Server) guardedKey(uid, pid uint32, req *Request, pub string) (string, *Response) {
	s.keysMu.RLock()
	action, matched := s.Policy.DecideRule(req.Project, req.Env, uid)
	s.keysMu.RUnlock()
	chain := ""
	if s.Chain != nil {
		chain = s.Chain(pid)
	}
	if req.Host != "" {
		chain = req.Host + ": " + chain
	}
	entry := AuditEntry{UID: uid, PID: pid, Op: req.Op, Project: req.Project, Env: req.Env, Caller: chain, Session: req.Session}
	if matched && action == policy.Deny {
		entry.Decision, entry.Detail = "deny", "policy"
		_ = s.auditEntry(entry)
		return "", &Response{OK: false, Error: fmt.Sprintf("denied by policy: %s env %q", req.Project, req.Env)}
	}
	entry.Decision, entry.Detail = "ask", "guard"
	if err := s.auditEntry(entry); err != nil {
		return "", auditFailed()
	}
	key, how, err := s.Guard.Key(GuardRequest{Project: req.Project, Env: req.Env, PublicKey: pub, Path: req.Path, Host: req.Host, UID: uid, PID: pid, Caller: chain, Session: req.Session})
	if err != nil {
		entry.Decision, entry.Detail = "deny", "guard: "+err.Error()
		_ = s.auditEntry(entry)
		return "", &Response{OK: false, Error: err.Error()}
	}
	entry.Decision, entry.Detail = "allow", "guard "+how
	if err := s.auditEntry(entry); err != nil {
		return "", auditFailed()
	}
	return key, nil
}

func (s *Server) newPending() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.pending[id] = make(chan bool, 1)
	s.mu.Unlock()
	return id, nil
}

func (s *Server) waitPending(id string) bool {
	s.mu.Lock()
	ch := s.pending[id]
	s.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case approved := <-ch:
		return approved
	case <-time.After(s.ApproveTimeout):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return false
	}
}

func (s *Server) handleApprove(uid, pid uint32, req *Request) *Response {
	if req.ID == "" {
		return &Response{OK: false, Error: "id is required"}
	}
	s.mu.Lock()
	ch, ok := s.pending[req.ID]
	if ok {
		delete(s.pending, req.ID)
	}
	s.mu.Unlock()
	if !ok {
		return &Response{OK: false, Error: fmt.Sprintf("no pending approval %q", req.ID)}
	}
	if err := s.audit(uid, pid, req.Op, "", "", "approve", req.ID); err != nil {
		// Do not grant the approval: the decision would go unrecorded.
		return auditFailed()
	}
	ch <- true
	return &Response{OK: true}
}
