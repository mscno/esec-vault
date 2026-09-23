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

// keyFor returns the hex private key for a project environment.
func (s *Server) keyFor(project, env string) (string, error) {
	entries, ok := s.Keys[project]
	if !ok {
		return "", fmt.Errorf("no keys held for project %q", project)
	}
	name := esec.EsecPrivateKey
	if env != "" {
		name = fmt.Sprintf("%s_%s", esec.EsecPrivateKey, strings.ToUpper(env))
	}
	key, ok := entries[name]
	if !ok {
		return "", fmt.Errorf("no key %q held for project %q", name, project)
	}
	return key, nil
}

// Serve listens on the socket and serves until ctx is cancelled. The socket
// file is removed on shutdown.
func (s *Server) Serve(ctx context.Context, sockPath string) error {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		return err
	}
	// Refuse to serve over a live socket; clean up a stale one.
	if _, err := os.Stat(sockPath); err == nil {
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
	_ = enc.Encode(resp)
}

func (s *Server) audit(uid, pid uint32, op, project, env, decision, detail string) {
	if s.Audit == nil {
		return
	}
	if err := s.Audit.Log(AuditEntry{UID: uid, PID: pid, Op: op, Project: project, Env: env, Decision: decision, Detail: detail}); err != nil {
		s.Logger.Error("audit log write failed", "error", err)
	}
}

func (s *Server) dispatch(uid, pid uint32, req *Request) *Response {
	switch req.Op {
	case OpPing:
		return &Response{OK: true}

	case OpListEnvs:
		entries, ok := s.Keys[req.Project]
		if !ok {
			s.audit(uid, pid, req.Op, req.Project, "", "deny", "unknown project")
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
		s.audit(uid, pid, req.Op, req.Project, "", "allow", "metadata")
		return &Response{OK: true, Envs: envs}

	case OpGetSecrets:
		return s.handleGetSecrets(uid, pid, req)

	case OpApprove:
		return s.handleApprove(uid, pid, req)

	default:
		return &Response{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

func (s *Server) handleGetSecrets(uid, pid uint32, req *Request) *Response {
	if req.Project == "" || req.Path == "" {
		return &Response{OK: false, Error: "project and path are required"}
	}
	if !filepath.IsAbs(req.Path) {
		return &Response{OK: false, Error: "path must be absolute"}
	}

	action := s.Policy.Decide(req.Project, req.Env, uid)
	if action == policy.Deny {
		s.audit(uid, pid, req.Op, req.Project, req.Env, "deny", "policy")
		return &Response{OK: false, Error: fmt.Sprintf("denied by policy: %s env %q", req.Project, req.Env)}
	}
	if action == policy.Ask {
		id, err := s.newPending()
		if err != nil {
			return &Response{OK: false, Error: err.Error()}
		}
		s.audit(uid, pid, req.Op, req.Project, req.Env, "ask", id)
		approved := s.waitPending(id)
		if !approved {
			s.audit(uid, pid, req.Op, req.Project, req.Env, "deny", "approval "+id+" timed out or rejected")
			return &Response{OK: false, Error: fmt.Sprintf("approval %s was not granted", id)}
		}
		s.audit(uid, pid, req.Op, req.Project, req.Env, "allow", "approved "+id)
	} else {
		s.audit(uid, pid, req.Op, req.Project, req.Env, "allow", "policy")
	}

	key, err := s.keyFor(req.Project, req.Env)
	if err != nil {
		return &Response{OK: false, Error: err.Error()}
	}

	data, err := os.ReadFile(req.Path) //nolint:gosec // broker runs as the user; path comes from the user's session
	if err != nil {
		return &Response{OK: false, Error: fmt.Sprintf("failed to read secrets file: %v", err)}
	}

	var plain bytes.Buffer
	format := esec.FileFormat(req.Format)
	if _, err := esec.Decrypt(bytes.NewReader(data), &plain, "", format, ".", key); err != nil {
		return &Response{OK: false, Error: fmt.Sprintf("decryption failed: %v", err)}
	}

	var secrets map[string]string
	switch format {
	case esec.FileFormatEjson:
		secrets, err = esec.EjsonToEnv(plain.Bytes())
	case esec.FileFormatEnv:
		secrets, err = esec.DotEnvToEnv(plain.Bytes())
	default:
		err = fmt.Errorf("format %s is not supported for secret injection", format)
	}
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
	s.audit(uid, pid, req.Op, "", "", "approve", req.ID)
	ch <- true
	return &Response{OK: true}
}
