// Package daemon hosts the long-lived broker and backup scheduler.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/remote"
)

// Request is the versioned local control protocol. It carries no private keys
// or recovery phrases and permits no arbitrary executable or path selection.
type Request struct {
	Version int           `json:"version"`
	Op      string        `json:"op"`
	TTL     time.Duration `json:"ttl,omitempty"`
	Remote  string        `json:"remote,omitempty"`
	Prune   bool          `json:"prune,omitempty"`
	Async   bool          `json:"async,omitempty"`
	ID      string        `json:"id,omitempty"`
}

// Response contains control metadata only. Secret values use agent.sock.
type Response struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Unlocked bool      `json:"unlocked"`
	Expires  time.Time `json:"expires,omitempty"`
	Job      *Job      `json:"job,omitempty"`
}

// Job records the result of a queued backup; durable dirty state survives restart.
type Job struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Error      string `json:"error,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}
type queued struct {
	request Request
	id      string
	done    chan Job
}

// Server owns one broker session and serializes uploads. Keyring access by the
// backup worker is transient and does not extend the broker session TTL.
type Server struct {
	Keyring    keyring.Keyring
	Logger     *slog.Logger
	Broker     *broker.Server
	UID        uint32
	Interval   time.Duration
	mu         sync.Mutex
	jobs       map[string]Job
	sequence   uint64
	queue      chan queued
	wake       chan struct{}
	cancel     context.CancelFunc
	boot       string
	watchReady chan struct{}
}

// New constructs a locked daemon. Tests inject an in-memory keyring.
func New(kr keyring.Keyring, logger *slog.Logger) (*Server, error) {
	if err := paths.EnsureHome(); err != nil {
		return nil, err
	}
	p, err := policy.Load(paths.PolicyPath())
	if err != nil {
		return nil, err
	}
	audit, err := broker.NewAuditLogger(paths.AuditPath())
	if err != nil {
		return nil, err
	}
	b := broker.NewServer(nil, p, audit, logger)
	b.ControlOnlyApproval = true
	b.Lock()
	cfg, err := remote.Load()
	if err != nil {
		return nil, err
	}
	interval := cfg.Policy.IntervalDuration()
	if interval <= 0 {
		return nil, fmt.Errorf("daemon requires a positive policy.interval")
	}
	return &Server{Keyring: kr, Logger: logger, Broker: b, UID: uint32(os.Getuid()), Interval: interval, jobs: map[string]Job{}, queue: make(chan queued, 16), wake: make(chan struct{}, 1), boot: rand.Text(), watchReady: make(chan struct{})}, nil //nolint:gosec // supported platforms have a nonnegative uid
}

// Serve runs both endpoints and the scheduler until cancellation. The OS user
// service owns process lifetime; a broker lock/expiry does not stop this loop.
func (s *Server) Serve(parent context.Context) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("daemon requires macOS or Linux")
	}
	if err := os.MkdirAll(paths.RuntimeDir(), 0700); err != nil {
		return err
	}
	ln, err := listen(paths.ControlSocket())
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(paths.ControlSocket())
	defer s.Broker.Lock()
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	defer cancel()
	var workers sync.WaitGroup
	workers.Go(func() { s.watch(ctx) })
	<-s.watchReady
	workers.Go(func() { s.work(ctx) })
	brokerDone := make(chan error, 1)
	workers.Go(func() { brokerDone <- s.Broker.Serve(ctx, paths.SocketPath()); cancel() })
	workers.Go(func() { <-ctx.Done(); ln.Close() })
	var clients sync.WaitGroup
	defer func() { cancel(); ln.Close(); s.Broker.Lock(); clients.Wait(); workers.Wait() }()
	s.Logger.Info("daemon ready", "control", paths.ControlSocket(), "broker", paths.SocketPath(), "locked", true)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				select {
				case err := <-brokerDone:
					return err
				default:
					return nil
				}
			}
			return err
		}
		clients.Go(func() { s.handle(ctx, conn) })
	}
}

func listen(p string) (net.Listener, error) {
	if info, err := os.Lstat(p); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing non-socket at %s", p)
		}
		if c, err := net.DialTimeout("unix", p, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("daemon already running")
		}
		if err := os.Remove(p); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Minute))
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	uid, pid, err := broker.PeerCredentials(u)
	if err != nil || uid != s.UID {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&req); err != nil {
		return
	}
	resp := s.dispatch(ctx, uid, pid, req)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		s.Logger.Debug("control client disconnected", "error", err)
	}
}

func (s *Server) dispatch(ctx context.Context, uid, pid uint32, r Request) Response {
	if uid != s.UID {
		return failure(fmt.Errorf("owner access required"))
	}
	if r.Version != 1 {
		return failure(fmt.Errorf("unsupported control protocol"))
	}
	switch r.Op {
	case "ping", "status":
		unlocked, expires := s.Broker.Session()
		return Response{OK: true, PID: os.Getpid(), Unlocked: unlocked, Expires: expires}
	case "lock":
		s.Broker.Lock()
		return Response{OK: true}
	case "shutdown":
		if s.cancel != nil {
			s.cancel()
		}
		return Response{OK: true}
	case "unlock":
		return s.unlock(r.TTL)
	case "reload":
		p, err := policy.Load(paths.PolicyPath())
		if err != nil {
			return failure(err)
		}
		s.Broker.ReloadPolicy(p)
		return Response{OK: true}
	case "approve":
		got := s.Broker.ApproveOwner(uid, pid, r.ID)
		return Response{OK: got.OK, Error: got.Error}
	case "changed":
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return Response{OK: true}
	case "backup", "snapshot":
		return s.enqueue(ctx, r)
	case "job":
		s.mu.Lock()
		j, ok := s.jobs[r.ID]
		s.mu.Unlock()
		if !ok {
			return failure(fmt.Errorf("unknown job"))
		}
		return Response{OK: true, Job: &j}
	default:
		return failure(fmt.Errorf("unknown control operation"))
	}
}

func (s *Server) unlock(ttl time.Duration) Response {
	if ttl <= 0 || ttl > 24*time.Hour {
		return failure(fmt.Errorf("TTL must be between 0 and 24h"))
	}
	id, err := identity.Load(s.Keyring)
	if err != nil {
		return failure(err)
	}
	if _, _, err := identity.BackupMaterial(id); err != nil {
		return failure(err)
	}
	ks := keystore.New()
	projects, err := ks.List()
	if err != nil {
		return failure(err)
	}
	keys := map[string]map[string]string{}
	for _, p := range projects {
		e, err := ks.Read(p)
		if err != nil {
			return failure(err)
		}
		keys[p] = e
	}
	s.Broker.Unlock(keys, ttl)
	_, expires := s.Broker.Session()
	return Response{OK: true, Unlocked: true, Expires: expires}
}

func (s *Server) enqueue(ctx context.Context, r Request) Response {
	s.mu.Lock()
	s.sequence++
	id := s.boot + "-" + strconv.FormatUint(s.sequence, 10)
	j := Job{ID: id, State: "queued"}
	s.jobs[id] = j
	if s.sequence > 64 {
		delete(s.jobs, s.boot+"-"+strconv.FormatUint(s.sequence-64, 10))
	}
	s.mu.Unlock()
	q := queued{request: r, id: id, done: make(chan Job, 1)}
	select {
	case s.queue <- q:
	case <-ctx.Done():
		return failure(ctx.Err())
	default:
		s.complete(id, fmt.Errorf("backup queue full"), 0)
		return failure(fmt.Errorf("backup queue full"))
	}
	if r.Async {
		return Response{OK: true, Job: &j}
	}
	select {
	case j := <-q.done:
		return Response{OK: j.State == "complete", Error: j.Error, Job: &j}
	case <-ctx.Done():
		return failure(ctx.Err())
	}
}

func (s *Server) work(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.automatic(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.automatic(ctx)
		case <-ticker.C:
			s.automatic(ctx)
		case q := <-s.queue:
			if ctx.Err() != nil {
				return
			}
			jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			id, err := identity.Load(s.Keyring)
			var generation uint64
			if err == nil && q.request.Op == "snapshot" {
				var snap *remote.Snapshot
				snap, err = remote.BuildSnapshot(id, keystore.New())
				if snap != nil {
					generation = snap.Generation
				}
			} else if err == nil {
				var result *remote.PushResult
				result, err = remote.PushNow(jobCtx, id, keystore.New(), q.request.Remote, q.request.Prune)
				if result != nil {
					generation = result.Generation
				}
			}
			cancel()
			q.done <- s.complete(q.id, err, generation)
		}
	}
}

func (s *Server) automatic(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	id, err := identity.Load(s.Keyring)
	if err == nil {
		_, err = remote.BuildSnapshot(id, keystore.New())
		if err == nil {
			_, err = remote.MaybePush(ctx, id, keystore.New(), "")
		}
	}
	if err != nil && parent.Err() == nil {
		s.Logger.Warn("backup pending; will retry", "error", err)
	}
}

func (s *Server) complete(id string, err error, generation uint64) Job {
	j := Job{ID: id, State: "complete", Generation: generation}
	if err != nil {
		j.State = "failed"
		j.Error = err.Error()
	}
	s.mu.Lock()
	s.jobs[id] = j
	s.mu.Unlock()
	return j
}
func failure(err error) Response { return Response{Error: err.Error()} }

// Call talks only to the control endpoint, with a bounded wait for completion.
func Call(ctx context.Context, req Request) (*Response, error) {
	req.Version = 1
	dial := net.Dialer{Timeout: time.Second}
	conn, err := dial.DialContext(ctx, "unix", paths.ControlSocket())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(6 * time.Minute)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, fmt.Errorf("daemon: %s", resp.Error)
	}
	return &resp, nil
}

// Notify is a best-effort wake-up after durable state was saved by the CLI.
func Notify() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Call(ctx, Request{Op: "changed"})
	return err == nil
}

// ManagedSocket reports whether the broker socket resides in the managed runtime directory.
func ManagedSocket() bool {
	return filepath.Clean(paths.SocketPath()) == filepath.Join(paths.RuntimeDir(), "agent.sock")
}
