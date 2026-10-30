package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
)

// sessionTTL bounds how long a session-guarded key stays open when the
// broker has no session of its own.
const sessionTTL = time.Hour

// openTimeout bounds one dialog and touch: the dialog gives up after two
// minutes, the touch after a little more. A plugin that hangs past it no
// longer blocks every other guarded read.
const openTimeout = 3 * time.Minute

// maxWaiting caps the guarded reads waiting for their turn at the dialog,
// so a program cannot queue dialogs to wear the person down.
const maxWaiting = 3

var envNameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// guarder opens guarded keys for the broker: a dialog that says what is
// read and which programs asked, then the touch. A session-guarded key
// stays open until the broker locks; a touch-guarded one never does.
type guarder struct {
	// securityKeys returns this person's security keys, for a seal without
	// a record (a forwarded one).
	securityKeys func() ([]string, error)
	// session reports the broker's session, to end cached keys with it.
	session func() (bool, time.Time)
	// presence is read at each use, so tests can swap the default.
	presence func() guard.Presence
	// timeout bounds one open; tests shorten it.
	timeout time.Duration

	// turn keeps to one dialog and one touch at a time.
	turn chan struct{}

	mu      sync.Mutex
	waiting map[string]bool
	cache   map[string]cachedKey
}

type cachedKey struct {
	priv    string
	project string
	env     string
	until   time.Time
}

func newGuarder(securityKeys func() ([]string, error), session func() (bool, time.Time)) *guarder {
	return &guarder{
		securityKeys: securityKeys, session: session, timeout: openTimeout,
		presence: func() guard.Presence { return guard.DefaultPresence },
		turn:     make(chan struct{}, 1),
		waiting:  map[string]bool{},
		cache:    map[string]cachedKey{},
	}
}

// Has implements broker.Guarder: a read is guarded when the project's
// esec.toml or seal record says so, or when it comes forwarded with its
// seal. The claim only routes the read: a guarded seal opens only with a
// security key whatever the claim says. A project file that cannot be read
// is an error, not "not guarded".
func (g *guarder) Has(req broker.GuardRequest) (bool, error) {
	if len(req.Seal) > 0 {
		return true, nil
	}
	root, pf, err := projectOf(req)
	if err != nil || pf == nil {
		return false, err
	}
	if seal.Guarded(pf.Env[req.Env].Guard) {
		return true, nil
	}
	recs, err := seal.LoadRecords(root)
	if err != nil {
		return false, err
	}
	rec := recs[req.Env]
	return rec != nil && seal.Guarded(rec.Guard), nil
}

// projectOf finds the project of a local read's file: its root and
// esec.toml, nil when the file belongs to none. It must be the project
// asked for.
func projectOf(req broker.GuardRequest) (string, *projectfile.File, error) {
	if req.Path == "" || req.Forwarded {
		return "", nil, nil
	}
	pf, path, err := projectfile.Find(filepath.Dir(req.Path))
	if errors.Is(err, projectfile.ErrNotFound) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if pf.Project != req.Project {
		return "", nil, fmt.Errorf("%s belongs to %s, not %s", req.Path, pf.Project, req.Project)
	}
	return filepath.Dir(path), pf, nil
}

// Key implements broker.Guarder.
func (g *guarder) Key(req broker.GuardRequest) (string, string, error) {
	if !envNameRe.MatchString(req.Env) {
		return "", "", fmt.Errorf("invalid environment name %q", safetext.CleanN(req.Env, 40))
	}
	data, recipients, err := g.find(req)
	if err != nil {
		return "", "", err
	}
	pub := strings.ToLower(req.PublicKey)
	// A forwarded read is always one the person sees and touches.
	if !req.Forwarded && req.Protection != "touch" {
		if priv, ok := g.cached(pub, req.Project, req.Env); ok {
			return priv, "session (open)", nil
		}
	}
	ask := strings.Join([]string{req.Project, req.Env, pub, req.Path, req.Caller, req.Host, fmt.Sprint(req.Forwarded)}, "\x00")
	if err := g.queue(ask); err != nil {
		return "", "", err
	}
	defer g.unqueue(ask)
	select {
	case g.turn <- struct{}{}:
	case <-time.After(g.timeout):
		return "", "", errors.New("another guarded read is still waiting for you")
	}
	released := false
	release := func() {
		if !released {
			released = true
			<-g.turn
		}
	}
	defer release()
	if !req.Forwarded && req.Protection != "touch" {
		if priv, ok := g.cached(pub, req.Project, req.Env); ok {
			return priv, "session (open)", nil
		}
	}
	p, err := g.open(data, req, recipients, describeRead(req, req.Env, pub), release)
	if err != nil {
		return "", "", err
	}
	if p.Guard == "session" && req.Protection != "touch" && !req.Forwarded && pub != "" {
		g.keep(pub, req.Project, p)
	}
	if req.Protection == "touch" {
		return p.Private, "touch", nil
	}
	return p.Private, p.Guard, nil
}

// find returns the read's seal and the security keys it was made for: the
// seal a forwarded read carries, or the one in the local project.
func (g *guarder) find(req broker.GuardRequest) ([]byte, []string, error) {
	if len(req.Seal) > 0 {
		keys, err := g.securityKeys()
		return req.Seal, keys, err
	}
	root, pf, err := projectOf(req)
	if err != nil {
		return nil, nil, err
	}
	if pf == nil {
		return nil, nil, fmt.Errorf("no project file (esec.toml) above %s", req.Path)
	}
	data, err := coreseal.Read(root, req.Env)
	if err != nil {
		return nil, nil, err
	}
	recs, err := seal.LoadRecords(root)
	if err != nil {
		return nil, nil, err
	}
	if rec := recs[req.Env]; rec != nil {
		return data, rec.Recipients(), nil
	}
	keys, err := g.securityKeys()
	return data, keys, err
}

// keep holds a session key open until the broker's session ends.
func (g *guarder) keep(pub, project string, p *coreseal.Payload) {
	until := time.Now().Add(sessionTTL)
	if unlocked, expires := g.session(); unlocked && !expires.IsZero() {
		until = expires
	}
	g.mu.Lock()
	g.cache[pub] = cachedKey{priv: p.Private, project: project, env: p.Env, until: until}
	g.mu.Unlock()
}

// open asks and opens the seal, giving up after the timeout. A plugin that
// never returns is left behind, and the next read may go ahead.
func (g *guarder) open(data []byte, req broker.GuardRequest, recipients []string, text string, release func()) (*coreseal.Payload, error) {
	type result struct {
		p   *coreseal.Payload
		err error
	}
	done := make(chan result, 1)
	presence := g.presence()
	go func() {
		p, err := presence.OpenSeal(data, req.Project, req.Env, req.PublicKey, recipients, "esec: allow a guarded read?", text)
		done <- result{p, err}
	}()
	select {
	case r := <-done:
		return r.p, r.err
	case <-time.After(g.timeout):
		release()
		return nil, errors.New("the guarded read timed out waiting for the dialog or the security key")
	}
}

// queue records a read waiting for its turn, refusing a duplicate of one
// already waiting and more than maxWaiting.
func (g *guarder) queue(ask string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waiting[ask] {
		return errors.New("the same guarded read is already waiting for you")
	}
	if len(g.waiting) >= maxWaiting {
		return errors.New("too many guarded reads are waiting for you; try again later")
	}
	g.waiting[ask] = true
	return nil
}

func (g *guarder) unqueue(ask string) {
	g.mu.Lock()
	delete(g.waiting, ask)
	g.mu.Unlock()
}

func (g *guarder) cached(pub, project, env string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.cache[pub]
	if !ok || c.project != project || (env != "" && c.env != "" && c.env != env) || !time.Now().Before(c.until) {
		delete(g.cache, pub)
		return "", false
	}
	return c.priv, true
}

// clear forgets every open session key; locking the broker calls it.
func (g *guarder) clear() {
	g.mu.Lock()
	g.cache = map[string]cachedKey{}
	g.mu.Unlock()
}

// field makes a value from a request safe for one dialog line: no control
// characters or newlines, short, quoted.
func field(s string) string { return fmt.Sprintf("%q", safetext.CleanN(s, 120)) }

// describeRead is the dialog text. Who asked and from where come first, so
// nothing in the request can push them out of sight; every value from the
// request is one cleaned, quoted line.
func describeRead(req broker.GuardRequest, keyEnv, pub string) string {
	var b strings.Builder
	who := req.Caller
	if who == "" {
		who = caller.Describe(nil)
	}
	fmt.Fprintf(&b, "Asked by: %s", safetext.CleanN(who, 160))
	if req.Forwarded {
		b.WriteString("\nFROM ANOTHER MACHINE (esec vault forward)")
		if req.Host != "" {
			fmt.Fprintf(&b, ", which says it is %s", field(req.Host))
		}
	}
	if req.Command != "" {
		fmt.Fprintf(&b, "\nCommand: %s", field(req.Command))
	}
	if req.Session != "" {
		fmt.Fprintf(&b, "\nSession (as the program names itself): %s", field(req.Session))
	}
	what := keyEnv
	if what == "" {
		what = "a retired key " + pub[:min(12, len(pub))] + "… (asked as " + safetext.CleanN(req.Env, 40) + ")"
	}
	fmt.Fprintf(&b, "\n\nRead: %s %s", safetext.CleanN(req.Project, 120), what)
	if req.Path != "" {
		fmt.Fprintf(&b, "\nFile: %s", field(req.Path))
	}
	b.WriteString("\n\nAllow, then touch your security key, only if you started this.")
	return b.String()
}

// sessionOpen reads availability metadata only; inspection never returns a key.
func (g *guarder) sessionOpen(pub, project, env string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.cache[pub]
	return ok && c.project == project && c.env == env && time.Now().Before(c.until)
}
