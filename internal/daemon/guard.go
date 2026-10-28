package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/safetext"
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
	ks *keystore.Store
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

func newGuarder(ks *keystore.Store, session func() (bool, time.Time)) *guarder {
	return &guarder{
		ks: ks, session: session, timeout: openTimeout,
		presence: func() guard.Presence { return guard.DefaultPresence },
		turn:     make(chan struct{}, 1),
		waiting:  map[string]bool{},
		cache:    map[string]cachedKey{},
	}
}

// Has implements broker.Guarder. A keyring that cannot be read is an
// error, not "no guarded key": the broker must not fall back to a clear
// key it loaded earlier.
func (g *guarder) Has(project, env, pub string) (bool, error) {
	entries, err := g.ks.Read(project)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the keyring of %s: %w", project, err)
	}
	_, _, ok := guard.Lookup(entries, env, pub)
	return ok, nil
}

// Key implements broker.Guarder.
func (g *guarder) Key(req broker.GuardRequest) (string, string, error) {
	value, pub, keyEnv, err := g.find(req)
	if err != nil {
		return "", "", err
	}
	// A forwarded read is always one the person sees and touches.
	if !req.Forwarded {
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
	if !req.Forwarded {
		if priv, ok := g.cached(pub, req.Project, req.Env); ok {
			return priv, "session (open)", nil
		}
	}
	gd, err := guard.Load(g.ks)
	if err != nil {
		return "", "", err
	}
	id, err := g.open(gd, describeRead(req, keyEnv, pub), release)
	if err != nil {
		return "", "", err
	}
	k, err := guard.Unwrap(id, value, pub, keystore.PublicHex)
	if err != nil {
		return "", "", err
	}
	if err := belongs(k, req); err != nil {
		return "", "", err
	}
	if k.Level == "session" && !req.Forwarded {
		g.keep(pub, req.Project, k)
	}
	if k.Level == "" {
		k.Level = "touch"
	}
	return k.Private, k.Level, nil
}

// find looks the guarded key up: its keyring value, public key, and the
// environment it belongs to. The key decides what is read, not the
// environment asked for: a prod file renamed .env.dev is still prod.
func (g *guarder) find(req broker.GuardRequest) (value, pub, keyEnv string, err error) {
	if req.Env != "" && !envNameRe.MatchString(req.Env) {
		return "", "", "", fmt.Errorf("invalid environment name %q", safetext.CleanN(req.Env, 40))
	}
	entries, err := g.ks.Read(req.Project)
	if err != nil {
		return "", "", "", err
	}
	value, pub, ok := guard.Lookup(entries, req.Env, req.PublicKey)
	if !ok {
		return "", "", "", fmt.Errorf("no guarded key for %s %s", req.Project, req.Env)
	}
	keyEnv = guard.EnvOf(entries, pub)
	if keyEnv != "" && req.Env != "" && keyEnv != req.Env {
		return "", "", "", fmt.Errorf("the file is encrypted to %s's key, not %s's", keyEnv, req.Env)
	}
	return value, pub, keyEnv, nil
}

// belongs checks the opened key's own record against the request.
func belongs(k *guard.Key, req broker.GuardRequest) error {
	if k.Project != "" && k.Project != req.Project {
		return errors.New("the guarded key belongs to another project")
	}
	if k.Env != "" && req.Env != "" && k.Env != req.Env {
		return fmt.Errorf("the guarded key belongs to %s, not %s", k.Env, req.Env)
	}
	return nil
}

// keep holds a session key open until the broker's session ends.
func (g *guarder) keep(pub, project string, k *guard.Key) {
	until := time.Now().Add(sessionTTL)
	if unlocked, expires := g.session(); unlocked && !expires.IsZero() {
		until = expires
	}
	g.mu.Lock()
	g.cache[pub] = cachedKey{priv: k.Private, project: project, env: k.Env, until: until}
	g.mu.Unlock()
}

// open asks and opens the guard, giving up after the timeout. A plugin
// that never returns is left behind, and the next read may go ahead.
func (g *guarder) open(gd *guard.Guard, text string, release func()) (*age.X25519Identity, error) {
	type result struct {
		id  *age.X25519Identity
		err error
	}
	done := make(chan result, 1)
	presence := g.presence()
	go func() {
		id, err := presence.Open(gd, "esec: allow a guarded read?", text)
		done <- result{id, err}
	}()
	select {
	case r := <-done:
		return r.id, r.err
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
	if req.Session != "" {
		fmt.Fprintf(&b, "\nAgent session: %s", field(req.Session))
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
