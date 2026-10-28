package daemon

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/guard"
	"github.com/mscno/esec-vault/internal/keystore"
)

// sessionTTL bounds how long a session-guarded key stays open when the
// broker has no session of its own.
const sessionTTL = time.Hour

// guarder opens guarded keys for the broker: a dialog that says what is
// read and which programs asked, then the touch. A session-guarded key
// stays open until the broker locks; a touch-guarded one never does.
type guarder struct {
	ks *keystore.Store
	// session reports the broker's session, to end cached keys with it.
	session func() (bool, time.Time)
	// presence is read at each use, so tests can swap the default.
	presence func() guard.Presence

	// mu keeps to one dialog and one touch at a time.
	mu      sync.Mutex
	cacheMu sync.Mutex
	cache   map[string]cachedKey
}

type cachedKey struct {
	priv    string
	project string
	until   time.Time
}

func newGuarder(ks *keystore.Store, session func() (bool, time.Time)) *guarder {
	return &guarder{ks: ks, session: session, presence: func() guard.Presence { return guard.DefaultPresence }, cache: map[string]cachedKey{}}
}

// Has implements broker.Guarder.
func (g *guarder) Has(project, env, pub string) bool {
	entries, err := g.ks.Read(project)
	if err != nil {
		return false
	}
	_, _, ok := guard.Lookup(entries, env, pub)
	return ok
}

// Key implements broker.Guarder.
func (g *guarder) Key(req broker.GuardRequest) (string, string, error) {
	entries, err := g.ks.Read(req.Project)
	if err != nil {
		return "", "", err
	}
	value, pub, ok := guard.Lookup(entries, req.Env, req.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("no guarded key for %s %s", req.Project, req.Env)
	}
	if priv, ok := g.cached(pub, req.Project); ok {
		return priv, "session (open)", nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if priv, ok := g.cached(pub, req.Project); ok {
		return priv, "session (open)", nil
	}
	gd, err := guard.Load(g.ks)
	if err != nil {
		return "", "", err
	}
	id, err := g.presence().Open(gd, "esec: allow a guarded read?", describeRead(req))
	if err != nil {
		return "", "", err
	}
	k, err := guard.Unwrap(id, value, pub, keystore.PublicHex)
	if err != nil {
		return "", "", err
	}
	if k.Project != "" && k.Project != req.Project {
		return "", "", errors.New("the guarded key belongs to another project")
	}
	if k.Level == "session" {
		until := time.Now().Add(sessionTTL)
		if unlocked, expires := g.session(); unlocked && !expires.IsZero() {
			until = expires
		}
		g.cacheMu.Lock()
		g.cache[pub] = cachedKey{priv: k.Private, project: req.Project, until: until}
		g.cacheMu.Unlock()
	}
	if k.Level == "" {
		k.Level = "touch"
	}
	return k.Private, k.Level, nil
}

func (g *guarder) cached(pub, project string) (string, bool) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	c, ok := g.cache[pub]
	if !ok || c.project != project || !time.Now().Before(c.until) {
		delete(g.cache, pub)
		return "", false
	}
	return c.priv, true
}

// clear forgets every open session key; locking the broker calls it.
func (g *guarder) clear() {
	g.cacheMu.Lock()
	g.cache = map[string]cachedKey{}
	g.cacheMu.Unlock()
}

// describeRead is the dialog text: what is read, where, and who asked.
func describeRead(req broker.GuardRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Read %s %s", req.Project, req.Env)
	if req.Path != "" {
		fmt.Fprintf(&b, "\nFile: %s", req.Path)
	}
	if req.Host != "" {
		fmt.Fprintf(&b, "\nFrom another machine: %s", req.Host)
	}
	who := req.Caller
	if who == "" {
		who = caller.Describe(nil)
	}
	fmt.Fprintf(&b, "\nAsked by: %s", who)
	if req.Session != "" {
		fmt.Fprintf(&b, "\nAgent session: %s", req.Session)
	}
	b.WriteString("\n\nAllow, then touch your security key, only if you started this.")
	return b.String()
}
