package daemon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/notify"
	"github.com/mscno/esec-vault/internal/policy"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec/pkg/seal"
)

// ReadAsker is the trusted desktop consent provider; tests inject a fake UI.
var ReadAsker = notify.ReadConsent

type consentGrant struct {
	until time.Time
	epoch uint64
}
type readConsent struct {
	broker *broker.Server
	mu     sync.Mutex
	grants map[string]consentGrant
	turn   chan struct{}
}

func newReadConsent(b *broker.Server) *readConsent {
	return &readConsent{broker: b, grants: map[string]consentGrant{}, turn: make(chan struct{}, 1)}
}
func consentScope(uid uint32, t *esec.ReadTarget) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s", uid, t.Root, t.Project, t.Environment, t.PublicKey)
}
func (c *readConsent) has(uid uint32, t *esec.ReadTarget) bool {
	epoch := c.broker.Epoch()
	c.mu.Lock()
	defer c.mu.Unlock()
	scope := consentScope(uid, t)
	g := c.grants[scope]
	if g.epoch != epoch || !time.Now().Before(g.until) {
		return false
	}
	return true
}
func (c *readConsent) ask(uid, pid uint32, t *esec.ReadTarget) (string, error) {
	if t.Project == "" || t.Root == "" {
		return "", &esec.ReadError{Code: "project_missing", Detail: "broker consent requires the file's own esec.toml"}
	}
	if c.has(uid, t) {
		return "session", nil
	}
	select {
	case c.turn <- struct{}{}:
		defer func() { <-c.turn }()
	default:
		return "", &esec.ReadError{Code: "approval_busy", Detail: "another read is waiting for approval; retry after answering it"}
	}
	if c.has(uid, t) {
		return "session", nil
	}
	if strings.EqualFold(os.Getenv("ESEC_VAULT_DIALOGS"), "off") {
		return "", &esec.ReadError{Code: "consent_required", Detail: "desktop approval is disabled; enable daemon dialogs and retry this read"}
	}
	epoch := c.broker.Epoch()
	caller := describePID(pid)
	text := fmt.Sprintf("Asked by: %s\n\nProject: %q\nEnvironment: %q\nFile: %q\nPublic key: %s\nProtection: %s\n\nAllow once, or allow this project/environment/key for one hour. Session consent applies to programs running as your local account. Locking the vault revokes session consent. Approve only if you started this read.", safetext.CleanN(caller, 160), t.Project, t.Environment, t.Path, t.PublicKey, t.Guard)
	answer, err := ReadAsker("esec: allow this read?", text, 2*time.Minute)
	if errors.Is(err, notify.ErrNoDialogs) {
		return "", &esec.ReadError{Code: "consent_required", Detail: "no desktop approval is available; retry from your desktop session"}
	}
	if err != nil {
		return "", err
	}
	if epoch != c.broker.Epoch() {
		return "", &esec.ReadError{Code: "access_revoked", Detail: "the vault was locked while approval was pending"}
	}
	if answer != "once" && answer != "session" {
		return "", &esec.ReadError{Code: "consent_denied", Detail: "the read was cancelled or approval timed out"}
	}
	if answer == "session" {
		c.mu.Lock()
		c.grants[consentScope(uid, t)] = consentGrant{time.Now().Add(time.Hour), epoch}
		c.mu.Unlock()
	}
	return answer, nil
}

func (s *Server) openRead(t *esec.ReadTarget) (string, error) {
	entries, err := keystore.New().Read(t.Project)
	if err == nil {
		// Public-key lookup must not depend on a possibly stale environment label.
		key := entries[keystore.PubEntry(t.PublicKey)]
		if key == "" {
			key, _, _ = esec.ResolveKey(entries, esec.KeySuffixes(t.Environment), nil)
		}
		if key != "" {
			got, err := seal.PublicHex(key)
			if err != nil || !strings.EqualFold(got, t.PublicKey) {
				return "", &esec.ReadError{Code: "key_mismatch", Detail: "cached key does not match the resolved file"}
			}
			return key, nil
		}
	}
	id, err := identity.Load(s.Keyring)
	if err != nil {
		return "", &esec.ReadError{Code: "identity_unavailable", Detail: err.Error()}
	}
	reader, err := seal.X25519Identity(hex.EncodeToString(id.Private[:]))
	if err != nil {
		return "", err
	}
	sealed, err := seal.Read(t.Root, t.KeyEnvironment)
	if err != nil {
		return "", &esec.ReadError{Code: "seal_missing", Detail: err.Error()}
	}
	payload, err := seal.Open(sealed, t.Project, t.KeyEnvironment, t.PublicKey, reader)
	if err != nil {
		return "", &esec.ReadError{Code: "recipient_missing", Detail: err.Error()}
	}
	if payload.Guard != "" && payload.Guard != "none" {
		return "", &esec.ReadError{Code: "protection_mismatch", Detail: "the seal requires guarded access; refresh the project metadata"}
	}
	// A one-read approval never creates a persistent working key or global unlock.
	return payload.Private, nil
}

func (s *Server) inspectRead(c *readConsent, uid uint32, t *esec.ReadTarget) *esec.ReadInspection {
	i := esec.InspectLocalRead(t, esec.ReadOptions{})
	i.Route = "daemon"
	unlocked, _ := s.Broker.Session()
	i.Broker = "locked"
	if unlocked {
		i.Broker = "unlocked"
	}
	inspectionReader(t, i)
	s.BrokerPolicyInspection(uid, t, i)
	if i.Route == "daemon" {
		i.Consent = "required"
		action, configured := s.Broker.ReadPolicy(uid, t.Project, t.Environment)
		if t.Guard == "none" && action == policy.Allow && configured && unlocked {
			i.Consent = "policy_allowed"
		}
		if c.has(uid, t) {
			i.Consent = "session_granted"
		}
		if t.Guard != "none" {
			i.Hardware = "not_verified"
			seen, err := LoadSeenKeys()
			if err == nil && !seen.Checked.IsZero() && time.Since(seen.Checked) < 2*time.Minute {
				if len(seen.PluggedIn) > 0 {
					i.Hardware = "recently_seen_unverified"
				} else {
					i.Hardware = "no_yubikey_recently_seen"
				}
			}
		}
		if t.Guard == "session" && s.guard != nil && s.guard.sessionOpen(t.PublicKey, t.Project, t.KeyEnvironment) {
			i.Consent = "session_open"
			i.Hardware = "session_open"
		}
		if t.Guard != "none" && i.Consent != "session_open" {
			i.Blockers = append(i.Blockers, esec.ReadError{Code: "hardware_approval_required", Detail: "the key requires hardware approval; availability has not been tested"})
		}
		if i.Consent == "required" {
			i.Blockers = append(i.Blockers, esec.ReadError{Code: "consent_required", Detail: "the read will request local approval"})
		}
	}
	return i
}

// BrokerPolicyInspection reports denial without consulting secret storage.
func (s *Server) BrokerPolicyInspection(uid uint32, t *esec.ReadTarget, i *esec.ReadInspection) {
	action, configured := s.Broker.ReadPolicy(uid, t.Project, t.Environment)
	if i.Route == "daemon" && action == policy.Deny && configured {
		i.Blockers = append(i.Blockers, esec.ReadError{Code: "policy_denied", Detail: "local broker policy explicitly denies this environment"})
	}
}

func describePID(pid uint32) string { return caller.Describe(caller.Chain(int(pid))) }

func commandOf(pid uint32) string { return caller.Args(int(pid)) }

func inspectionReader(t *esec.ReadTarget, i *esec.ReadInspection) {
	if state, err := account.LoadState(); err == nil {
		for _, reader := range t.Readers {
			if strings.Contains(reader, "("+state.User+")") {
				i.Reader = state.Login + " — listed in project metadata (identity not opened)"
				break
			}
		}
	}
}
