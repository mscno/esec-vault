package team

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mscno/esec/pkg/crypto"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
)

// KindGrant is the envelope kind of grants.
const KindGrant = "project-grant"

// ErrStale marks a grant that no longer applies: an environment moved to
// another key since, or it was sealed to a user key the recipient has since
// replaced. An admin's device sends a new one.
var ErrStale = errors.New("the grant is out of date")

// Grant carries environment keys of a project to one member or machine.
// The keys are sealed to the recipient's key; the rest is signed by the
// admin who made it.
type Grant struct {
	Project string `json:"project"`
	// ProjectSeq is the length of the project chain the admin verified.
	ProjectSeq uint64 `json:"project_seq"`
	From       string `json:"from"`
	FromKey    uint64 `json:"from_ukey_version"`
	// To is a user id or a machine id; ToKey is the recipient's user key
	// version (users only) and ToEncPub the key the box is sealed to.
	To       string    `json:"to"`
	ToKey    uint64    `json:"to_ukey_version,omitempty"`
	ToEncPub string    `json:"to_enc_pub"`
	Envs     []Env     `json:"envs"`
	CTime    time.Time `json:"ctime"`
	Box      []byte    `json:"box"`
}

// payload is the sealed content of a grant. It names the project and the
// recipient again, so a box cannot be moved into another grant.
type payload struct {
	Project string            `json:"project"`
	To      string            `json:"to"`
	Keys    map[string]string `json:"keys"`
}

// Recipient is who a grant is sealed to.
type Recipient struct {
	ID string
	// Version is the recipient's user key version; 0 for machines.
	Version uint64
	EncPub  [32]byte
}

// NewGrant seals keys (environment name to hex private key) to to, signed
// by from at user key version fromVersion. Every key must be the current key
// of its environment in st, and to must have access to it.
func NewGrant(st *State, from string, fromVersion uint64, sign ed25519.PrivateKey, to Recipient, keys map[string]string, now time.Time) (*envelope.Envelope, error) {
	if len(keys) == 0 {
		return nil, errors.New("a grant needs at least one environment")
	}
	g := Grant{Project: st.Project, ProjectSeq: st.Seq, From: from, FromKey: fromVersion, To: to.ID, ToKey: to.Version, ToEncPub: hex.EncodeToString(to.EncPub[:]), CTime: now.UTC().Truncate(time.Second)}
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e, ok := st.Envs[n]
		if !ok {
			return nil, fmt.Errorf("unknown environment %s", n)
		}
		pub, err := PublicHex(keys[n])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		if pub != e.PublicKey {
			return nil, fmt.Errorf("the local %s key is not the project's current %s key", n, n)
		}
		if !st.HasAccess(to.ID, n) {
			return nil, fmt.Errorf("%s has no access to %s", to.ID, n)
		}
		g.Envs = append(g.Envs, e.Env)
	}
	plain, err := json.Marshal(payload{Project: st.Project, To: to.ID, Keys: keys})
	if err != nil {
		return nil, err
	}
	if g.Box, err = crypto.SealAnonymous(plain, &to.EncPub); err != nil {
		return nil, err
	}
	return envelope.New(KindGrant, g, sign)
}

// PeekGrant decodes a grant without verifying it.
func PeekGrant(e *envelope.Envelope) (*Grant, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindGrant {
		return nil, errors.New("not a grant")
	}
	var g Grant
	if err := e.Decode(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

// CheckGrant verifies a grant against the verified project state st: signed
// by an active admin with the user key version it names, to an active
// member or machine with access to every environment, each at the key st
// names. It returns ErrStale (wrapped) for a grant made before an
// environment's key changed.
func CheckGrant(e *envelope.Envelope, st *State, chains Chains) (*Grant, error) {
	g, err := PeekGrant(e)
	if err != nil {
		return nil, err
	}
	if g.Project != st.Project {
		return nil, errors.New("the grant is for another project")
	}
	if g.CTime.IsZero() || len(g.Envs) == 0 || len(g.Box) == 0 {
		return nil, errors.New("incomplete grant")
	}
	admin, ok := st.Member(g.From)
	if !ok || !admin.Admin {
		return nil, fmt.Errorf("%w: %s is not an admin of %s", ErrStale, g.From, st.Project)
	}
	// A grant can carry only the keys the chain names, to members and
	// machines the chain lets read them, so any user key the admin ever had
	// may sign it.
	cs, err := chains(g.From)
	if err != nil {
		return nil, fmt.Errorf("user chain of %s: %w", g.From, err)
	}
	if cs.Root() != admin.Root {
		return nil, fmt.Errorf("the account of %s is not the one the project recorded", g.From)
	}
	ep, ok := cs.Epoch(g.FromKey)
	if !ok {
		return nil, fmt.Errorf("%s has no user key version %d", g.From, g.FromKey)
	}
	pub := ep.SignPub
	if err := e.Require(KindGrant, pub); err != nil {
		return nil, err
	}
	if _, err := chain.ParseKey32(g.ToEncPub); err != nil {
		return nil, errors.New("invalid recipient key")
	}
	seen := map[string]bool{}
	for i, env := range g.Envs {
		env.Name = st.CurrentEnv(env.Name)
		g.Envs[i].Name = env.Name
		cur, ok := st.Envs[env.Name]
		if !ok || seen[env.Name] {
			return nil, fmt.Errorf("the grant lists an unknown or repeated environment %q", env.Name)
		}
		seen[env.Name] = true
		if cur.PublicKey != env.PublicKey {
			return nil, fmt.Errorf("%w: %s has a new key since", ErrStale, env.Name)
		}
		if !st.HasAccess(g.To, env.Name) {
			return nil, fmt.Errorf("%w: %s no longer has access to %s", ErrStale, g.To, env.Name)
		}
	}
	return g, nil
}

// Open verifies a grant (see CheckGrant) and opens it with the recipient's
// key. It returns the keys by environment name, each checked against the
// public key the project chain names.
func Open(e *envelope.Envelope, st *State, chains Chains, me Recipient, priv [32]byte) (*Grant, map[string]string, error) {
	g, err := CheckGrant(e, st, chains)
	if err != nil {
		return nil, nil, err
	}
	if g.To != me.ID {
		return nil, nil, errors.New("the grant is for someone else")
	}
	if g.ToKey != me.Version || g.ToEncPub != hex.EncodeToString(me.EncPub[:]) {
		return nil, nil, fmt.Errorf("%w: it was sealed to an earlier key of yours", ErrStale)
	}
	plain, err := crypto.OpenAnonymous(g.Box, &me.EncPub, &priv)
	if err != nil {
		return nil, nil, errors.New("the grant does not open with this key")
	}
	var p payload
	if err := envelope.DecodeStrict(plain, &p); err != nil {
		return nil, nil, fmt.Errorf("invalid grant content: %w", err)
	}
	if p.Project != g.Project || p.To != g.To || len(p.Keys) != len(g.Envs) {
		return nil, nil, errors.New("the grant's content does not match it")
	}
	original, err := PeekGrant(e)
	if err != nil {
		return nil, nil, err
	}
	keys := map[string]string{}
	for _, env := range original.Envs {
		k, ok := p.Keys[env.Name]
		if !ok {
			return nil, nil, errors.New("the grant's content does not match it")
		}
		pub, err := PublicHex(k)
		if err != nil || pub != env.PublicKey {
			return nil, nil, fmt.Errorf("the %s key in the grant does not match the project's public key", env.Name)
		}
		keys[st.CurrentEnv(env.Name)] = k
	}
	return g, keys, nil
}
