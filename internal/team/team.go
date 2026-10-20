// Package team implements shared projects: a project chain that records who
// may read which environment keys of a project, signed by the project's
// admins, and grants that carry environment keys to members and machines.
//
// A project chain is an append-only, hash-linked list of signed links, like
// a user's device chain. Each link is signed by the user key of the member
// who made it, at the key version the link names; the verifier checks that
// signature against that member's own verified user chain, whose first link
// the project chain recorded when the member was added. The server stores
// both chains but can forge neither: it can withhold links, never add a
// member, change someone's access, or swap an environment key.
//
// Environment keys never pass through the server in the clear. An admin's
// device seals them to the recipient's current user key (or a machine's
// key) in a grant, signed by the admin; the recipient checks that every key
// is the one the project chain names for that environment before using it.
package team

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
)

// KindLink is the envelope kind of project chain links.
const KindLink = "project-link"

// Link types.
const (
	TypeInit          = "init"
	TypeMemberAdd     = "member_add"
	TypeMemberUpdate  = "member_update"
	TypeMemberRemove  = "member_remove"
	TypeEnvSet        = "env_set"
	TypeMachineAdd    = "machine_add"
	TypeMachineRemove = "machine_remove"
	TypeGroupSet      = "group_set"
)

// How an admin checked that a new member's account is theirs.
const (
	// VerifiedGitHubSSH: the member signed their account key with an SSH
	// key registered on their GitHub account.
	VerifiedGitHubSSH = "github_ssh"
	// VerifiedAccountKey: the admin typed the member's account key words,
	// read to them over another channel.
	VerifiedAccountKey = "account_key"
)

// Bounds that keep verification and the web pages cheap.
const (
	MaxLinks    = 10000
	MaxMembers  = 200
	MaxMachines = 100
	MaxEnvs     = 100
)

// ErrRollback is returned when a project chain is older than, or forks
// from, a pinned head.
var ErrRollback = errors.New("project chain rollback or fork detected")

// Link is the signed body of a project-link envelope.
type Link struct {
	Project string    `json:"project"`
	Seq     uint64    `json:"seq"`
	Prev    string    `json:"prev"`
	CTime   time.Time `json:"ctime"`
	Type    string    `json:"type"`
	// Signer is the member who made the link, SignerKey the version of
	// their user key that signed it, and SignerSeq the length of their user
	// chain then. The key must be the one current at that position, and a
	// signer's positions never go back within a project chain.
	Signer    string `json:"signer"`
	SignerKey uint64 `json:"signer_ukey_version"`
	SignerSeq uint64 `json:"signer_seq"`
	// SignerDelegate, when set, is the signer's delegate that signed the
	// link for them (delegate.go); SignerKey is then 0.
	SignerDelegate string          `json:"signer_delegate,omitempty"`
	Body           json.RawMessage `json:"body"`
}

// Person identifies a member's account: the GitHub id, the login when they
// were added (for display), and the hash of the first link of their user
// chain, which every later key of theirs is verified from.
type Person struct {
	User  string `json:"user"`
	Login string `json:"login"`
	Root  string `json:"root"`
}

// Env is an environment and its current public key.
type Env struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// InitBody creates a project; the creator is its first admin.
type InitBody struct {
	Creator Person `json:"creator"`
	Envs    []Env  `json:"envs"`
}

// MemberAddBody adds a member. Admins can read every environment and
// manage the project; others read the environments listed.
type MemberAddBody struct {
	Member   Person   `json:"member"`
	Admin    bool     `json:"admin,omitempty"`
	Envs     []string `json:"envs,omitempty"`
	Verified string   `json:"verified"`
}

// MemberUpdateBody changes a member's role or environments.
type MemberUpdateBody struct {
	User  string   `json:"user"`
	Admin bool     `json:"admin,omitempty"`
	Envs  []string `json:"envs,omitempty"`
}

// MemberRemoveBody removes a member; a member may also remove themselves.
type MemberRemoveBody struct {
	User   string `json:"user"`
	Reason string `json:"reason,omitempty"`
}

// EnvSetBody adds an environment or replaces its key.
type EnvSetBody struct {
	Env    Env    `json:"env"`
	Reason string `json:"reason,omitempty"`
}

// Machine is a non-person identity, such as a CI job or a deployed app:
// an X25519 key that receives environment keys and an Ed25519 key that
// signs its requests. Both private halves are in the machine's secret.
type Machine struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	EncPub  string    `json:"enc_pub"`
	SignPub string    `json:"sign_pub"`
	Created time.Time `json:"created"`
}

// MachineAddBody adds a machine that reads the listed environments.
type MachineAddBody struct {
	Machine Machine     `json:"machine"`
	Envs    []string    `json:"envs"`
	OIDC    *OIDCPolicy `json:"oidc,omitempty"`
}

// MachineRemoveBody removes a machine.
type MachineRemoveBody struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// GroupSetBody grants a machine group the listed environments, or with
// none, takes them away. Root is the hash of the group chain's first link.
type GroupSetBody struct {
	Group string   `json:"group"`
	Root  string   `json:"root"`
	Envs  []string `json:"envs"`
}

// ProjectGroupState is a machine group as the verified project chain sees
// it.
type ProjectGroupState struct {
	Group      string    `json:"group"`
	Root       string    `json:"root"`
	Envs       []string  `json:"envs"`
	Active     bool      `json:"active"`
	AddedBy    string    `json:"added_by"`
	AddedSeq   uint64    `json:"added_seq"`
	Since      time.Time `json:"since"`
	RemovedSeq uint64    `json:"removed_seq,omitempty"`
	// EnvSince is when the group was granted each environment it reads.
	EnvSince map[string]time.Time `json:"env_since"`
}

// Has reports whether the group may read env.
func (g *ProjectGroupState) Has(env string) bool { return g.Active && slices.Contains(g.Envs, env) }

// MemberState is a member as the verified chain sees them.
type MemberState struct {
	Person

	Admin      bool     `json:"admin"`
	Envs       []string `json:"envs,omitempty"`
	Active     bool     `json:"active"`
	Verified   string   `json:"verified,omitempty"`
	AddedBy    string   `json:"added_by,omitempty"`
	AddedSeq   uint64   `json:"added_seq"`
	RemovedSeq uint64   `json:"removed_seq,omitempty"`
}

// Has reports whether the member may read env.
func (m *MemberState) Has(env string) bool {
	return m.Active && (m.Admin || slices.Contains(m.Envs, env))
}

// MachineState is a machine as the verified chain sees it.
type MachineState struct {
	Machine

	Envs       []string    `json:"envs"`
	OIDC       *OIDCPolicy `json:"oidc,omitempty"`
	Active     bool        `json:"active"`
	AddedBy    string      `json:"added_by"`
	AddedSeq   uint64      `json:"added_seq"`
	RemovedSeq uint64      `json:"removed_seq,omitempty"`
}

// Has reports whether the machine may read env.
func (m *MachineState) Has(env string) bool { return m.Active && slices.Contains(m.Envs, env) }

// Exposure records someone who lost access to an environment while its
// current key was in use. They may still hold that key, so the key needs
// replacing.
type Exposure struct {
	// Holder is a user id or machine id, and Name its login or name.
	Holder string    `json:"holder"`
	Name   string    `json:"name"`
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
}

// EnvState is an environment as the verified chain sees it.
type EnvState struct {
	Env

	Seq   uint64    `json:"seq"`
	Since time.Time `json:"since"`
	// Retired lists the environment's earlier public keys, oldest first.
	Retired []string `json:"retired,omitempty"`
	// Exposed lists who lost access while the current key was in use. A
	// new key (env_set) clears it.
	Exposed []Exposure `json:"exposed,omitempty"`
}

// State is the result of verifying a project chain.
type State struct {
	Project  string
	Seq      uint64
	Hashes   []string
	LastTime time.Time
	Members  map[string]*MemberState
	Envs     map[string]*EnvState
	Machines map[string]*MachineState
	// Groups maps group ids to the machine groups granted environments.
	Groups map[string]*ProjectGroupState
	Links  []Link
	// signerSeqs is each signer's latest user chain position.
	signerSeqs map[string]uint64
}

// Chains returns the verified user chain of an account. A verifier passes
// one that checks the chain it fetches (and pins it where it can).
type Chains func(user string) (*chain.State, error)

var (
	loginPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	envPattern     = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9]+)*$`)
	machinePattern = regexp.MustCompile(`^m_[a-z0-9]{8,40}$`)
	rootPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reasonPattern  = regexp.MustCompile(`^[\pL\pN .,:;()'/_+-]{0,200}$`)
)

// ValidProject checks a project id ("org/repo").
func ValidProject(id string) error {
	if id == "default" || projectfile.ValidateOrgRepo(id) != nil {
		return fmt.Errorf("invalid project id %q: use org/repo", id)
	}
	return nil
}

// ValidLogin checks a GitHub login.
func ValidLogin(login string) error {
	if !loginPattern.MatchString(login) || strings.Contains(login, "--") || strings.HasSuffix(login, "-") {
		return fmt.Errorf("invalid GitHub login %q", login)
	}
	return nil
}

// ValidEnv checks an environment name: dot-separated lowercase letters and
// digits, as esec uses them.
func ValidEnv(name string) error {
	if len(name) > 64 || !envPattern.MatchString(name) {
		return fmt.Errorf("invalid environment %q: use dot-separated lowercase letters and digits", name)
	}
	return nil
}

// ValidMachineID checks a machine id.
func ValidMachineID(id string) error {
	if !machinePattern.MatchString(id) {
		return fmt.Errorf("invalid machine id")
	}
	return nil
}

// EnvKey is the keyring entry and environment variable of an environment's
// private key.
func EnvKey(env string) string {
	return "ESEC_PRIVATE_KEY_" + strings.ToUpper(strings.ReplaceAll(env, ".", "_"))
}

// PubKeyEntry is the keyring entry that stores a key under its public key,
// which keeps it findable after the environment moves to a new key.
func PubKeyEntry(pub string) string { return "ESEC_PRIVATE_KEY_" + strings.ToUpper(pub) }

func validPerson(p Person) error {
	if err := chain.ValidUser(p.User); err != nil {
		return err
	}
	if err := ValidLogin(p.Login); err != nil {
		return err
	}
	if !rootPattern.MatchString(p.Root) {
		return fmt.Errorf("invalid account root")
	}
	return nil
}

func validEnvKey(e Env) error {
	if err := ValidEnv(e.Name); err != nil {
		return err
	}
	if _, err := chain.ParseKey32(e.PublicKey); err != nil || strings.ToLower(e.PublicKey) != e.PublicKey {
		return fmt.Errorf("invalid public key for environment %s", e.Name)
	}
	return nil
}

func validReason(r string) error {
	if !reasonPattern.MatchString(r) {
		return fmt.Errorf("a reason is at most 200 letters, digits, spaces and simple punctuation")
	}
	return nil
}

// ValidateMachine checks a machine description.
func ValidateMachine(m Machine) error {
	if err := ValidMachineID(m.ID); err != nil {
		return err
	}
	if err := chain.ValidDeviceName(m.Name); err != nil {
		return fmt.Errorf("machine name must be 1-64 letters, digits, spaces or ._()'- characters")
	}
	if _, err := chain.ParseKey32(m.EncPub); err != nil {
		return fmt.Errorf("machine encryption key: %w", err)
	}
	if _, err := chain.ParseSignKey(m.SignPub); err != nil {
		return fmt.Errorf("machine signing key: %w", err)
	}
	if m.Created.IsZero() {
		return fmt.Errorf("machine creation time missing")
	}
	return nil
}

// New returns the empty state of a project.
func New(project string) *State {
	return &State{Project: project, Members: map[string]*MemberState{}, Envs: map[string]*EnvState{}, Machines: map[string]*MachineState{}, Groups: map[string]*ProjectGroupState{}, signerSeqs: map[string]uint64{}}
}

// Verify checks a complete project chain from its first link.
func Verify(project string, links []*envelope.Envelope, chains Chains) (*State, error) {
	if err := ValidProject(project); err != nil {
		return nil, err
	}
	if len(links) > MaxLinks {
		return nil, fmt.Errorf("project chain too long")
	}
	s := New(project)
	for i, e := range links {
		if err := s.step(e, chains); err != nil {
			return nil, fmt.Errorf("project chain link %d: %w", i+1, err)
		}
	}
	return s, nil
}

// Head returns the hash of the last link, or "".
func (s *State) Head() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[len(s.Hashes)-1]
}

// Root returns the hash of the first link, which identifies the project
// chain: machines hold it as their trust anchor.
func (s *State) Root() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[0]
}

// CheckPin returns ErrRollback unless s contains the pinned link at seq.
func (s *State) CheckPin(seq uint64, hash string) error {
	if seq == 0 {
		return nil
	}
	if s.Seq < seq {
		return fmt.Errorf("%w: the server's chain for %s has %d links, this device has seen %d", ErrRollback, s.Project, s.Seq, seq)
	}
	if s.Hashes[seq-1] != hash {
		return fmt.Errorf("%w: link %d of %s differs from the one this device verified", ErrRollback, seq, s.Project)
	}
	return nil
}

// Member returns an active member.
func (s *State) Member(user string) (*MemberState, bool) {
	m, ok := s.Members[user]
	if !ok || !m.Active {
		return nil, false
	}
	return m, true
}

// Admin reports whether user is an active admin.
func (s *State) Admin(user string) bool {
	m, ok := s.Member(user)
	return ok && m.Admin
}

// ActiveMembers returns the active members sorted by login.
func (s *State) ActiveMembers() []*MemberState {
	var out []*MemberState
	for _, m := range s.Members {
		if m.Active {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out
}

// ActiveMachines returns the active machines sorted by name.
func (s *State) ActiveMachines() []*MachineState {
	var out []*MachineState
	for _, m := range s.Machines {
		if m.Active {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Machine returns an active machine.
func (s *State) Machine(id string) (*MachineState, bool) {
	m, ok := s.Machines[id]
	if !ok || !m.Active {
		return nil, false
	}
	return m, true
}

// EnvNames returns the environment names, sorted.
func (s *State) EnvNames() []string {
	out := make([]string, 0, len(s.Envs))
	for n := range s.Envs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Access returns the environments a member or machine may read, sorted.
func (s *State) Access(holder string) []string {
	var out []string
	for _, n := range s.EnvNames() {
		if s.HasAccess(holder, n) {
			out = append(out, n)
		}
	}
	return out
}

// ActiveGroups returns the groups granted environments, sorted by id.
func (s *State) ActiveGroups() []*ProjectGroupState {
	var out []*ProjectGroupState
	for _, g := range s.Groups {
		if g.Active {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

// Group returns a group granted environments.
func (s *State) Group(id string) (*ProjectGroupState, bool) {
	g, ok := s.Groups[id]
	if !ok || !g.Active {
		return nil, false
	}
	return g, true
}

// HasAccess reports whether an active member, machine or group (by its
// holder id, GroupHolder) may read env.
func (s *State) HasAccess(holder, env string) bool {
	if id, ok := strings.CutPrefix(holder, GroupHolderPrefix); ok {
		g, ok := s.Groups[id]
		return ok && g.Has(env)
	}
	if m, ok := s.Members[holder]; ok {
		return m.Has(env)
	}
	if m, ok := s.Machines[holder]; ok {
		return m.Has(env)
	}
	return false
}

// Rotations lists the environments whose current key someone who lost
// access may still hold, sorted.
func (s *State) Rotations() []*EnvState {
	var out []*EnvState
	for _, n := range s.EnvNames() {
		if len(s.Envs[n].Exposed) > 0 {
			out = append(out, s.Envs[n])
		}
	}
	return out
}

// NewLink builds and signs the next link. signer is the member making it,
// with their current user key version and signing key.
func (s *State) NewLink(typ string, body any, ctime time.Time, signer string, version, signerSeq uint64, key ed25519.PrivateKey) (*envelope.Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	l := Link{Project: s.Project, Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, Signer: signer, SignerKey: version, SignerSeq: signerSeq, Body: raw}
	return envelope.New(KindLink, l, key)
}

// Next verifies e as the next link and returns the new state; s is not
// modified.
func (s *State) Next(e *envelope.Envelope, chains Chains) (*State, error) {
	n := s.clone()
	if err := n.step(e, chains); err != nil {
		return nil, err
	}
	return n, nil
}

// PeekLink decodes a link without verifying it.
func PeekLink(e *envelope.Envelope) (*Link, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindLink {
		return nil, fmt.Errorf("not a project chain link")
	}
	var l Link
	if err := e.Decode(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

// SignerKey returns the public key of user's user key version, which must
// be the one current after seq links of user's verified chain, whose root
// must be root. Positions, unlike times, cannot be skewed by the signer's
// clock; see State.signers for why they may not go back.
func SignerKey(chains Chains, user, root string, version, seq uint64) (ed25519.PublicKey, error) {
	if chains == nil {
		return nil, errors.New("no user chains to verify signatures with")
	}
	cs, err := chains(user)
	if err != nil {
		return nil, fmt.Errorf("user chain of %s: %w", user, err)
	}
	if cs.User != user || cs.Root() == "" || cs.Root() != root {
		return nil, fmt.Errorf("the account of %s is not the one the project recorded", user)
	}
	ep, ok := cs.EpochAt(seq)
	if !ok || ep.Version != version {
		return nil, fmt.Errorf("signed with a user key of %s that was not current at the position it names", user)
	}
	return ep.SignPub, nil
}

// DelegateLink builds the next link for a delegate of signer to sign; the
// caller adds the delegate's signature.
func (s *State) DelegateLink(typ string, body any, ctime time.Time, signer, delegate string, signerSeq uint64) (*envelope.Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	l := Link{Project: s.Project, Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, Signer: signer, SignerSeq: signerSeq, SignerDelegate: delegate, Body: raw}
	body2, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return envelope.NewRaw(KindLink, body2)
}

func (s *State) step(e *envelope.Envelope, chains Chains) error {
	l, err := PeekLink(e)
	if err != nil {
		return err
	}
	if l.Project != s.Project {
		return fmt.Errorf("link belongs to another project")
	}
	if l.Seq != s.Seq+1 || l.Prev != s.Head() {
		return fmt.Errorf("link is out of sequence")
	}
	if l.CTime.IsZero() {
		return fmt.Errorf("link time missing")
	}
	// Admins sign with their own clocks, so allow some skew, but not an
	// old time: a link may not claim to predate the chain's history.
	if !s.LastTime.IsZero() && l.CTime.Before(s.LastTime.Add(-time.Hour)) {
		return fmt.Errorf("link time goes backwards")
	}
	if err := chain.ValidUser(l.Signer); err != nil {
		return err
	}
	root, err := s.signerRoot(l, chains)
	if err != nil {
		return err
	}
	if err := s.checkSigner(e, l, root, chains); err != nil {
		return err
	}
	// A revoked device holds its owner's old key and knows the old chain,
	// so it could sign as of a position before the rotation. Once the owner
	// has signed in this project as of a later position, that is refused.
	if l.SignerSeq < s.signerSeqs[l.Signer] {
		return fmt.Errorf("%s signed as of an earlier position of their user chain than before", l.Signer)
	}
	if err := s.apply(*l); err != nil {
		return err
	}
	if len(s.Members) > MaxMembers || len(s.Machines) > MaxMachines || len(s.Envs) > MaxEnvs || len(s.Groups) > MaxProjectGroups {
		return fmt.Errorf("the project has too many members, machines, groups or environments")
	}
	s.signerSeqs[l.Signer] = l.SignerSeq
	s.Seq = l.Seq
	s.Hashes = append(s.Hashes, e.Hash())
	s.LastTime = l.CTime
	s.Links = append(s.Links, *l)
	return nil
}

// checkSigner checks a link's signature: by the signer's user key current
// at the position it names, or by a delegate of theirs whose scope covers
// the link.
func (s *State) checkSigner(e *envelope.Envelope, l *Link, root string, chains Chains) error {
	var add MemberAddBody
	webAdd := l.Type == TypeMemberAdd && decodeBody(*l, &add) == nil && add.Verified == VerifiedWeb
	if l.SignerDelegate == "" {
		if webAdd {
			return errors.New("only a delegate's link adds a member checked on the web")
		}
		pub, err := SignerKey(chains, l.Signer, root, l.SignerKey, l.SignerSeq)
		if err != nil {
			return err
		}
		return e.Require(KindLink, pub)
	}
	if l.SignerKey != 0 {
		return errors.New("a delegate's link names no user key version")
	}
	d, err := DelegateSigner(chains, l.Signer, root, l.SignerDelegate, l.SignerSeq, l.CTime)
	if err != nil {
		return err
	}
	scope, err := projectScope(s, *l)
	if err != nil {
		return err
	}
	if !chain.DelegateAllows(d.Scope, scope) {
		return fmt.Errorf("%w: the delegate %s may only sign %s changes", errNotInScope, d.Name, d.Scope)
	}
	return verifyDelegate(e, KindLink, d)
}

// signerRoot returns the account root the signer must have: the creator's
// for the first link, the recorded member's after that.
func (s *State) signerRoot(l *Link, _ Chains) (string, error) {
	if l.Seq == 1 {
		if l.Type != TypeInit {
			return "", fmt.Errorf("a project chain must start with an init link")
		}
		var b InitBody
		if err := decodeBody(*l, &b); err != nil {
			return "", err
		}
		if b.Creator.User != l.Signer {
			return "", fmt.Errorf("the init link must be signed by its creator")
		}
		return b.Creator.Root, nil
	}
	m, ok := s.Member(l.Signer)
	if !ok {
		return "", fmt.Errorf("%s is not a member of the project", l.Signer)
	}
	return m.Root, nil
}

func (s *State) apply(l Link) error {
	if l.Type != TypeInit && l.Seq == 1 {
		return fmt.Errorf("a project chain must start with an init link")
	}
	if l.Type != TypeInit && l.Type != TypeMemberRemove && !s.Admin(l.Signer) {
		return fmt.Errorf("only an admin can make a %s link", l.Type)
	}
	switch l.Type {
	case TypeInit:
		return s.applyInit(l)
	case TypeMemberAdd:
		return s.applyMemberAdd(l)
	case TypeMemberUpdate:
		return s.applyMemberUpdate(l)
	case TypeMemberRemove:
		return s.applyMemberRemove(l)
	case TypeEnvSet:
		var b EnvSetBody
		if err := decodeBody(l, &b); err != nil {
			return err
		}
		if err := validReason(b.Reason); err != nil {
			return err
		}
		return s.setEnv(b.Env, l, true)
	case TypeMachineAdd:
		return s.applyMachineAdd(l)
	case TypeMachineRemove:
		return s.applyMachineRemove(l)
	case TypeGroupSet:
		return s.applyGroupSet(l)
	}
	return fmt.Errorf("unknown link type %q", l.Type)
}

func (s *State) applyInit(l Link) error {
	if l.Seq != 1 {
		return fmt.Errorf("init link after the start of the chain")
	}
	var b InitBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := validPerson(b.Creator); err != nil {
		return err
	}
	for _, e := range b.Envs {
		if err := s.setEnv(e, l, false); err != nil {
			return err
		}
	}
	s.Members[b.Creator.User] = &MemberState{Person: b.Creator, Admin: true, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq}
	return nil
}

func (s *State) applyMemberAdd(l Link) error {
	var b MemberAddBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := validPerson(b.Member); err != nil {
		return err
	}
	if b.Verified != VerifiedGitHubSSH && b.Verified != VerifiedAccountKey && b.Verified != VerifiedWeb {
		return fmt.Errorf("unknown verification %q", b.Verified)
	}
	if old, exists := s.Members[b.Member.User]; exists && old.Active {
		return fmt.Errorf("%s is already a member", b.Member.Login)
	}
	envs, err := s.checkAccess(b.Admin, b.Envs)
	if err != nil {
		return err
	}
	// A former member comes back as a new entry; the record of their earlier
	// access stays in the chain.
	s.Members[b.Member.User] = &MemberState{Person: b.Member, Admin: b.Admin, Envs: envs, Active: true, Verified: b.Verified, AddedBy: l.Signer, AddedSeq: l.Seq}
	return nil
}

func (s *State) applyMemberUpdate(l Link) error {
	var b MemberUpdateBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	m, ok := s.Member(b.User)
	if !ok {
		return fmt.Errorf("%s is not a member", b.User)
	}
	envs, err := s.checkAccess(b.Admin, b.Envs)
	if err != nil {
		return err
	}
	if m.Admin && !b.Admin && s.admins() == 1 {
		return fmt.Errorf("a project needs at least one admin")
	}
	next := *m
	next.Admin, next.Envs = b.Admin, envs
	for _, n := range s.EnvNames() {
		if m.Has(n) && !next.Has(n) {
			s.expose(n, m.User, m.Login, l, "access to "+n+" removed")
		}
	}
	*m = next
	return nil
}

func (s *State) applyMemberRemove(l Link) error {
	var b MemberRemoveBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	// Admins remove anyone; a member may remove only themselves.
	if b.User != l.Signer && !s.Admin(l.Signer) {
		return fmt.Errorf("only an admin can make a %s link", l.Type)
	}
	m, ok := s.Member(b.User)
	if !ok {
		return fmt.Errorf("%s is not a member", b.User)
	}
	if m.Admin && s.admins() == 1 {
		return fmt.Errorf("the last admin cannot leave; make someone else an admin first")
	}
	why := "removed"
	if b.User == l.Signer {
		why = "left the project"
	}
	for _, n := range s.EnvNames() {
		if m.Has(n) {
			s.expose(n, m.User, m.Login, l, why)
		}
	}
	m.Active, m.RemovedSeq = false, l.Seq
	return nil
}

func (s *State) applyMachineAdd(l Link) error {
	var b MachineAddBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := ValidateMachine(b.Machine); err != nil {
		return err
	}
	if _, exists := s.Machines[b.Machine.ID]; exists {
		return fmt.Errorf("machine id reused")
	}
	for _, m := range s.Machines {
		if m.SignPub == b.Machine.SignPub || m.EncPub == b.Machine.EncPub {
			return fmt.Errorf("machine keys reused")
		}
	}
	if len(b.Envs) == 0 {
		return fmt.Errorf("a machine needs at least one environment")
	}
	envs, err := s.checkAccess(false, b.Envs)
	if err != nil {
		return err
	}
	if b.OIDC != nil {
		if err := b.OIDC.Validate(); err != nil {
			return err
		}
	}
	s.Machines[b.Machine.ID] = &MachineState{Machine: b.Machine, Envs: envs, OIDC: b.OIDC, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq}
	return nil
}

func (s *State) applyMachineRemove(l Link) error {
	var b MachineRemoveBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	m, ok := s.Machine(b.ID)
	if !ok {
		return fmt.Errorf("machine %s is not active", b.ID)
	}
	for _, n := range m.Envs {
		s.expose(n, m.ID, m.Name, l, "machine removed")
	}
	m.Active, m.RemovedSeq = false, l.Seq
	return nil
}

func (s *State) applyGroupSet(l Link) error {
	var b GroupSetBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := ValidGroup(b.Group); err != nil {
		return err
	}
	if !rootPattern.MatchString(b.Root) {
		return fmt.Errorf("invalid group root")
	}
	envs, err := s.checkAccess(false, b.Envs)
	if err != nil {
		return err
	}
	old, ok := s.Group(b.Group)
	if !ok {
		if len(envs) == 0 {
			return fmt.Errorf("the group %s reads nothing yet", b.Group)
		}
		since := map[string]time.Time{}
		for _, n := range envs {
			since[n] = l.CTime
		}
		s.Groups[b.Group] = &ProjectGroupState{Group: b.Group, Root: b.Root, Envs: envs, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq, Since: l.CTime, EnvSince: since}
		return nil
	}
	if old.Root != b.Root {
		return fmt.Errorf("the group %s was recreated; take its access away first", b.Group)
	}
	for _, n := range old.Envs {
		if !slices.Contains(envs, n) {
			s.expose(n, GroupHolder(b.Group), b.Group, l, "group access to "+n+" removed")
		}
	}
	if len(envs) == 0 {
		old.Active, old.RemovedSeq = false, l.Seq
		return nil
	}
	since := map[string]time.Time{}
	for _, n := range envs {
		since[n] = l.CTime
		if t, ok := old.EnvSince[n]; ok && slices.Contains(old.Envs, n) {
			since[n] = t
		}
	}
	old.Envs, old.EnvSince = envs, since
	return nil
}

// setEnv adds an environment or replaces its key. A replaced key is
// retired, and the exposures of the old key no longer matter.
func (s *State) setEnv(e Env, l Link, allowReplace bool) error {
	if err := validEnvKey(e); err != nil {
		return err
	}
	old, exists := s.Envs[e.Name]
	if exists && !allowReplace {
		return fmt.Errorf("environment %s listed twice", e.Name)
	}
	for _, other := range s.Envs {
		if other.PublicKey == e.PublicKey || slices.Contains(other.Retired, e.PublicKey) {
			return fmt.Errorf("the key of %s was already used", e.Name)
		}
	}
	next := &EnvState{Env: e, Seq: l.Seq, Since: l.CTime}
	if exists {
		next.Retired = append(append([]string(nil), old.Retired...), old.PublicKey)
	}
	s.Envs[e.Name] = next
	return nil
}

func (s *State) expose(env, holder, name string, l Link, reason string) {
	e, ok := s.Envs[env]
	if !ok {
		return
	}
	e.Exposed = append(e.Exposed, Exposure{Holder: holder, Name: name, Seq: l.Seq, Time: l.CTime, Reason: reason})
}

func (s *State) admins() int {
	n := 0
	for _, m := range s.Members {
		if m.Active && m.Admin {
			n++
		}
	}
	return n
}

// checkAccess validates a member's or machine's environments: admins list
// none (they read all), others list existing environments, sorted and
// without duplicates.
func (s *State) checkAccess(admin bool, envs []string) ([]string, error) {
	if admin {
		if len(envs) > 0 {
			return nil, fmt.Errorf("admins read every environment; list none")
		}
		return nil, nil
	}
	if !sort.StringsAreSorted(envs) {
		return nil, fmt.Errorf("environments must be sorted")
	}
	for i, n := range envs {
		if _, ok := s.Envs[n]; !ok {
			return nil, fmt.Errorf("unknown environment %q", n)
		}
		if i > 0 && envs[i-1] == n {
			return nil, fmt.Errorf("environment %s listed twice", n)
		}
	}
	return append([]string(nil), envs...), nil
}

func decodeBody(l Link, v any) error {
	if err := envelope.DecodeStrict(l.Body, v); err != nil {
		return fmt.Errorf("invalid %s body: %w", l.Type, err)
	}
	return nil
}

func (s *State) clone() *State {
	n := *s
	n.Hashes = append([]string(nil), s.Hashes...)
	n.Links = append([]Link(nil), s.Links...)
	n.signerSeqs = make(map[string]uint64, len(s.signerSeqs))
	for k, v := range s.signerSeqs {
		n.signerSeqs[k] = v
	}
	n.Members = make(map[string]*MemberState, len(s.Members))
	for k, v := range s.Members {
		c := *v
		c.Envs = append([]string(nil), v.Envs...)
		n.Members[k] = &c
	}
	n.Envs = make(map[string]*EnvState, len(s.Envs))
	for k, v := range s.Envs {
		c := *v
		c.Retired = append([]string(nil), v.Retired...)
		c.Exposed = append([]Exposure(nil), v.Exposed...)
		n.Envs[k] = &c
	}
	n.Groups = make(map[string]*ProjectGroupState, len(s.Groups))
	for k, v := range s.Groups {
		c := *v
		c.Envs = append([]string(nil), v.Envs...)
		c.EnvSince = make(map[string]time.Time, len(v.EnvSince))
		for e, t := range v.EnvSince {
			c.EnvSince[e] = t
		}
		n.Groups[k] = &c
	}
	n.Machines = make(map[string]*MachineState, len(s.Machines))
	for k, v := range s.Machines {
		c := *v
		c.Envs = append([]string(nil), v.Envs...)
		n.Machines[k] = &c
	}
	return &n
}

// SortEnvs returns a sorted, de-duplicated copy of names.
func SortEnvs(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return slices.Compact(out)
}

// PublicHex returns the hex public key of a hex X25519 private key.
func PublicHex(priv string) (string, error) {
	k, err := chain.ParseKey32(strings.ToLower(strings.TrimSpace(priv)))
	if err != nil {
		return "", errors.New("malformed private key")
	}
	pub := identity.PublicFromPrivate(k)
	return hex.EncodeToString(pub[:]), nil
}
