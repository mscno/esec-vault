package team

// Machine groups. A group (such as "acme/production") is a set of machines
// that read the same environments: its own signed chain records its admins,
// its machines and enrollment tokens, its encryption key, and the projects
// it trusts. A project grants environments to a group with a group_set link;
// an admin of the project seals those keys once, to the group's key. Every
// machine and token of the group gets the group's private key sealed to its
// own key, so a new machine reads the group's environments as soon as it is
// in the group, without an admin's device having to be online.
//
// A machine verifies the group chain from its first link, which its key
// names, and accepts environment keys only from projects the group chain
// lists with their first link: the server can neither add a machine nor feed
// one keys of a project the group's admins did not choose.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/crypto"
	"golang.org/x/crypto/nacl/box"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/fpwords"
	"github.com/mscno/esec-vault/internal/identity"
)

// Envelope kinds of machine groups.
const (
	KindGroupLink = "group-link"
	KindGroupKey  = "group-key"
)

// Group link types.
const (
	GroupInit         = "init"
	GroupAdminAdd     = "admin_add"
	GroupAdminRemove  = "admin_remove"
	GroupMachineAdd   = "machine_add"
	GroupTokenAdd     = "token_add"
	GroupRemove       = "remove"
	GroupKeyRotate    = "key_rotate"
	GroupAccessAdd    = "access_add"
	GroupAccessRemove = "access_remove"
)

// Credential kinds: a machine is one host; a token is a shared secret for
// short-lived workloads that can also enroll machines.
const (
	KindMachine = "machine"
	KindToken   = "token"
)

// Bounds of a group.
const (
	MaxGroupAdmins   = 50
	MaxGroupCreds    = 1000
	MaxGroupProjects = 200
	MaxProjectGroups = 50
)

// GroupHolderPrefix starts the holder id of a group in a project.
const GroupHolderPrefix = "g:"

// GroupHolder returns the holder id of a group in a project chain's grants.
func GroupHolder(group string) string { return GroupHolderPrefix + group }

var (
	credPattern = regexp.MustCompile(`^[mt]_[a-z0-9]{8,40}$`)
)

// ValidGroup checks a group id ("org/name").
func ValidGroup(id string) error {
	if ValidProject(id) != nil {
		return fmt.Errorf("invalid group %q: use org/name, such as acme/production", id)
	}
	return nil
}

// ValidCredID checks a machine or token id of a group.
func ValidCredID(id string) error {
	if !credPattern.MatchString(id) {
		return errors.New("invalid machine or token id")
	}
	return nil
}

// GroupLink is the signed body of a group-link envelope. Signer is an
// admin's user id, signing with their user key like in a project chain, or
// (for machine_add only) the id of an enrollment token, signing with the
// token's key; then SignerKey and SignerSeq are 0.
type GroupLink struct {
	Group     string    `json:"group"`
	Seq       uint64    `json:"seq"`
	Prev      string    `json:"prev"`
	CTime     time.Time `json:"ctime"`
	Type      string    `json:"type"`
	Signer    string    `json:"signer"`
	SignerKey uint64    `json:"signer_ukey_version"`
	SignerSeq uint64    `json:"signer_seq"`
	// SignerDelegate, when set, is the admin's delegate that signed the
	// link for them; SignerKey is then 0.
	SignerDelegate string          `json:"signer_delegate,omitempty"`
	Body           json.RawMessage `json:"body"`
}

// GroupKey is a version of a group's X25519 key.
type GroupKey struct {
	Version uint64 `json:"version"`
	EncPub  string `json:"enc_pub"`
}

// Credential is a machine or token of a group: an X25519 key the group key
// is sealed to and an Ed25519 key that signs its requests.
type Credential struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	EncPub  string    `json:"enc_pub"`
	SignPub string    `json:"sign_pub"`
	Created time.Time `json:"created"`
	// Expires ends a token's use; zero never.
	Expires time.Time `json:"expires,omitzero"`
	// OIDC, when set, hands the credential's keys only to matching
	// workloads.
	OIDC *OIDCPolicy `json:"oidc,omitempty"`
}

// Group link bodies.
type (
	// GroupInitBody creates a group; the creator is its first admin.
	GroupInitBody struct {
		Creator Person   `json:"creator"`
		Key     GroupKey `json:"key"`
	}
	// GroupAdminAddBody adds an admin.
	GroupAdminAddBody struct {
		Admin    Person `json:"admin"`
		Verified string `json:"verified"`
	}
	// GroupAdminRemoveBody removes an admin; an admin may remove themselves.
	GroupAdminRemoveBody struct {
		User   string `json:"user"`
		Reason string `json:"reason,omitempty"`
	}
	// GroupMachineAddBody adds a machine. Join names the request the
	// machine made, when it asked to join.
	GroupMachineAddBody struct {
		Machine Credential `json:"machine"`
		Join    string     `json:"join,omitempty"`
	}
	// GroupTokenAddBody adds an enrollment token.
	GroupTokenAddBody struct {
		Token Credential `json:"token"`
	}
	// GroupRemoveBody removes a machine or token. Destroyed says the admin
	// knows its keys are gone (a deleted VM), so nothing needs rotating.
	GroupRemoveBody struct {
		ID        string `json:"id"`
		Reason    string `json:"reason,omitempty"`
		Destroyed bool   `json:"destroyed,omitempty"`
	}
	// GroupKeyRotateBody replaces the group's key.
	GroupKeyRotateBody struct {
		Key    GroupKey `json:"key"`
		Reason string   `json:"reason,omitempty"`
	}
	// GroupAccessBody lets the group take keys from a project, named with
	// the hash of its chain's first link.
	GroupAccessBody struct {
		Project string `json:"project"`
		Root    string `json:"root"`
	}
	// GroupAccessRemoveBody stops the group taking keys from a project.
	GroupAccessRemoveBody struct {
		Project string `json:"project"`
	}
)

// GroupAdminState is an admin as the verified group chain sees them.
type GroupAdminState struct {
	Person

	Active      bool      `json:"active"`
	Verified    string    `json:"verified,omitempty"`
	AddedBy     string    `json:"added_by,omitempty"`
	AddedSeq    uint64    `json:"added_seq"`
	RemovedSeq  uint64    `json:"removed_seq,omitempty"`
	RemovedTime time.Time `json:"removed_time,omitzero"`
}

// CredState is a machine or token as the verified group chain sees it.
type CredState struct {
	Credential

	Kind        string    `json:"kind"`
	Active      bool      `json:"active"`
	AddedBy     string    `json:"added_by"`
	AddedSeq    uint64    `json:"added_seq"`
	AddedTime   time.Time `json:"added_time"`
	Join        string    `json:"join,omitempty"`
	RemovedSeq  uint64    `json:"removed_seq,omitempty"`
	RemovedTime time.Time `json:"removed_time,omitzero"`
	Destroyed   bool      `json:"destroyed,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// Expired reports whether a token can no longer be used at now.
func (c *CredState) Expired(now time.Time) bool {
	return !c.Expires.IsZero() && !now.Before(c.Expires)
}

// GroupState is the result of verifying a group chain.
type GroupState struct {
	Group    string
	Seq      uint64
	Hashes   []string
	LastTime time.Time
	Links    []GroupLink
	Admins   map[string]*GroupAdminState
	Creds    map[string]*CredState
	Key      GroupKey
	KeySince time.Time
	// KeyExposed lists machines and tokens removed while the current group
	// key was in use; a new key (key_rotate) clears it.
	KeyExposed []Exposure
	// Access maps the projects the group takes keys from to their roots.
	Access     map[string]string
	retired    map[string]bool
	signerSeqs map[string]uint64
	// active counts active machines and tokens.
	active int
}

// NewGroup returns the empty state of a group.
func NewGroup(group string) *GroupState {
	return &GroupState{Group: group, Admins: map[string]*GroupAdminState{}, Creds: map[string]*CredState{}, Access: map[string]string{}, retired: map[string]bool{}, signerSeqs: map[string]uint64{}}
}

// VerifyGroup checks a complete group chain from its first link.
func VerifyGroup(group string, links []*envelope.Envelope, chains Chains) (*GroupState, error) {
	if err := ValidGroup(group); err != nil {
		return nil, err
	}
	if len(links) > MaxLinks {
		return nil, errors.New("group chain too long")
	}
	s := NewGroup(group)
	for i, e := range links {
		if err := s.step(e, chains); err != nil {
			return nil, fmt.Errorf("group chain link %d: %w", i+1, err)
		}
	}
	return s, nil
}

// Head returns the hash of the last link, or "".
func (s *GroupState) Head() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[len(s.Hashes)-1]
}

// Root returns the hash of the first link, which machines hold as their
// trust anchor.
func (s *GroupState) Root() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[0]
}

// CheckPin returns ErrRollback unless s contains the pinned link at seq.
func (s *GroupState) CheckPin(seq uint64, hash string) error {
	if seq == 0 {
		return nil
	}
	if s.Seq < seq {
		return fmt.Errorf("%w: the server's chain for %s has %d links, this device has seen %d", ErrRollback, s.Group, s.Seq, seq)
	}
	if s.Hashes[seq-1] != hash {
		return fmt.Errorf("%w: link %d of %s differs from the one this device verified", ErrRollback, seq, s.Group)
	}
	return nil
}

// Admin reports whether user is an active admin.
func (s *GroupState) Admin(user string) bool {
	a, ok := s.Admins[user]
	return ok && a.Active
}

// ActiveAdmins returns the active admins sorted by login.
func (s *GroupState) ActiveAdmins() []*GroupAdminState {
	var out []*GroupAdminState
	for _, a := range s.Admins {
		if a.Active {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out
}

// Cred returns an active machine or token.
func (s *GroupState) Cred(id string) (*CredState, bool) {
	c, ok := s.Creds[id]
	if !ok || !c.Active {
		return nil, false
	}
	return c, true
}

// ActiveCreds returns the active machines and tokens of kind ("" for both),
// sorted by name.
func (s *GroupState) ActiveCreds(kind string) []*CredState {
	var out []*CredState
	for _, c := range s.Creds {
		if c.Active && (kind == "" || c.Kind == kind) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Projects returns the projects the group takes keys from, sorted.
func (s *GroupState) Projects() []string {
	out := make([]string, 0, len(s.Access))
	for p := range s.Access {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// NewLink builds and signs the next link as an admin, or as a token.
func (s *GroupState) NewLink(typ string, body any, ctime time.Time, signer string, version, signerSeq uint64, key ed25519.PrivateKey) (*envelope.Envelope, error) {
	l := GroupLink{Group: s.Group, Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, Signer: signer, SignerKey: version, SignerSeq: signerSeq}
	var err error
	if l.Body, err = json.Marshal(body); err != nil {
		return nil, err
	}
	return envelope.New(KindGroupLink, l, key)
}

// Next verifies e as the next link and returns the new state; s is not
// modified.
func (s *GroupState) Next(e *envelope.Envelope, chains Chains) (*GroupState, error) {
	n := s.clone()
	if err := n.step(e, chains); err != nil {
		return nil, err
	}
	return n, nil
}

// PeekGroupLink decodes a group link without verifying it.
func PeekGroupLink(e *envelope.Envelope) (*GroupLink, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindGroupLink {
		return nil, errors.New("not a group chain link")
	}
	var l GroupLink
	if err := e.Decode(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

// DelegateLink builds the next link for a delegate of an admin to sign;
// the caller adds the delegate's signature.
func (s *GroupState) DelegateLink(typ string, body any, ctime time.Time, signer, delegate string, signerSeq uint64) (*envelope.Envelope, error) {
	l := GroupLink{Group: s.Group, Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, Signer: signer, SignerSeq: signerSeq, SignerDelegate: delegate}
	var err error
	if l.Body, err = json.Marshal(body); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return envelope.NewRaw(KindGroupLink, raw)
}

func (s *GroupState) step(e *envelope.Envelope, chains Chains) error {
	l, err := PeekGroupLink(e)
	if err != nil {
		return err
	}
	if l.Group != s.Group {
		return errors.New("link belongs to another group")
	}
	if l.Seq != s.Seq+1 || l.Prev != s.Head() {
		return errors.New("link is out of sequence")
	}
	if l.CTime.IsZero() {
		return errors.New("link time missing")
	}
	if !s.LastTime.IsZero() && l.CTime.Before(s.LastTime.Add(-time.Hour)) {
		return errors.New("link time goes backwards")
	}
	if err := s.checkSigner(e, l, chains); err != nil {
		return err
	}
	if err := s.apply(*l); err != nil {
		return err
	}
	if len(s.Admins) > MaxGroupAdmins || s.active > MaxGroupCreds || len(s.Access) > MaxGroupProjects {
		return errors.New("the group has too many admins, machines or projects")
	}
	if l.SignerSeq > 0 {
		s.signerSeqs[l.Signer] = l.SignerSeq
	}
	s.Seq = l.Seq
	s.Hashes = append(s.Hashes, e.Hash())
	s.LastTime = l.CTime
	s.Links = append(s.Links, *l)
	return nil
}

// checkSigner checks a link's signature: by a token (for a machine it
// enrolls), an admin's user key, or a delegate of an admin's whose scope
// covers the link.
func (s *GroupState) checkSigner(e *envelope.Envelope, l *GroupLink, chains Chains) error {
	if l.SignerDelegate == "" {
		pub, err := s.signerKey(l, chains)
		if err != nil {
			return err
		}
		return e.Require(KindGroupLink, pub)
	}
	a, ok := s.Admins[l.Signer]
	if !ok || !a.Active || l.SignerKey != 0 || l.Seq == 1 {
		return errors.New("only an admin's delegate signs group links")
	}
	if l.SignerSeq < s.signerSeqs[l.Signer] {
		return fmt.Errorf("%s signed as of an earlier position of their user chain than before", l.Signer)
	}
	d, err := DelegateSigner(chains, l.Signer, a.Root, l.SignerDelegate, l.SignerSeq, l.CTime)
	if err != nil {
		return err
	}
	scope, err := groupScope(*l)
	if err != nil {
		return err
	}
	if !chain.DelegateAllows(d.Scope, scope) {
		return fmt.Errorf("%w: the delegate %s may only sign %s changes", errNotInScope, d.Name, d.Scope)
	}
	return verifyDelegate(e, KindGroupLink, d)
}

// signerKey returns the key a link must be signed with: an enrollment
// token's for a machine it enrolls, otherwise an admin's user key, checked
// like a project chain's signers.
func (s *GroupState) signerKey(l *GroupLink, chains Chains) (ed25519.PublicKey, error) {
	if ValidCredID(l.Signer) == nil {
		t, ok := s.Cred(l.Signer)
		if !ok || t.Kind != KindToken {
			return nil, errors.New("the link is signed by an unknown or removed token")
		}
		if l.Type != GroupMachineAdd || l.SignerKey != 0 || l.SignerSeq != 0 {
			return nil, errors.New("a token can only enroll machines")
		}
		if t.Expired(l.CTime) {
			return nil, errors.New("the token had expired")
		}
		return chain.ParseSignKey(t.SignPub)
	}
	if err := chain.ValidUser(l.Signer); err != nil {
		return nil, err
	}
	var root string
	if l.Seq == 1 {
		if l.Type != GroupInit {
			return nil, errors.New("a group chain must start with an init link")
		}
		var b GroupInitBody
		if err := decodeGroupBody(*l, &b); err != nil {
			return nil, err
		}
		if b.Creator.User != l.Signer {
			return nil, errors.New("the init link must be signed by its creator")
		}
		root = b.Creator.Root
	} else {
		a, ok := s.Admins[l.Signer]
		if !ok || !a.Active {
			return nil, fmt.Errorf("%s is not an admin of the group", l.Signer)
		}
		root = a.Root
	}
	pub, err := SignerKey(chains, l.Signer, root, l.SignerKey, l.SignerSeq)
	if err != nil {
		return nil, err
	}
	if l.SignerSeq < s.signerSeqs[l.Signer] {
		return nil, fmt.Errorf("%s signed as of an earlier position of their user chain than before", l.Signer)
	}
	return pub, nil
}

func (s *GroupState) apply(l GroupLink) error {
	if l.Seq == 1 && l.Type != GroupInit {
		return errors.New("a group chain must start with an init link")
	}
	switch l.Type {
	case GroupInit:
		return s.applyInit(l)
	case GroupAdminAdd:
		return s.applyAdminAdd(l)
	case GroupAdminRemove:
		return s.applyAdminRemove(l)
	case GroupMachineAdd:
		return s.applyMachineAdd(l)
	case GroupTokenAdd:
		var b GroupTokenAddBody
		if err := decodeGroupBody(l, &b); err != nil {
			return err
		}
		return s.addCred(b.Token, KindToken, "", l)
	case GroupRemove:
		return s.applyRemove(l)
	case GroupKeyRotate:
		return s.applyKeyRotate(l)
	case GroupAccessAdd, GroupAccessRemove:
		return s.applyAccess(l)
	}
	return fmt.Errorf("unknown link type %q", l.Type)
}

func (s *GroupState) applyMachineAdd(l GroupLink) error {
	var b GroupMachineAddBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if b.Join != "" && !joinPattern.MatchString(b.Join) {
		return errors.New("invalid join request id")
	}
	if t, ok := s.Cred(l.Signer); ok && !sameOIDC(t.OIDC, b.Machine.OIDC) {
		return errors.New("a machine a token enrolls has the token's OIDC policy")
	}
	return s.addCred(b.Machine, KindMachine, b.Join, l)
}

func (s *GroupState) applyKeyRotate(l GroupLink) error {
	var b GroupKeyRotateBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	if b.Key.Version != s.Key.Version+1 {
		return errors.New("the group key version must go up by one")
	}
	return s.setKey(b.Key, l)
}

func (s *GroupState) applyAccess(l GroupLink) error {
	if l.Type == GroupAccessRemove {
		var b GroupAccessRemoveBody
		if err := decodeGroupBody(l, &b); err != nil {
			return err
		}
		if _, ok := s.Access[b.Project]; !ok {
			return fmt.Errorf("the group does not take keys from %s", b.Project)
		}
		delete(s.Access, b.Project)
		return nil
	}
	var b GroupAccessBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := ValidProject(b.Project); err != nil {
		return err
	}
	if !rootPattern.MatchString(b.Root) {
		return errors.New("invalid project root")
	}
	if _, ok := s.Access[b.Project]; ok {
		return fmt.Errorf("the group already takes keys from %s", b.Project)
	}
	s.Access[b.Project] = b.Root
	return nil
}

func (s *GroupState) applyInit(l GroupLink) error {
	if l.Seq != 1 {
		return errors.New("init link after the start of the chain")
	}
	var b GroupInitBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := validPerson(b.Creator); err != nil {
		return err
	}
	if b.Key.Version != 1 {
		return errors.New("the first group key is version 1")
	}
	if err := s.setKey(b.Key, l); err != nil {
		return err
	}
	s.Admins[b.Creator.User] = &GroupAdminState{Person: b.Creator, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq}
	return nil
}

func (s *GroupState) applyAdminAdd(l GroupLink) error {
	var b GroupAdminAddBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := validPerson(b.Admin); err != nil {
		return err
	}
	if b.Verified != VerifiedGitHubSSH && b.Verified != VerifiedAccountKey {
		return fmt.Errorf("unknown verification %q", b.Verified)
	}
	if s.Admin(b.Admin.User) {
		return fmt.Errorf("%s is already an admin", b.Admin.Login)
	}
	s.Admins[b.Admin.User] = &GroupAdminState{Person: b.Admin, Active: true, Verified: b.Verified, AddedBy: l.Signer, AddedSeq: l.Seq}
	return nil
}

func (s *GroupState) applyAdminRemove(l GroupLink) error {
	var b GroupAdminRemoveBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	a, ok := s.Admins[b.User]
	if !ok || !a.Active {
		return fmt.Errorf("%s is not an admin", b.User)
	}
	if len(s.ActiveAdmins()) == 1 {
		return errors.New("a group needs at least one admin")
	}
	a.Active, a.RemovedSeq, a.RemovedTime = false, l.Seq, l.CTime
	// A former admin may hold the group key.
	s.KeyExposed = append(s.KeyExposed, Exposure{Holder: a.User, Name: a.Login, Seq: l.Seq, Time: l.CTime, Reason: "admin removed"})
	return nil
}

func (s *GroupState) addCred(c Credential, kind, join string, l GroupLink) error {
	if err := ValidCredID(c.ID); err != nil {
		return err
	}
	if (kind == KindMachine) != strings.HasPrefix(c.ID, "m_") {
		return errors.New("machine ids start with m_, token ids with t_")
	}
	if err := chain.ValidDeviceName(c.Name); err != nil {
		return errors.New("a name is 1-64 letters, digits, spaces or ._()'- characters")
	}
	if _, err := chain.ParseKey32(c.EncPub); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if _, err := chain.ParseSignKey(c.SignPub); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if c.Created.IsZero() {
		return errors.New("creation time missing")
	}
	if kind == KindMachine && !c.Expires.IsZero() {
		return errors.New("only tokens expire")
	}
	if c.OIDC != nil {
		if err := c.OIDC.Validate(); err != nil {
			return err
		}
	}
	if _, exists := s.Creds[c.ID]; exists {
		return errors.New("id reused")
	}
	for _, o := range s.Creds {
		if o.SignPub == c.SignPub || o.EncPub == c.EncPub {
			return errors.New("keys reused")
		}
	}
	if c.EncPub == s.Key.EncPub || s.retired[c.EncPub] {
		return errors.New("keys reused")
	}
	s.Creds[c.ID] = &CredState{Credential: c, Kind: kind, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq, AddedTime: l.CTime, Join: join}
	s.active++
	return nil
}

func (s *GroupState) applyRemove(l GroupLink) error {
	var b GroupRemoveBody
	if err := decodeGroupBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	c, ok := s.Cred(b.ID)
	if !ok {
		return fmt.Errorf("%s is not an active machine or token of the group", b.ID)
	}
	c.Active, c.RemovedSeq, c.RemovedTime, c.Destroyed, c.Reason = false, l.Seq, l.CTime, b.Destroyed, b.Reason
	s.active--
	if !b.Destroyed {
		s.KeyExposed = append(s.KeyExposed, Exposure{Holder: c.ID, Name: c.Name, Seq: l.Seq, Time: l.CTime, Reason: c.Kind + " removed"})
	}
	return nil
}

func (s *GroupState) setKey(k GroupKey, l GroupLink) error {
	if _, err := chain.ParseKey32(k.EncPub); err != nil || strings.ToLower(k.EncPub) != k.EncPub {
		return errors.New("invalid group key")
	}
	if s.retired[k.EncPub] || k.EncPub == s.Key.EncPub {
		return errors.New("the group key was already used")
	}
	for _, c := range s.Creds {
		if c.EncPub == k.EncPub {
			return errors.New("the group key was already used")
		}
	}
	if s.Key.EncPub != "" {
		s.retired[s.Key.EncPub] = true
	}
	s.Key, s.KeySince, s.KeyExposed = k, l.CTime, nil
	return nil
}

func sameOIDC(a, b *OIDCPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Provider == b.Provider && a.Repository == b.Repository && a.RepositoryID == b.RepositoryID && slices.Equal(a.Refs, b.Refs) && slices.Equal(a.Environments, b.Environments)
}

func decodeGroupBody(l GroupLink, v any) error {
	if err := envelope.DecodeStrict(l.Body, v); err != nil {
		return fmt.Errorf("invalid %s body: %w", l.Type, err)
	}
	return nil
}

func (s *GroupState) clone() *GroupState {
	n := *s
	n.Hashes = append([]string(nil), s.Hashes...)
	n.Links = append([]GroupLink(nil), s.Links...)
	n.KeyExposed = append([]Exposure(nil), s.KeyExposed...)
	n.Admins = make(map[string]*GroupAdminState, len(s.Admins))
	for k, v := range s.Admins {
		c := *v
		n.Admins[k] = &c
	}
	n.Creds = make(map[string]*CredState, len(s.Creds))
	for k, v := range s.Creds {
		c := *v
		n.Creds[k] = &c
	}
	n.Access = make(map[string]string, len(s.Access))
	for k, v := range s.Access {
		n.Access[k] = v
	}
	n.retired = make(map[string]bool, len(s.retired))
	for k, v := range s.retired {
		n.retired[k] = v
	}
	n.signerSeqs = make(map[string]uint64, len(s.signerSeqs))
	for k, v := range s.signerSeqs {
		n.signerSeqs[k] = v
	}
	return &n
}

// GroupExposures lists, by environment, the group's machines and tokens that
// were removed (and not destroyed) after the project's current key of an
// environment the group reads was set: they may still hold that key.
func GroupExposures(ps *State, gs *GroupState) map[string][]Exposure {
	g, ok := ps.Groups[gs.Group]
	if !ok || !g.Active || g.Root != gs.Root() {
		return nil
	}
	out := map[string][]Exposure{}
	for _, env := range g.Envs {
		e, ok := ps.Envs[env]
		if !ok {
			continue
		}
		granted := g.EnvSince[env]
		exposed := func(t time.Time) bool { return !t.Before(e.Since) && !t.Before(granted) }
		for _, c := range gs.Creds {
			if !c.Active && !c.Destroyed && exposed(c.RemovedTime) {
				out[env] = append(out[env], Exposure{Holder: c.ID, Name: gs.Group + " " + c.Name, Seq: c.RemovedSeq, Time: c.RemovedTime, Reason: c.Kind + " removed from the group"})
			}
		}
		// A former admin held the group key too.
		for _, a := range gs.Admins {
			if !a.Active && exposed(a.RemovedTime) {
				out[env] = append(out[env], Exposure{Holder: a.User, Name: gs.Group + " admin " + a.Login, Seq: a.RemovedSeq, Time: a.RemovedTime, Reason: "admin removed from the group"})
			}
		}
	}
	return out
}

// ---- group key grants ----

// KeyGrant carries the group's private key to a machine, token or admin,
// sealed to its key. The key inside is checked against the group key the
// chain names, so whoever made the grant cannot hand out another key.
type KeyGrant struct {
	Group   string `json:"group"`
	Version uint64 `json:"version"`
	EncPub  string `json:"enc_pub"`
	// From is an admin's user id (FromKey their user key version) or, for a
	// machine it enrolls, a token's id.
	From    string `json:"from"`
	FromKey uint64 `json:"from_ukey_version,omitempty"`
	// To is a machine or token id, or an admin's user id; ToKey is the
	// admin's user key version and ToEncPub the key the box is sealed to.
	To       string    `json:"to"`
	ToKey    uint64    `json:"to_ukey_version,omitempty"`
	ToEncPub string    `json:"to_enc_pub"`
	CTime    time.Time `json:"ctime"`
	Box      []byte    `json:"box"`
}

type keyPayload struct {
	Group   string `json:"group"`
	To      string `json:"to"`
	Version uint64 `json:"version"`
	Key     string `json:"key"`
}

// NewKeyGrant seals the group's current private key to to.
func NewKeyGrant(gs *GroupState, from string, fromVersion uint64, sign ed25519.PrivateKey, to Recipient, priv [32]byte, now time.Time) (*envelope.Envelope, error) {
	pub := identity.PublicFromPrivate(priv)
	if hex.EncodeToString(pub[:]) != gs.Key.EncPub {
		return nil, errors.New("that is not the group's current key")
	}
	plain, err := json.Marshal(keyPayload{Group: gs.Group, To: to.ID, Version: gs.Key.Version, Key: hex.EncodeToString(priv[:])})
	if err != nil {
		return nil, err
	}
	g := KeyGrant{Group: gs.Group, Version: gs.Key.Version, EncPub: gs.Key.EncPub, From: from, FromKey: fromVersion, To: to.ID, ToKey: to.Version, ToEncPub: hex.EncodeToString(to.EncPub[:]), CTime: now.UTC().Truncate(time.Second)}
	if g.Box, err = crypto.SealAnonymous(plain, &to.EncPub); err != nil {
		return nil, err
	}
	return envelope.New(KindGroupKey, g, sign)
}

// PeekKeyGrant decodes a key grant without verifying it.
func PeekKeyGrant(e *envelope.Envelope) (*KeyGrant, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindGroupKey {
		return nil, errors.New("not a group key grant")
	}
	var g KeyGrant
	if err := e.Decode(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

// CheckKeyGrant verifies a key grant against the verified group state:
// signed by an admin (with any user key they had) or an active token, for
// the current group key, to an active machine or token at the key the chain
// names, or to an admin. It returns ErrStale (wrapped) for an earlier key.
func CheckKeyGrant(e *envelope.Envelope, gs *GroupState, chains Chains) (*KeyGrant, error) {
	g, err := PeekKeyGrant(e)
	if err != nil {
		return nil, err
	}
	if g.Group != gs.Group {
		return nil, errors.New("the key grant is for another group")
	}
	if g.CTime.IsZero() || len(g.Box) == 0 {
		return nil, errors.New("incomplete key grant")
	}
	if g.Version != gs.Key.Version || g.EncPub != gs.Key.EncPub {
		return nil, fmt.Errorf("%w: the group has a new key since", ErrStale)
	}
	pub, err := keyGrantSigner(g, gs, chains)
	if err != nil {
		return nil, err
	}
	if err := e.Require(KindGroupKey, pub); err != nil {
		return nil, err
	}
	if c, ok := gs.Cred(g.To); ok {
		if g.ToKey != 0 || g.ToEncPub != c.EncPub {
			return nil, errors.New("the key grant is not sealed to that machine's key")
		}
		return g, nil
	}
	if !gs.Admin(g.To) {
		return nil, fmt.Errorf("%w: %s is no longer in the group", ErrStale, g.To)
	}
	if _, err := chain.ParseKey32(g.ToEncPub); err != nil {
		return nil, errors.New("invalid recipient key")
	}
	return g, nil
}

// keyGrantSigner returns the key a key grant must be signed with: an
// active token's, or any user key an active admin had (the grant can carry
// only the key the chain names, to members of the group).
func keyGrantSigner(g *KeyGrant, gs *GroupState, chains Chains) (ed25519.PublicKey, error) {
	if t, ok := gs.Cred(g.From); ok && t.Kind == KindToken && g.FromKey == 0 {
		return chain.ParseSignKey(t.SignPub)
	}
	a, ok := gs.Admins[g.From]
	if !ok || !a.Active {
		return nil, fmt.Errorf("%w: %s is not an admin of %s", ErrStale, g.From, gs.Group)
	}
	cs, err := chains(g.From)
	if err != nil {
		return nil, fmt.Errorf("user chain of %s: %w", g.From, err)
	}
	if cs.Root() != a.Root {
		return nil, fmt.Errorf("the account of %s is not the one the group recorded", g.From)
	}
	ep, ok := cs.Epoch(g.FromKey)
	if !ok {
		return nil, fmt.Errorf("%s has no user key version %d", g.From, g.FromKey)
	}
	return ep.SignPub, nil
}

// OpenKeyGrant verifies a key grant and opens it with the recipient's key.
// It returns the group's private key, checked against the chain.
func OpenKeyGrant(e *envelope.Envelope, gs *GroupState, chains Chains, me Recipient, priv [32]byte) ([32]byte, error) {
	var none [32]byte
	g, err := CheckKeyGrant(e, gs, chains)
	if err != nil {
		return none, err
	}
	if g.To != me.ID {
		return none, errors.New("the key grant is for someone else")
	}
	if g.ToKey != me.Version || g.ToEncPub != hex.EncodeToString(me.EncPub[:]) {
		return none, fmt.Errorf("%w: it was sealed to an earlier key", ErrStale)
	}
	plain, err := crypto.OpenAnonymous(g.Box, &me.EncPub, &priv)
	if err != nil {
		return none, errors.New("the key grant does not open with this key")
	}
	var p keyPayload
	if err := envelope.DecodeStrict(plain, &p); err != nil {
		return none, fmt.Errorf("invalid key grant content: %w", err)
	}
	if p.Group != g.Group || p.To != g.To || p.Version != g.Version {
		return none, errors.New("the key grant's content does not match it")
	}
	k, err := chain.ParseKey32(p.Key)
	if err != nil {
		return none, errors.New("invalid group key in the grant")
	}
	pub := identity.PublicFromPrivate(k)
	if hex.EncodeToString(pub[:]) != gs.Key.EncPub {
		return none, errors.New("the key in the grant is not the group's key")
	}
	return k, nil
}

// NewGroupKey creates a group key pair.
func NewGroupKey(version uint64) (GroupKey, [32]byte, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return GroupKey{}, [32]byte{}, err
	}
	return GroupKey{Version: version, EncPub: hex.EncodeToString(pub[:])}, *priv, nil
}

// ---- credentials ----

// CredPrefix starts every group credential, so secret scanners find one.
const CredPrefix = "esecg1_"

// CredKey is the private side of a machine or token of a group: what a
// host keeps in its key file, or a CI job or app holds as a secret.
type CredKey struct {
	Server string `json:"server"`
	Group  string `json:"group"`
	// Root is the hash of the group chain's first link: the credential
	// verifies the group, and through it every project, from it.
	Root     string `json:"root"`
	ID       string `json:"id"`
	EncPriv  []byte `json:"enc"`
	SignSeed []byte `json:"sign"`
}

// NewCredKey creates the keys of a machine (kind KindMachine) or token.
func NewCredKey(server, group, root, kind, name string, now time.Time) (*CredKey, Credential, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Credential{}, err
	}
	signPub, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Credential{}, err
	}
	idBytes := make([]byte, 15)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, Credential{}, err
	}
	prefix := "m_"
	if kind == KindToken {
		prefix = "t_"
	}
	id := prefix + base32Lower(idBytes)
	k := &CredKey{Server: server, Group: group, Root: root, ID: id, EncPriv: priv[:], SignSeed: sign.Seed()}
	c := Credential{ID: id, Name: name, EncPub: hex.EncodeToString(pub[:]), SignPub: hex.EncodeToString(signPub), Created: now.UTC().Truncate(time.Second)}
	return k, c, nil
}

// String encodes k as one string.
func (k *CredKey) String() string {
	raw, err := json.Marshal(k)
	if err != nil {
		panic(err) // strings and byte slices always marshal
	}
	return CredPrefix + b64(raw)
}

// ParseCredKey decodes a group credential.
func ParseCredKey(s string) (*CredKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), CredPrefix)
	if !ok {
		return nil, errors.New("not an esec vault group key (it starts with " + CredPrefix + ")")
	}
	raw, err := unb64(rest)
	if err != nil {
		return nil, errors.New("the group key is damaged")
	}
	var k CredKey
	if err := envelope.DecodeStrict(raw, &k); err != nil {
		return nil, errors.New("the group key is damaged")
	}
	if err := ValidGroup(k.Group); err != nil {
		return nil, err
	}
	if ValidCredID(k.ID) != nil || !rootPattern.MatchString(k.Root) || len(k.EncPriv) != 32 || len(k.SignSeed) != ed25519.SeedSize || k.Server == "" {
		return nil, errors.New("the group key is damaged")
	}
	return &k, nil
}

// Kind returns KindMachine or KindToken.
func (k *CredKey) Kind() string {
	if strings.HasPrefix(k.ID, "t_") {
		return KindToken
	}
	return KindMachine
}

// Sign returns the credential's signing key.
func (k *CredKey) Sign() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(k.SignSeed) }

// Keys returns the credential's X25519 keypair.
func (k *CredKey) Keys() (pub, priv [32]byte) {
	copy(priv[:], k.EncPriv)
	return identity.PublicFromPrivate(priv), priv
}

// Public returns the credential's public description, for a machine that
// asks to join.
func (k *CredKey) Public(name string, now time.Time) Credential {
	pub, _ := k.Keys()
	signPub, _ := k.Sign().Public().(ed25519.PublicKey)
	return Credential{ID: k.ID, Name: name, EncPub: hex.EncodeToString(pub[:]), SignPub: hex.EncodeToString(signPub), Created: now.UTC().Truncate(time.Second)}
}

// Matches reports whether c describes this key.
func (k *CredKey) Matches(c Credential) bool {
	pub, _ := k.Keys()
	signPub, _ := k.Sign().Public().(ed25519.PublicKey)
	return c.ID == k.ID && c.EncPub == hex.EncodeToString(pub[:]) && c.SignPub == hex.EncodeToString(signPub)
}

// GroupKeysMessage is what a credential signs to fetch its keys.
func GroupKeysMessage(group, id string, timestamp int64, nonce, oidcTokenHash string) []byte {
	return []byte(fmt.Sprintf("esec-vault group-keys v1\n%s\n%s\n%d\n%s\n%s", group, id, timestamp, nonce, oidcTokenHash))
}

// JoinMessage is what a machine signs to ask to join a group, or to ask
// whether it was let in.
func JoinMessage(action, group string, c Credential, timestamp int64, nonce string) []byte {
	return []byte(fmt.Sprintf("esec-vault group-join v1\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%s", action, group, c.ID, c.Name, c.EncPub, c.SignPub, timestamp, nonce))
}

var joinPattern = regexp.MustCompile(`^j_[a-z0-9]{16,40}$`)

// ValidJoinID checks a join request id.
func ValidJoinID(id string) error {
	if !joinPattern.MatchString(id) {
		return errors.New("invalid join request id")
	}
	return nil
}

// GroupWords are the fingerprint of a group: its id and the hash of its
// chain's first link, as 8 words (88 bits, like an account key, since a
// forger may search offline for a chain that matches). A machine that
// joins with them cannot be put in a look-alike group by the server.
func GroupWords(group, root string) string {
	return fpwords.Words(fpwords.AccountWords, "esec-vault group v1", []byte(group), []byte(root))
}

// JoinWords are the words a joining machine shows and its approver
// compares: a fingerprint of the group's root and the machine's keys, so a
// server that swaps either gets different words. They cover 66 bits, for a
// comparison made while the machine waits.
func JoinWords(group, root string, c Credential) string {
	return fpwords.Words(fpwords.DeviceWords, "esec-vault group-join v1", []byte(group), []byte(root), []byte(c.ID), []byte(c.Name), []byte(c.EncPub), []byte(c.SignPub))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
