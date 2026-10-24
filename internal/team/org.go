package team

// Organisations. An organisation (the "acme" of acme/api and
// acme/production) may have its own signed chain, like a group's: its
// admins and members (the roster), the KMS keys its admins approved for
// workloads, and its settings. Devices verify it from its first link and pin
// it. It says three things the chains of projects and groups cannot:
//
//   - who belongs to acme: someone removed from it is taken out of every
//     project and group of acme by the devices of their admins;
//   - which KMS keys may wrap a group key of acme: a device adds a workload
//     only with an approved key, so a server cannot slip in a key of its own;
//   - acme's rules, which devices check when they sign, and the server when
//     it stores links.
//
// Once acme has a chain, the server lets only its people create projects
// and groups named acme/..., and devices tell people whether the creator of
// a project they are added to belongs to acme.

import (
	"crypto/ed25519"
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
	"github.com/mscno/esec-vault/internal/fpwords"
	"github.com/mscno/esec-vault/internal/kms"
)

// KindOrgLink is the envelope kind of an organisation chain's links.
const KindOrgLink = "org-link"

// Organisation link types.
const (
	OrgInit         = "init"
	OrgAdminAdd     = "admin_add"
	OrgAdminRemove  = "admin_remove"
	OrgMemberAdd    = "member_add"
	OrgMemberRemove = "member_remove"
	// OrgKMSAdd approves a KMS key for the workloads of the organisation's
	// groups; OrgKMSRemove withdraws it.
	OrgKMSAdd    = "kms_add"
	OrgKMSRemove = "kms_remove"
	// OrgSettingsSet replaces the organisation's settings.
	OrgSettingsSet = "settings"
)

// Bounds of an organisation.
const (
	MaxOrgAdmins  = 50
	MaxOrgMembers = 2000
	MaxOrgKMS     = 500
	// MaxOrgDays bounds the day counts of the settings.
	MaxOrgDays = 3660
)

var kmsLabelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidOrg checks an organisation name: the first part of a project id, in
// lower case.
func ValidOrg(org string) error {
	if org == "" || org != strings.ToLower(org) || projectfile.ValidateOrgRepo(org+"/x") != nil {
		return fmt.Errorf("invalid organisation %q: use the lower-case first part of your project ids, such as acme", org)
	}
	return nil
}

// OrgOf returns the organisation of a project or group id, in lower case.
func OrgOf(id string) string {
	org, _, _ := strings.Cut(id, "/")
	return strings.ToLower(org)
}

// ValidKMSLabel checks the name an organisation gives a KMS key.
func ValidKMSLabel(name string) error {
	if !kmsLabelPattern.MatchString(name) {
		return fmt.Errorf("invalid key name %q: 1-63 lower-case letters, digits and ._-", name)
	}
	return nil
}

// OrgLink is the signed body of an org-link envelope. Signer is an admin's
// user id (or a member's, leaving), signing with their user key like in a
// group chain, or through a delegate (SignerDelegate; SignerKey is then 0).
type OrgLink struct {
	Org            string          `json:"org"`
	Seq            uint64          `json:"seq"`
	Prev           string          `json:"prev"`
	CTime          time.Time       `json:"ctime"`
	Type           string          `json:"type"`
	Signer         string          `json:"signer"`
	SignerKey      uint64          `json:"signer_ukey_version"`
	SignerSeq      uint64          `json:"signer_seq"`
	SignerDelegate string          `json:"signer_delegate,omitempty"`
	Body           json.RawMessage `json:"body"`
}

// OrgSettings are an organisation's rules and defaults. Devices check the
// rules when they sign; the server when it stores links.
type OrgSettings struct {
	// RequireGitHubProof refuses people added with account key words
	// instead of a GitHub SSH proof, in the organisation and its projects
	// and groups.
	RequireGitHubProof bool `json:"require_github_proof,omitempty"`
	// MembersOnly lets only the organisation's people into its projects and
	// groups.
	MembersOnly bool `json:"members_only,omitempty"`
	// MaxTokenDays bounds the lifetime of the groups' enrollment tokens,
	// and refuses tokens that never expire; 0 sets no bound.
	MaxTokenDays int `json:"max_token_days,omitempty"`
	// NoServerSigning keeps the server from signing removals made on the
	// web pages; passkeys and devices sign them instead.
	NoServerSigning bool `json:"no_server_signing,omitempty"`
	// ReviewDays asks each project's admins to review who reads it every so
	// many days; 0 never.
	ReviewDays int `json:"review_days,omitempty"`
	// FlyOrg is the Fly.io organisation new workloads run in, by default.
	FlyOrg string `json:"fly_org,omitempty"`
	// DefaultKMS names the approved key new workloads use, by default.
	DefaultKMS string `json:"default_kms,omitempty"`
}

// OrgKMSKey is a KMS key an organisation approved for its workloads.
type OrgKMSKey struct {
	// Name is the organisation's name for it, such as gcp-prod or fly-api.
	Name string  `json:"name"`
	Key  kms.Key `json:"key"`
	// Groups, when set, are the only groups whose workloads may use it,
	// such as the one group of the one app a per-app key is for.
	Groups []string `json:"groups,omitempty"`
}

// Organisation link bodies.
type (
	// OrgInitBody creates an organisation; the creator is its first admin.
	OrgInitBody struct {
		Creator Person `json:"creator"`
	}
	// OrgAdminAddBody adds an admin.
	OrgAdminAddBody struct {
		Admin    Person `json:"admin"`
		Verified string `json:"verified"`
	}
	// OrgAdminRemoveBody removes an admin, who leaves the organisation.
	OrgAdminRemoveBody struct {
		User   string `json:"user"`
		Reason string `json:"reason,omitempty"`
	}
	// OrgMemberAddBody adds a member.
	OrgMemberAddBody struct {
		Member   Person `json:"member"`
		Verified string `json:"verified"`
	}
	// OrgMemberRemoveBody removes a member; a member may remove themselves.
	// KeepAdminRoles leaves them admin of the projects and groups they
	// administer: a removal signed unasked (changes --yes) takes away only
	// what is not an admin's.
	OrgMemberRemoveBody struct {
		User           string `json:"user"`
		Reason         string `json:"reason,omitempty"`
		KeepAdminRoles bool   `json:"keep_admin_roles,omitempty"`
	}
	// OrgKMSAddBody approves a KMS key.
	OrgKMSAddBody struct {
		Key OrgKMSKey `json:"key"`
	}
	// OrgKMSRemoveBody withdraws a KMS key: no new workload uses it.
	OrgKMSRemoveBody struct {
		Name   string `json:"name"`
		Reason string `json:"reason,omitempty"`
	}
	// OrgSettingsBody replaces the settings.
	OrgSettingsBody struct {
		Settings OrgSettings `json:"settings"`
	}
)

// OrgKMSState is an approved key as the verified chain sees it.
type OrgKMSState struct {
	OrgKMSKey

	Active      bool      `json:"active"`
	AddedBy     string    `json:"added_by"`
	AddedSeq    uint64    `json:"added_seq"`
	AddedTime   time.Time `json:"added_time"`
	RemovedSeq  uint64    `json:"removed_seq,omitempty"`
	RemovedTime time.Time `json:"removed_time,omitzero"`
}

// OrgState is the result of verifying an organisation chain.
type OrgState struct {
	Org      string
	Seq      uint64
	Hashes   []string
	LastTime time.Time
	Links    []OrgLink
	// Admins manage the organisation; Members belong to it. An admin is
	// not also a member.
	Admins  map[string]*GroupAdminState
	Members map[string]*GroupAdminState
	// KMS are the approved keys by name; Removed ones stay, inactive.
	KMS map[string]*OrgKMSState
	// Settings, and who set them when.
	Settings     OrgSettings
	SettingsBy   string
	SettingsTime time.Time
	signerSeqs   map[string]uint64
}

// NewOrg returns the empty state of an organisation.
func NewOrg(org string) *OrgState {
	return &OrgState{Org: org, Admins: map[string]*GroupAdminState{}, Members: map[string]*GroupAdminState{}, KMS: map[string]*OrgKMSState{}, signerSeqs: map[string]uint64{}}
}

// VerifyOrg checks a complete organisation chain from its first link.
func VerifyOrg(org string, links []*envelope.Envelope, chains Chains) (*OrgState, error) {
	if err := ValidOrg(org); err != nil {
		return nil, err
	}
	if len(links) > MaxLinks {
		return nil, errors.New("organisation chain too long")
	}
	s := NewOrg(org)
	for i, e := range links {
		if err := s.step(e, chains); err != nil {
			return nil, fmt.Errorf("organisation chain link %d: %w", i+1, err)
		}
	}
	return s, nil
}

// Head returns the hash of the last link, or "".
func (s *OrgState) Head() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[len(s.Hashes)-1]
}

// Root returns the hash of the first link.
func (s *OrgState) Root() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[0]
}

// CheckPin returns ErrRollback unless s contains the pinned link at seq.
func (s *OrgState) CheckPin(seq uint64, hash string) error {
	if seq == 0 {
		return nil
	}
	if s.Seq < seq {
		return fmt.Errorf("%w: the server's chain for the organisation %s has %d links, this device has seen %d", ErrRollback, s.Org, s.Seq, seq)
	}
	if s.Hashes[seq-1] != hash {
		return fmt.Errorf("%w: link %d of the organisation %s differs from the one this device verified", ErrRollback, seq, s.Org)
	}
	return nil
}

// Words are the organisation's fingerprint: its name and first link.
func (s *OrgState) Words() string { return OrgWords(s.Org, s.Root()) }

// OrgWords are the fingerprint of an organisation chain, as 8 words.
func OrgWords(org, root string) string {
	return fpwords.Words(fpwords.AccountWords, "esec-vault org v1", []byte(org), []byte(root))
}

// Admin reports whether user is an active admin.
func (s *OrgState) Admin(user string) bool {
	a, ok := s.Admins[user]
	return ok && a.Active
}

// Member reports whether user is an active member (not counting admins).
func (s *OrgState) Member(user string) bool {
	m, ok := s.Members[user]
	return ok && m.Active
}

// In reports whether user belongs to the organisation: an admin or member.
func (s *OrgState) In(user string) bool { return s.Admin(user) || s.Member(user) }

// Person returns an active admin or member.
func (s *OrgState) Person(user string) (*GroupAdminState, bool) {
	if a, ok := s.Admins[user]; ok && a.Active {
		return a, true
	}
	if m, ok := s.Members[user]; ok && m.Active {
		return m, true
	}
	return nil, false
}

// PersonByLogin returns an active admin or member by GitHub login.
func (s *OrgState) PersonByLogin(login string) (*GroupAdminState, bool) {
	for _, p := range s.People() {
		if strings.EqualFold(p.Login, login) {
			return p, true
		}
	}
	return nil, false
}

// People returns the active admins and members, sorted by login.
func (s *OrgState) People() []*GroupAdminState {
	out := activePeople(s.Admins)
	out = append(out, activePeople(s.Members)...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out
}

// ActiveAdmins returns the active admins sorted by login.
func (s *OrgState) ActiveAdmins() []*GroupAdminState { return activePeople(s.Admins) }

// Left reports whether user is no longer in the organisation, having been
// in it, and when they were last removed. Someone removed from the
// organisation is taken out of what they read in it before that time.
func (s *OrgState) Left(user string) (time.Time, bool) {
	if s.In(user) {
		return time.Time{}, false
	}
	var last time.Time
	for _, m := range []map[string]*GroupAdminState{s.Admins, s.Members} {
		if p, ok := m[user]; ok && p.RemovedTime.After(last) {
			last = p.RemovedTime
		}
	}
	return last, !last.IsZero()
}

// KeepsAdminRoles reports whether the link that took user out of the
// organisation leaves their admin roles in its projects and groups: one a
// delegate signed (a passkey, or the server), or one that says so.
func (s *OrgState) KeepsAdminRoles(user string) bool {
	var seq uint64
	for _, m := range []map[string]*GroupAdminState{s.Admins, s.Members} {
		if p, ok := m[user]; ok && !p.Active && p.RemovedSeq > seq {
			seq = p.RemovedSeq
		}
	}
	if seq == 0 {
		return false
	}
	l := s.Links[seq-1]
	if l.SignerDelegate != "" {
		return true
	}
	var b OrgMemberRemoveBody
	return l.Type == OrgMemberRemove && decodeOrgBody(l, &b) == nil && b.KeepAdminRoles
}

// SignedWithUserKey reports whether user signed a link of the chain with
// their user key version: links of their delegates (a passkey on a page,
// the server) do not count, nor links signed with an earlier user key,
// which a revoked device may still hold.
func (s *OrgState) SignedWithUserKey(user string, version uint64) bool {
	for _, l := range s.Links {
		if l.Signer == user && l.SignerDelegate == "" && l.SignerKey == version {
			return true
		}
	}
	return false
}

// Former returns the people who left the organisation, sorted by login.
func (s *OrgState) Former() []*GroupAdminState {
	seen := map[string]*GroupAdminState{}
	for _, m := range []map[string]*GroupAdminState{s.Admins, s.Members} {
		for u, p := range m {
			if _, left := s.Left(u); left && (seen[u] == nil || p.RemovedTime.After(seen[u].RemovedTime)) {
				seen[u] = p
			}
		}
	}
	out := make([]*GroupAdminState, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out
}

// ActiveKMS returns the approved keys, sorted by name.
func (s *OrgState) ActiveKMS() []*OrgKMSState {
	var out []*OrgKMSState
	for _, k := range s.KMS {
		if k.Active {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// KMSByName returns an approved key by its name.
func (s *OrgState) KMSByName(name string) (*OrgKMSState, bool) {
	k, ok := s.KMS[name]
	return k, ok && k.Active
}

// KMSFor returns the approved key that is k, if any, active or not.
func (s *OrgState) KMSFor(k kms.Key) *OrgKMSState {
	var found *OrgKMSState
	for _, a := range s.KMS {
		if a.Key.Fingerprint() == k.Fingerprint() && a.Key.Audience == k.Audience && a.Key.Principal == k.Principal && (found == nil || a.Active) {
			found = a
		}
	}
	return found
}

// CheckKMS returns nil if the organisation approved k for the workloads of
// group, or says why not.
func (s *OrgState) CheckKMS(k kms.Key, group string) error {
	a := s.KMSFor(k)
	switch {
	case a == nil:
		return fmt.Errorf("the organisation %s has not approved that KMS key (%s %s): an admin of %s approves it with 'esec vault org kms add', or on the organisation's Settings page", s.Org, k.Provider, k.Name, s.Org)
	case !a.Active:
		return fmt.Errorf("the organisation %s withdrew the KMS key %s", s.Org, a.Name)
	case len(a.Groups) > 0 && !slices.Contains(a.Groups, group):
		return fmt.Errorf("the organisation %s approved the KMS key %s only for %s", s.Org, a.Name, strings.Join(a.Groups, ", "))
	}
	return nil
}

// CheckPerson applies the organisation's rules to someone about to be
// added to one of its projects or groups, verified as verified.
func (s *OrgState) CheckPerson(user, login, verified string) error {
	if s.Settings.MembersOnly && !s.In(user) {
		return fmt.Errorf("%s lets only its people into its projects and groups, and %s is not one: an admin of %s adds them first (esec vault org add %s %s)", s.Org, login, s.Org, s.Org, login)
	}
	if s.Settings.RequireGitHubProof && verified == VerifiedAccountKey {
		return fmt.Errorf("%s requires a GitHub SSH proof: %s publishes one with 'esec vault access prove', then add them without --account-key", s.Org, login)
	}
	return nil
}

// CheckToken applies the organisation's token lifetime to a token that
// expires at expires (zero: never), created at now.
func (s *OrgState) CheckToken(expires, now time.Time) error {
	days := s.Settings.MaxTokenDays
	if days == 0 {
		return nil
	}
	if expires.IsZero() || expires.After(now.Add(time.Duration(days)*24*time.Hour+time.Hour)) {
		return fmt.Errorf("%s allows enrollment tokens of at most %d days: use --expires %dd or less", s.Org, days, days)
	}
	return nil
}

// CheckSettings reports whether st would be accepted as the next settings.
func (s *OrgState) CheckSettings(st OrgSettings) error { return s.validSettings(st) }

// NewLink builds and signs the next link.
func (s *OrgState) NewLink(typ string, body any, ctime time.Time, signer string, version, signerSeq uint64, key ed25519.PrivateKey) (*envelope.Envelope, error) {
	l, err := s.nextLink(typ, body, ctime, signer, signerSeq)
	if err != nil {
		return nil, err
	}
	l.SignerKey = version
	return envelope.New(KindOrgLink, l, key)
}

// DelegateLink builds the next link for a delegate of an admin to sign;
// the caller adds the delegate's signature.
func (s *OrgState) DelegateLink(typ string, body any, ctime time.Time, signer, delegate string, signerSeq uint64) (*envelope.Envelope, error) {
	l, err := s.nextLink(typ, body, ctime, signer, signerSeq)
	if err != nil {
		return nil, err
	}
	l.SignerDelegate = delegate
	raw, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return envelope.NewRaw(KindOrgLink, raw)
}

// Next verifies e as the next link and returns the new state; s is not
// modified.
func (s *OrgState) Next(e *envelope.Envelope, chains Chains) (*OrgState, error) {
	n := s.clone()
	if err := n.step(e, chains); err != nil {
		return nil, err
	}
	return n, nil
}

func (s *OrgState) nextLink(typ string, body any, ctime time.Time, signer string, signerSeq uint64) (OrgLink, error) {
	raw, err := json.Marshal(body)
	return OrgLink{Org: s.Org, Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, Signer: signer, SignerSeq: signerSeq, Body: raw}, err
}

// PeekOrgLink decodes an organisation link without verifying it.
func PeekOrgLink(e *envelope.Envelope) (*OrgLink, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindOrgLink {
		return nil, errors.New("not an organisation chain link")
	}
	var l OrgLink
	if err := e.Decode(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *OrgState) step(e *envelope.Envelope, chains Chains) error {
	l, err := PeekOrgLink(e)
	if err != nil {
		return err
	}
	if l.Org != s.Org {
		return errors.New("link belongs to another organisation")
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
	if len(s.Admins) > MaxOrgAdmins || len(s.Members) > MaxOrgMembers || len(s.KMS) > MaxOrgKMS {
		return errors.New("the organisation has too many admins, members or KMS keys")
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

// checkSigner checks a link's signature: an admin's user key, a member's
// (leaving), or a delegate of an admin's whose scope covers the link.
func (s *OrgState) checkSigner(e *envelope.Envelope, l *OrgLink, chains Chains) error {
	if l.SignerDelegate != "" {
		return s.people().delegateUnless(e, KindOrgLink, l.head(), chains, func() (string, error) { return orgScope(*l) }, s.Settings.NoServerSigning)
	}
	var add OrgMemberAddBody
	if l.Type == OrgMemberAdd && decodeOrgBody(*l, &add) == nil && add.Verified == VerifiedWeb {
		return errors.New("only a delegate's link adds a member checked on the web")
	}
	pub, err := s.signerKey(l, chains)
	if err != nil {
		return err
	}
	return e.Require(KindOrgLink, pub)
}

func (s *OrgState) people() chainPeople {
	return chainPeople{admins: s.Admins, members: s.Members, seqs: s.signerSeqs, leave: OrgMemberRemove, what: "organisation"}
}

func (l *OrgLink) head() signedHead {
	return signedHead{Seq: l.Seq, Type: l.Type, Signer: l.Signer, SignerKey: l.SignerKey, SignerSeq: l.SignerSeq, SignerDelegate: l.SignerDelegate, CTime: l.CTime}
}

// orgScope returns the scope a delegate needs to sign l. Approving keys,
// adding admins and the settings are a device's to sign.
func orgScope(l OrgLink) (string, error) {
	switch l.Type {
	case OrgMemberRemove, OrgKMSRemove:
		return chain.ScopeRemove, nil
	case OrgMemberAdd:
		var b OrgMemberAddBody
		if err := decodeOrgBody(l, &b); err != nil {
			return "", err
		}
		if b.Verified == VerifiedWeb {
			return chain.ScopeManage, nil
		}
	}
	return "", fmt.Errorf("%w: %s", errNotInScope, l.Type)
}

func (s *OrgState) signerKey(l *OrgLink, chains Chains) (ed25519.PublicKey, error) {
	var creator *Person
	if l.Seq == 1 {
		if l.Type != OrgInit {
			return nil, errors.New("an organisation chain must start with an init link")
		}
		var b OrgInitBody
		if err := decodeOrgBody(*l, &b); err != nil {
			return nil, err
		}
		creator = &b.Creator
	}
	return s.people().userKey(l.head(), creator, chains)
}

func (s *OrgState) apply(l OrgLink) error {
	if l.Seq == 1 && l.Type != OrgInit {
		return errors.New("an organisation chain must start with an init link")
	}
	switch l.Type {
	case OrgInit:
		if l.Seq != 1 {
			return errors.New("init link after the start of the chain")
		}
		var b OrgInitBody
		if err := decodeOrgBody(l, &b); err != nil {
			return err
		}
		if err := validPerson(b.Creator); err != nil {
			return err
		}
		s.Admins[b.Creator.User] = &GroupAdminState{Person: b.Creator, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq}
		return nil
	case OrgAdminAdd:
		var b OrgAdminAddBody
		if err := decodeOrgBody(l, &b); err != nil {
			return err
		}
		return s.addPerson(b.Admin, b.Verified, true, l)
	case OrgMemberAdd:
		var b OrgMemberAddBody
		if err := decodeOrgBody(l, &b); err != nil {
			return err
		}
		return s.addPerson(b.Member, b.Verified, false, l)
	case OrgAdminRemove, OrgMemberRemove:
		return s.applyRemove(l)
	case OrgKMSAdd:
		var b OrgKMSAddBody
		if err := decodeOrgBody(l, &b); err != nil {
			return err
		}
		return s.addKMS(b.Key, l)
	case OrgKMSRemove:
		return s.applyKMSRemove(l)
	case OrgSettingsSet:
		var b OrgSettingsBody
		if err := decodeOrgBody(l, &b); err != nil {
			return err
		}
		if err := s.validSettings(b.Settings); err != nil {
			return err
		}
		s.Settings, s.SettingsBy, s.SettingsTime = b.Settings, l.Signer, l.CTime
		return nil
	}
	return fmt.Errorf("unknown link type %q", l.Type)
}

func (s *OrgState) applyRemove(l OrgLink) error {
	if l.Type == OrgAdminRemove {
		var b OrgAdminRemoveBody
		if err := decodeOrgBody(l, &b); err != nil {
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
			return errors.New("an organisation needs at least one admin")
		}
		a.Active, a.RemovedSeq, a.RemovedTime = false, l.Seq, l.CTime
		return nil
	}
	var b OrgMemberRemoveBody
	if err := decodeOrgBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	m, ok := s.Members[b.User]
	if !ok || !m.Active {
		return fmt.Errorf("%s is not a member of the organisation", b.User)
	}
	if !s.Admin(l.Signer) && l.Signer != b.User {
		return errors.New("a member can only remove themselves")
	}
	m.Active, m.RemovedSeq, m.RemovedTime = false, l.Seq, l.CTime
	return nil
}

func (s *OrgState) applyKMSRemove(l OrgLink) error {
	var b OrgKMSRemoveBody
	if err := decodeOrgBody(l, &b); err != nil {
		return err
	}
	if err := validReason(b.Reason); err != nil {
		return err
	}
	k, ok := s.KMSByName(b.Name)
	if !ok {
		return fmt.Errorf("the organisation has no key %s", b.Name)
	}
	k.Active, k.RemovedSeq, k.RemovedTime = false, l.Seq, l.CTime
	if s.Settings.DefaultKMS == b.Name {
		s.Settings.DefaultKMS = ""
	}
	return nil
}

func (s *OrgState) addPerson(p Person, verified string, admin bool, l OrgLink) error {
	if err := validPerson(p); err != nil {
		return err
	}
	if verified != VerifiedGitHubSSH && verified != VerifiedAccountKey && (admin || verified != VerifiedWeb) {
		return fmt.Errorf("unknown verification %q", verified)
	}
	if s.Settings.RequireGitHubProof && verified == VerifiedAccountKey {
		return fmt.Errorf("%s requires a GitHub SSH proof", s.Org)
	}
	if s.Admin(p.User) {
		return fmt.Errorf("%s is already an admin", p.Login)
	}
	if m, ok := s.Members[p.User]; ok && m.Active {
		if !admin {
			return fmt.Errorf("%s is already a member", p.Login)
		}
		if m.Root != p.Root {
			return fmt.Errorf("%s's account is not the one the organisation recorded", p.Login)
		}
		// A member who becomes an admin is an admin only.
		m.Active, m.RemovedSeq, m.RemovedTime = false, l.Seq, l.CTime
	}
	st := &GroupAdminState{Person: p, Active: true, Verified: verified, AddedBy: l.Signer, AddedSeq: l.Seq}
	if admin {
		s.Admins[p.User] = st
	} else {
		s.Members[p.User] = st
	}
	return nil
}

func (s *OrgState) addKMS(k OrgKMSKey, l OrgLink) error {
	if err := ValidKMSLabel(k.Name); err != nil {
		return err
	}
	if _, ok := s.KMSByName(k.Name); ok {
		return fmt.Errorf("the organisation has a key %s already", k.Name)
	}
	if err := k.Key.Validate(); err != nil {
		return err
	}
	if a := s.KMSFor(k.Key); a != nil && a.Active {
		return fmt.Errorf("that key is approved already, as %s", a.Name)
	}
	if len(k.Groups) > MaxGroupProjects || !slices.IsSorted(k.Groups) || len(slices.Compact(slices.Clone(k.Groups))) != len(k.Groups) {
		return errors.New("a key's groups are sorted and named once each")
	}
	for _, g := range k.Groups {
		if err := ValidGroup(g); err != nil {
			return err
		}
		if OrgOf(g) != s.Org {
			return fmt.Errorf("%s is not a group of %s", g, s.Org)
		}
	}
	s.KMS[k.Name] = &OrgKMSState{OrgKMSKey: k, Active: true, AddedBy: l.Signer, AddedSeq: l.Seq, AddedTime: l.CTime}
	return nil
}

func (s *OrgState) validSettings(st OrgSettings) error {
	if st.MaxTokenDays < 0 || st.MaxTokenDays > MaxOrgDays || st.ReviewDays < 0 || st.ReviewDays > MaxOrgDays {
		return fmt.Errorf("day counts are 0 to %d", MaxOrgDays)
	}
	if st.FlyOrg != "" && !flyNamePattern.MatchString(st.FlyOrg) {
		return fmt.Errorf("invalid Fly.io organisation %q", st.FlyOrg)
	}
	if st.DefaultKMS != "" {
		if _, ok := s.KMSByName(st.DefaultKMS); !ok {
			return fmt.Errorf("the organisation has no key %s to use by default", st.DefaultKMS)
		}
	}
	return nil
}

func decodeOrgBody(l OrgLink, v any) error {
	if err := envelope.DecodeStrict(l.Body, v); err != nil {
		return fmt.Errorf("invalid %s body: %w", l.Type, err)
	}
	return nil
}

func (s *OrgState) clone() *OrgState {
	n := *s
	n.Hashes = append([]string(nil), s.Hashes...)
	n.Links = append([]OrgLink(nil), s.Links...)
	n.Admins = make(map[string]*GroupAdminState, len(s.Admins))
	for k, v := range s.Admins {
		c := *v
		n.Admins[k] = &c
	}
	n.Members = make(map[string]*GroupAdminState, len(s.Members))
	for k, v := range s.Members {
		c := *v
		n.Members[k] = &c
	}
	n.KMS = make(map[string]*OrgKMSState, len(s.KMS))
	for k, v := range s.KMS {
		c := *v
		c.Groups = slices.Clone(v.Groups)
		n.KMS[k] = &c
	}
	n.signerSeqs = make(map[string]uint64, len(s.signerSeqs))
	for k, v := range s.signerSeqs {
		n.signerSeqs[k] = v
	}
	return &n
}

// DescribeOrgLink says what a link did, for people.
func DescribeOrgLink(s *OrgState, l OrgLink) string {
	login := func(user string) string {
		for _, m := range []map[string]*GroupAdminState{s.Admins, s.Members} {
			if p, ok := m[user]; ok {
				return p.Login
			}
		}
		return user
	}
	var b struct {
		Admin  Person    `json:"admin"`
		Member Person    `json:"member"`
		User   string    `json:"user"`
		Key    OrgKMSKey `json:"key"`
		Name   string    `json:"name"`
	}
	_ = json.Unmarshal(l.Body, &b)
	switch l.Type {
	case OrgInit:
		return "created the organisation"
	case OrgAdminAdd:
		return "made " + b.Admin.Login + " an admin"
	case OrgMemberAdd:
		return "added " + b.Member.Login
	case OrgAdminRemove:
		return "removed the admin " + login(b.User)
	case OrgMemberRemove:
		if b.User == l.Signer {
			return "left the organisation"
		}
		return "removed " + login(b.User)
	case OrgKMSAdd:
		return "approved the KMS key " + b.Key.Name
	case OrgKMSRemove:
		return "withdrew the KMS key " + b.Name
	case OrgSettingsSet:
		return "changed the settings"
	}
	return l.Type
}
