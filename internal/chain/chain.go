// Package chain implements a user's device chain: an append-only, hash-linked
// list of signed links that is the only authority for which user key (U) is
// current and which devices and SSH-agent unlock slots are trusted.
//
// The server stores the chain but is not trusted with it. Every client
// verifies the full chain from the first link, pins the verified head, and
// rejects any chain that is shorter than the pin or forks from it. A link is
// valid only when signed by the user key current at that point, so a server
// that cannot produce such signatures can withhold links but never add a
// device, swap a key, or rewrite history unnoticed.
package chain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/fpwords"
)

// Envelope kinds used by the chain.
const (
	KindLink        = "chain-link"
	KindDeviceProof = "device-proof"
)

// Link types.
const (
	TypeInit            = "init"
	TypeDeviceAdd       = "device_add"
	TypeDeviceRevoke    = "device_revoke"
	TypeDeviceRename    = "device_rename"
	TypeUKeyRotate      = "ukey_rotate"
	TypeAgentSlotAdd    = "agent_slot_add"
	TypeAgentSlotRemove = "agent_slot_remove"
)

// Device addition methods.
const (
	MethodFirst    = "first"
	MethodApproval = "approval"
	MethodRecovery = "recovery"
	MethodSSHAgent = "ssh_agent"
)

// Device statuses in the verified state.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// MaxSlotLifetime bounds an agent unlock slot.
const MaxSlotLifetime = 366 * 24 * time.Hour

// MaxLinks bounds a chain so verification stays cheap.
const MaxLinks = 10000

// ErrRollback is returned when a chain is older than, or forks from, a pin.
var ErrRollback = errors.New("chain rollback or fork detected")

// Link is the signed body of a chain-link envelope.
type Link struct {
	Seq         uint64          `json:"seq"`
	Prev        string          `json:"prev"`
	CTime       time.Time       `json:"ctime"`
	Type        string          `json:"type"`
	User        string          `json:"user"`
	UKeyVersion uint64          `json:"ukey_version"`
	Body        json.RawMessage `json:"body"`
}

// InitBody starts a chain with the first user key.
type InitBody struct {
	EncPub    string `json:"enc_pub"`
	SignPub   string `json:"sign_pub"`
	MasterPub string `json:"master_pub"`
}

// Device describes a device's public identity.
type Device struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	EncPub   string    `json:"enc_pub"`
	SignPub  string    `json:"sign_pub"`
	Created  time.Time `json:"created"`
}

// DeviceProof is signed by a device's own key. It proves the device holds
// the private half and binds it to one user.
type DeviceProof struct {
	User   string `json:"user"`
	Device Device `json:"device"`
}

// DeviceAddBody adds a device.
type DeviceAddBody struct {
	Device     Device            `json:"device"`
	Proof      envelope.Envelope `json:"proof"`
	Method     string            `json:"method"`
	ApprovedBy string            `json:"approved_by,omitempty"`
	Slot       string            `json:"slot,omitempty"`
}

// DeviceRevokeBody revokes a device.
type DeviceRevokeBody struct {
	DeviceID string `json:"device_id"`
	Reason   string `json:"reason,omitempty"`
}

// DeviceRenameBody renames an active device.
type DeviceRenameBody struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
}

// UKeyRotateBody replaces the user key. Devices lists the devices that
// receive the new key; every other active device is revoked.
type UKeyRotateBody struct {
	EncPub  string   `json:"enc_pub"`
	SignPub string   `json:"sign_pub"`
	Devices []string `json:"devices"`
	Reason  string   `json:"reason,omitempty"`
}

// AgentSlotAddBody registers an SSH-agent unlock slot.
type AgentSlotAddBody struct {
	SlotID   string    `json:"slot_id"`
	SSHKeyFP string    `json:"ssh_key_fp"`
	Expires  time.Time `json:"expires"`
}

// AgentSlotRemoveBody disables an SSH-agent unlock slot.
type AgentSlotRemoveBody struct {
	SlotID string `json:"slot_id"`
	Reason string `json:"reason,omitempty"`
}

// DeviceState is a device as seen by the verified chain.
type DeviceState struct {
	Device

	Status     string `json:"status"`
	Method     string `json:"method"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Slot       string `json:"slot,omitempty"`
	AddedSeq   uint64 `json:"added_seq"`
	RevokedSeq uint64 `json:"revoked_seq,omitempty"`
}

// SlotState is an agent unlock slot as seen by the verified chain.
type SlotState struct {
	SlotID      string    `json:"slot_id"`
	SSHKeyFP    string    `json:"ssh_key_fp"`
	Expires     time.Time `json:"expires"`
	UKeyVersion uint64    `json:"ukey_version"`
	Active      bool      `json:"active"`
}

// State is the result of verifying a chain.
type State struct {
	User        string
	Seq         uint64
	Hashes      []string
	LastTime    time.Time
	UKeyVersion uint64
	EncPub      [32]byte
	SignPub     ed25519.PublicKey
	MasterPub   [32]byte
	Devices     map[string]*DeviceState
	Slots       map[string]*SlotState
	// Links holds the decoded links, in order.
	Links []Link
}

var (
	userPattern     = regexp.MustCompile(`^gh:[1-9][0-9]{0,19}$`)
	deviceIDPattern = regexp.MustCompile(`^d_[a-z0-9]{8,40}$`)
	slotIDPattern   = regexp.MustCompile(`^s_[a-z0-9]{8,40}$`)
	platformPattern = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9]{1,16}$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()'-]{0,63}$`)
	sshFPPattern    = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// ValidUser checks a chain user identifier ("gh:<numeric GitHub id>").
func ValidUser(u string) error {
	if !userPattern.MatchString(u) {
		return fmt.Errorf("invalid user id %q", u)
	}
	return nil
}

// ValidDeviceID checks a device identifier.
func ValidDeviceID(id string) error {
	if !deviceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid device id")
	}
	return nil
}

// ValidSlotID checks a slot identifier.
func ValidSlotID(id string) error {
	if !slotIDPattern.MatchString(id) {
		return fmt.Errorf("invalid slot id")
	}
	return nil
}

// ValidDeviceName checks a device name. Names are shown in terminals and
// notifications, so control and escape characters are never allowed.
func ValidDeviceName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("device name must be 1-64 letters, digits, spaces or ._()'- characters")
	}
	return nil
}

// SanitizeName turns an arbitrary string (for example a hostname) into a
// valid device name.
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(" ._()'-", r):
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.TrimLeft(b.String(), " ._()'-")
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		return "device"
	}
	return out
}

// ValidPlatform checks a "goos/goarch" platform string.
func ValidPlatform(p string) error {
	if !platformPattern.MatchString(p) {
		return fmt.Errorf("invalid platform")
	}
	return nil
}

// ValidSSHFingerprint checks an OpenSSH SHA256 key fingerprint.
func ValidSSHFingerprint(fp string) error {
	if !sshFPPattern.MatchString(fp) {
		return fmt.Errorf("invalid SSH key fingerprint")
	}
	return nil
}

// ParseKey32 decodes a hex 32-byte key.
func ParseKey32(s string) ([32]byte, error) {
	var k [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return k, fmt.Errorf("invalid key encoding")
	}
	copy(k[:], raw)
	if k == [32]byte{} {
		return k, fmt.Errorf("invalid all-zero key")
	}
	return k, nil
}

// ParseSignKey decodes a hex Ed25519 public key.
func ParseSignKey(s string) (ed25519.PublicKey, error) {
	k, err := ParseKey32(s)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(k[:]), nil
}

// ValidateDevice checks every field of a device description.
func ValidateDevice(d Device) error {
	if err := ValidDeviceID(d.ID); err != nil {
		return err
	}
	if err := ValidDeviceName(d.Name); err != nil {
		return err
	}
	if err := ValidPlatform(d.Platform); err != nil {
		return err
	}
	if _, err := ParseKey32(d.EncPub); err != nil {
		return fmt.Errorf("device encryption key: %w", err)
	}
	if _, err := ParseSignKey(d.SignPub); err != nil {
		return fmt.Errorf("device signing key: %w", err)
	}
	if d.Created.IsZero() {
		return fmt.Errorf("device creation time missing")
	}
	return nil
}

// VerifyProof checks a device proof envelope and returns its content.
func VerifyProof(proof *envelope.Envelope) (*DeviceProof, error) {
	if err := proof.Check(); err != nil {
		return nil, err
	}
	var p DeviceProof
	if err := proof.Decode(&p); err != nil {
		return nil, err
	}
	if err := ValidUser(p.User); err != nil {
		return nil, err
	}
	if err := ValidateDevice(p.Device); err != nil {
		return nil, err
	}
	pub, err := ParseSignKey(p.Device.SignPub)
	if err != nil {
		return nil, err
	}
	if err := proof.Require(KindDeviceProof, pub); err != nil {
		return nil, err
	}
	return &p, nil
}

// New returns the empty state for user.
func New(user string) *State {
	return &State{User: user, Devices: map[string]*DeviceState{}, Slots: map[string]*SlotState{}}
}

// Verify checks a complete chain from its first link.
func Verify(user string, links []*envelope.Envelope) (*State, error) {
	if err := ValidUser(user); err != nil {
		return nil, err
	}
	if len(links) > MaxLinks {
		return nil, fmt.Errorf("chain too long")
	}
	s := New(user)
	for i, e := range links {
		if err := s.step(e); err != nil {
			return nil, fmt.Errorf("chain link %d: %w", i+1, err)
		}
	}
	return s, nil
}

// Head returns the hash of the last link, or "" for an empty chain.
func (s *State) Head() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[len(s.Hashes)-1]
}

// Root returns the hash of the first link, which identifies the account.
func (s *State) Root() string {
	if len(s.Hashes) == 0 {
		return ""
	}
	return s.Hashes[0]
}

// AccountWords returns the account fingerprint words. They derive from the
// first link, so they stay the same across key rotations and for every
// device of the account.
func (s *State) AccountWords() string {
	if s.Root() == "" {
		return ""
	}
	return fpwords.Words(fpwords.DomainAccount, []byte(s.User), []byte(s.Root()))
}

// CheckPin returns ErrRollback unless s contains the pinned link at seq.
func (s *State) CheckPin(seq uint64, hash string) error {
	if seq == 0 {
		return nil
	}
	if s.Seq < seq {
		return fmt.Errorf("%w: server chain has %d links, this device has seen %d", ErrRollback, s.Seq, seq)
	}
	if s.Hashes[seq-1] != hash {
		return fmt.Errorf("%w: link %d differs from the one this device verified", ErrRollback, seq)
	}
	return nil
}

// ActiveDevices returns active devices sorted by id.
func (s *State) ActiveDevices() []*DeviceState {
	var out []*DeviceState
	for _, d := range s.Devices {
		if d.Status == StatusActive {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ActiveDevice returns the device if it is active.
func (s *State) ActiveDevice(id string) (*DeviceState, bool) {
	d, ok := s.Devices[id]
	if !ok || d.Status != StatusActive {
		return nil, false
	}
	return d, true
}

// UsableSlot returns an active, unexpired slot for the current user key.
func (s *State) UsableSlot(id string, now time.Time) (*SlotState, bool) {
	sl, ok := s.Slots[id]
	if !ok || !sl.Active || !now.Before(sl.Expires) || sl.UKeyVersion != s.UKeyVersion {
		return nil, false
	}
	return sl, true
}

// NewLink builds and signs the next link of type typ with body. For
// ukey_rotate the caller passes both the old and new signing keys.
func (s *State) NewLink(typ string, body any, ctime time.Time, signers ...ed25519.PrivateKey) (*envelope.Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	version := s.UKeyVersion
	switch typ {
	case TypeInit:
		version = 1
	case TypeUKeyRotate:
		version = s.UKeyVersion + 1
	}
	l := Link{Seq: s.Seq + 1, Prev: s.Head(), CTime: ctime.UTC().Truncate(time.Second), Type: typ, User: s.User, UKeyVersion: version, Body: raw}
	return envelope.New(KindLink, l, signers...)
}

// Next verifies e as the next link and returns the resulting state. s is not
// modified.
func (s *State) Next(e *envelope.Envelope) (*State, error) {
	n := s.clone()
	if err := n.step(e); err != nil {
		return nil, err
	}
	return n, nil
}

// step verifies e as the next link and applies it to s in place. On error s
// may be partially modified and must be discarded.
func (s *State) step(e *envelope.Envelope) error {
	if err := e.Check(); err != nil {
		return err
	}
	if e.Kind != KindLink {
		return fmt.Errorf("not a chain link")
	}
	var l Link
	if err := e.Decode(&l); err != nil {
		return err
	}
	if l.User != s.User {
		return fmt.Errorf("link belongs to a different user")
	}
	if l.Seq != s.Seq+1 || l.Prev != s.Head() {
		return fmt.Errorf("link is out of sequence")
	}
	if l.CTime.IsZero() {
		return fmt.Errorf("link time missing")
	}
	if !s.LastTime.IsZero() && l.CTime.Before(s.LastTime.Add(-24*time.Hour)) {
		return fmt.Errorf("link time goes backwards")
	}
	var err error
	if l.Seq == 1 {
		err = s.applyInit(e, l)
	} else {
		err = s.apply(e, l)
	}
	if err != nil {
		return err
	}
	s.Seq = l.Seq
	s.Hashes = append(s.Hashes, e.Hash())
	s.LastTime = l.CTime
	s.Links = append(s.Links, l)
	return nil
}

func (s *State) applyInit(e *envelope.Envelope, l Link) error {
	if l.Type != TypeInit || l.UKeyVersion != 1 {
		return fmt.Errorf("chain must start with an init link for key version 1")
	}
	var b InitBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	enc, err := ParseKey32(b.EncPub)
	if err != nil {
		return err
	}
	sign, err := ParseSignKey(b.SignPub)
	if err != nil {
		return err
	}
	master, err := ParseKey32(b.MasterPub)
	if err != nil {
		return err
	}
	if err := e.Require(KindLink, sign); err != nil {
		return err
	}
	s.UKeyVersion, s.EncPub, s.SignPub, s.MasterPub = 1, enc, sign, master
	return nil
}

func (s *State) apply(e *envelope.Envelope, l Link) error { //nolint:gocyclo // one case per link type
	if l.Type == TypeInit {
		return fmt.Errorf("init link after the start of the chain")
	}
	if l.Type == TypeUKeyRotate {
		return s.applyRotate(e, l)
	}
	if l.UKeyVersion != s.UKeyVersion {
		return fmt.Errorf("link names key version %d, current is %d", l.UKeyVersion, s.UKeyVersion)
	}
	if err := e.Require(KindLink, s.SignPub); err != nil {
		return err
	}
	switch l.Type {
	case TypeDeviceAdd:
		return s.applyDeviceAdd(l)
	case TypeDeviceRevoke:
		var b DeviceRevokeBody
		if err := decodeBody(l, &b); err != nil {
			return err
		}
		d, ok := s.ActiveDevice(b.DeviceID)
		if !ok {
			return fmt.Errorf("revoked device is not active")
		}
		d.Status, d.RevokedSeq = StatusRevoked, l.Seq
		return nil
	case TypeDeviceRename:
		var b DeviceRenameBody
		if err := decodeBody(l, &b); err != nil {
			return err
		}
		if err := ValidDeviceName(b.Name); err != nil {
			return err
		}
		d, ok := s.ActiveDevice(b.DeviceID)
		if !ok {
			return fmt.Errorf("renamed device is not active")
		}
		d.Name = b.Name
		return nil
	case TypeAgentSlotAdd:
		var b AgentSlotAddBody
		if err := decodeBody(l, &b); err != nil {
			return err
		}
		if err := ValidSlotID(b.SlotID); err != nil {
			return err
		}
		if err := ValidSSHFingerprint(b.SSHKeyFP); err != nil {
			return err
		}
		if _, exists := s.Slots[b.SlotID]; exists {
			return fmt.Errorf("slot id reused")
		}
		if !b.Expires.After(l.CTime) || b.Expires.After(l.CTime.Add(MaxSlotLifetime)) {
			return fmt.Errorf("slot expiry must be within %s of creation", MaxSlotLifetime)
		}
		s.Slots[b.SlotID] = &SlotState{SlotID: b.SlotID, SSHKeyFP: b.SSHKeyFP, Expires: b.Expires.UTC(), UKeyVersion: s.UKeyVersion, Active: true}
		return nil
	case TypeAgentSlotRemove:
		var b AgentSlotRemoveBody
		if err := decodeBody(l, &b); err != nil {
			return err
		}
		sl, ok := s.Slots[b.SlotID]
		if !ok || !sl.Active {
			return fmt.Errorf("removed slot is not active")
		}
		sl.Active = false
		return nil
	}
	return fmt.Errorf("unknown link type %q", l.Type)
}

func (s *State) applyDeviceAdd(l Link) error { //nolint:gocyclo // every rule for adding a device in one place
	var b DeviceAddBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := ValidateDevice(b.Device); err != nil {
		return err
	}
	if _, exists := s.Devices[b.Device.ID]; exists {
		return fmt.Errorf("device id reused")
	}
	for _, d := range s.Devices {
		if d.SignPub == b.Device.SignPub || d.EncPub == b.Device.EncPub {
			return fmt.Errorf("device keys reused")
		}
	}
	proof, err := VerifyProof(&b.Proof)
	if err != nil {
		return fmt.Errorf("device proof: %w", err)
	}
	if proof.User != s.User || !sameDevice(proof.Device, b.Device) {
		return fmt.Errorf("device proof does not match the device")
	}
	switch b.Method {
	case MethodFirst:
		if len(s.Devices) != 0 || b.ApprovedBy != "" || b.Slot != "" {
			return fmt.Errorf("only the first device can use method %q", MethodFirst)
		}
	case MethodApproval:
		if _, ok := s.ActiveDevice(b.ApprovedBy); !ok || b.Slot != "" {
			return fmt.Errorf("approving device is not active")
		}
	case MethodRecovery:
		if b.ApprovedBy != "" || b.Slot != "" {
			return fmt.Errorf("recovery adds carry no approver or slot")
		}
	case MethodSSHAgent:
		if _, ok := s.UsableSlot(b.Slot, l.CTime); !ok || b.ApprovedBy != "" {
			return fmt.Errorf("agent unlock slot is not usable")
		}
	default:
		return fmt.Errorf("unknown device method %q", b.Method)
	}
	s.Devices[b.Device.ID] = &DeviceState{Device: b.Device, Status: StatusActive, Method: b.Method, ApprovedBy: b.ApprovedBy, Slot: b.Slot, AddedSeq: l.Seq}
	return nil
}

func (s *State) applyRotate(e *envelope.Envelope, l Link) error {
	if l.UKeyVersion != s.UKeyVersion+1 {
		return fmt.Errorf("rotation must advance the key version by one")
	}
	var b UKeyRotateBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	enc, err := ParseKey32(b.EncPub)
	if err != nil {
		return err
	}
	sign, err := ParseSignKey(b.SignPub)
	if err != nil {
		return err
	}
	if enc == s.EncPub || bytes.Equal(sign, s.SignPub) {
		return fmt.Errorf("rotation must replace both keys")
	}
	if err := e.Require(KindLink, s.SignPub, sign); err != nil {
		return err
	}
	if len(b.Devices) == 0 {
		return fmt.Errorf("rotation must keep at least one device")
	}
	keep := map[string]bool{}
	for _, id := range b.Devices {
		if _, ok := s.ActiveDevice(id); !ok || keep[id] {
			return fmt.Errorf("rotation lists an inactive or duplicate device")
		}
		keep[id] = true
	}
	for id, d := range s.Devices {
		if d.Status == StatusActive && !keep[id] {
			d.Status, d.RevokedSeq = StatusRevoked, l.Seq
		}
	}
	for _, sl := range s.Slots {
		sl.Active = false
	}
	s.UKeyVersion, s.EncPub, s.SignPub = l.UKeyVersion, enc, sign
	return nil
}

func sameDevice(a, b Device) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Platform == b.Platform && a.EncPub == b.EncPub && a.SignPub == b.SignPub && a.Created.Equal(b.Created)
}

func decodeBody(l Link, v any) error {
	d := json.NewDecoder(bytes.NewReader(l.Body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid %s body: %w", l.Type, err)
	}
	if d.More() {
		return fmt.Errorf("invalid %s body: trailing data", l.Type)
	}
	return nil
}

func (s *State) clone() *State {
	n := *s
	n.Hashes = append([]string(nil), s.Hashes...)
	n.Links = append([]Link(nil), s.Links...)
	n.SignPub = append(ed25519.PublicKey(nil), s.SignPub...)
	n.Devices = make(map[string]*DeviceState, len(s.Devices))
	for k, v := range s.Devices {
		c := *v
		n.Devices[k] = &c
	}
	n.Slots = make(map[string]*SlotState, len(s.Slots))
	for k, v := range s.Slots {
		c := *v
		n.Slots[k] = &c
	}
	return &n
}
