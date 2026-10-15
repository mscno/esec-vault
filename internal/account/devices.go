package account

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/sshagent"
	"github.com/mscno/esec-vault/internal/ukey"
	"github.com/mscno/esec-vault/internal/wire"
)

// Pending is a device waiting for approval, as verified locally from its
// self-signed proof. Words are computed here from the proof's keys, never
// taken from the server.
type Pending struct {
	Info  wire.DeviceInfo
	Proof *chain.DeviceProof
	Env   *envelope.Envelope
	Words string
}

// PendingDevices lists devices waiting for approval whose proofs verify.
func (a *Account) PendingDevices(ctx context.Context) ([]Pending, error) {
	devices, err := a.Client.Devices(ctx)
	if err != nil {
		return nil, err
	}
	var out []Pending
	for _, d := range devices {
		if d.Status != wire.DevicePending || d.Proof == nil {
			continue
		}
		p, err := chain.VerifyProof(d.Proof)
		if err != nil || p.User != a.State.User || p.Device.ID != d.ID {
			continue
		}
		out = append(out, Pending{Info: d, Proof: p, Env: d.Proof, Words: devicekey.Words(p.Device.EncPub, p.Device.SignPub)})
	}
	return out, nil
}

// Approve holds the account lock; see approve.
func (a *Account) Approve(ctx context.Context, p Pending) error {
	return a.Locked(func() error { return a.approve(ctx, p) })
}

// Approve adds a pending device to the chain and seals the user key to it.
func (a *Account) approve(ctx context.Context, p Pending) error {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	if _, ok := st.ActiveDevice(a.State.DeviceID); !ok {
		return errors.New("this device is not active in the chain and cannot approve others")
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return err
	}
	link, err := st.NewLink(chain.TypeDeviceAdd, chain.DeviceAddBody{Device: p.Proof.Device, Proof: *p.Env, Method: chain.MethodApproval, ApprovedBy: a.State.DeviceID}, a.Now(), id.Sign)
	if err != nil {
		return err
	}
	next, err := st.Next(link)
	if err != nil {
		return err
	}
	box, err := a.boxFor(next, id, p.Proof.Device)
	if err != nil {
		return err
	}
	if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}, DeviceBoxes: []wire.DeviceBox{box}}); err != nil {
		return err
	}
	a.State.pin(next)
	return a.State.Save()
}

// DeviceView combines the verified chain with server-side status.
type DeviceView struct {
	chain.DeviceState

	ServerStatus string
	LastSeen     time.Time
	LastIP       string
	Words        string
	Self         bool
}

// Devices lists devices from the verified chain plus pending and suspended
// devices the server knows about.
func (a *Account) Devices(ctx context.Context) ([]DeviceView, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	server, err := a.Client.Devices(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]wire.DeviceInfo{}
	for _, d := range server {
		byID[d.ID] = d
	}
	var out []DeviceView
	for _, d := range st.Devices {
		v := DeviceView{DeviceState: *d, Words: devicekey.Words(d.EncPub, d.SignPub), Self: d.ID == a.State.DeviceID}
		if s, ok := byID[d.ID]; ok {
			v.ServerStatus, v.LastSeen, v.LastIP = s.Status, s.LastSeen, s.LastIP
		}
		out = append(out, v)
	}
	for _, d := range server {
		if _, inChain := st.Devices[d.ID]; inChain || d.Status != wire.DevicePending {
			continue
		}
		out = append(out, DeviceView{DeviceState: chain.DeviceState{Device: chain.Device{ID: d.ID, Name: d.Name, Platform: d.Platform, EncPub: d.EncPub, SignPub: d.SignPub, Created: d.Created}, Status: "pending"}, ServerStatus: d.Status, LastSeen: d.LastSeen, LastIP: d.LastIP})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// RevokeResult describes a completed revocation.
type RevokeResult struct {
	Device      chain.DeviceState
	UKeyVersion uint64
	// Projects lists the projects whose keys the revoked device could read.
	Projects []string
}

// Revoke holds the account lock; see revoke.
func (a *Account) Revoke(ctx context.Context, deviceID, reason string) (*RevokeResult, error) {
	var out *RevokeResult
	err := a.Locked(func() error {
		var err error
		out, err = a.revoke(ctx, deviceID, reason)
		return err
	})
	return out, err
}

// Revoke removes a device from the chain and rotates the user key so the
// device cannot open anything stored from now on.
func (a *Account) revoke(ctx context.Context, deviceID, reason string) (*RevokeResult, error) {
	if deviceID == a.State.DeviceID {
		return nil, errors.New("a device cannot revoke itself; revoke it from another device, or use 'esec vault logout --forget-device'")
	}
	if _, err := a.sync(ctx, SyncOptions{}); err != nil {
		return nil, fmt.Errorf("sync before revoking: %w", err)
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	target, ok := st.ActiveDevice(deviceID)
	if !ok {
		return nil, fmt.Errorf("device %s is not active in the chain", deviceID)
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return nil, err
	}
	revoke, err := st.NewLink(chain.TypeDeviceRevoke, chain.DeviceRevokeBody{DeviceID: deviceID, Reason: reason}, a.Now(), id.Sign)
	if err != nil {
		return nil, err
	}
	next, err := st.Next(revoke)
	if err != nil {
		return nil, err
	}
	version, err := a.rotate(ctx, next, id, []*envelope.Envelope{revoke}, "revoked "+deviceID)
	if err != nil {
		return nil, err
	}
	projects, err := a.KS.List()
	if err != nil {
		return nil, err
	}
	return &RevokeResult{Device: *target, UKeyVersion: version, Projects: projects}, nil
}

// RotateUserKey holds the account lock; see rotateUserKey.
func (a *Account) RotateUserKey(ctx context.Context, reason string) (uint64, error) {
	var out uint64
	err := a.Locked(func() error {
		var err error
		out, err = a.rotateUserKey(ctx, reason)
		return err
	})
	return out, err
}

// RotateUserKey replaces the user key without revoking a device.
func (a *Account) rotateUserKey(ctx context.Context, reason string) (uint64, error) {
	if _, err := a.sync(ctx, SyncOptions{}); err != nil {
		return 0, fmt.Errorf("sync before rotating: %w", err)
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return 0, err
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return 0, err
	}
	return a.rotate(ctx, st, id, nil, reason)
}

// rotate appends a ukey_rotate link after prefix, seals the new key to every
// remaining active device, re-wraps it to the master key, re-seals the vault,
// commits everything atomically, and only then installs the key locally.
func (a *Account) rotate(ctx context.Context, st *chain.State, id *identity.Identity, prefix []*envelope.Envelope, reason string) (uint64, error) {
	next, err := identity.NewRandom()
	if err != nil {
		return 0, err
	}
	keep := []string{}
	for _, d := range st.ActiveDevices() {
		keep = append(keep, d.ID)
	}
	link, err := st.NewLink(chain.TypeUKeyRotate, chain.UKeyRotateBody{EncPub: hex.EncodeToString(next.Public[:]), SignPub: hex.EncodeToString(next.SignPublic()), Devices: keep, Reason: reason}, a.Now(), id.Sign, next.Sign)
	if err != nil {
		return 0, err
	}
	rotated, err := st.Next(link)
	if err != nil {
		return 0, err
	}
	current, err := identity.WrappedFile()
	if err != nil {
		return 0, err
	}
	wrapped, err := identity.WrapForMaster(next, current)
	if err != nil {
		return 0, err
	}
	var boxes []wire.DeviceBox
	for _, d := range rotated.ActiveDevices() {
		b, err := a.boxFor(rotated, next, d.Device)
		if err != nil {
			return 0, err
		}
		boxes = append(boxes, b)
	}
	put, gen, err := a.vaultPut(rotated, next, wrapped, a.State.Vault.Version, a.State.Vault.Generation+1)
	if err != nil {
		return 0, err
	}
	res, err := a.Client.Commit(ctx, &wire.Commit{Links: append(prefix, link), DeviceBoxes: boxes, Identity: wrapped, Vault: put})
	if err != nil {
		return 0, err
	}
	if err := saveBase(put.Blob); err != nil {
		return 0, err
	}
	a.State.pin(rotated)
	a.State.Vault = VaultPin{Version: res.VaultVersion, Generation: gen, SHA256: sha(put.Blob), SyncedAt: a.Now()}
	if err := a.State.Save(); err != nil {
		return 0, err
	}
	// The server now holds the new key in this device's box; installing it
	// locally can be retried by any later sync if this step fails.
	if err := a.installIdentity(ctx, next, rotated); err != nil {
		return 0, fmt.Errorf("rotation committed, but installing the new key locally failed (run 'esec vault sync --server'): %w", err)
	}
	return rotated.UKeyVersion, a.State.Save()
}

// Suspend blocks a device on the server at once, pending revocation.
func (a *Account) Suspend(ctx context.Context, deviceID string) error {
	return a.Client.Suspend(ctx, deviceID)
}

// SlotView is an agent unlock slot.
type SlotView struct {
	chain.SlotState

	ServerDisabled bool
}

// AgentSlots lists slots from the verified chain with their server state.
func (a *Account) AgentSlots(ctx context.Context) ([]SlotView, error) {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return nil, err
	}
	server, err := a.Client.AgentSlots(ctx)
	if err != nil {
		return nil, err
	}
	enabled := map[string]bool{}
	for _, s := range server {
		enabled[s.SlotID] = !s.Disabled
	}
	var out []SlotView
	for _, s := range st.Slots {
		out = append(out, SlotView{SlotState: *s, ServerDisabled: !enabled[s.SlotID]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out, nil
}

// MaxSlotTTL is the longest slot lifetime the CLI accepts.
const MaxSlotTTL = 365 * 24 * time.Hour

// EnableAgentSlot holds the account lock; see enableAgentSlot.
func (a *Account) EnableAgentSlot(ctx context.Context, ag *sshagent.Agent, key *sshagent.Key, ttl time.Duration) (string, error) {
	var out string
	err := a.Locked(func() error {
		var err error
		out, err = a.enableAgentSlot(ctx, ag, key, ttl)
		return err
	})
	return out, err
}

// EnableAgentSlot creates an unlock slot for key: the user key wrapped under
// a key derived from the agent's (deterministic) signature over a fresh
// challenge.
func (a *Account) enableAgentSlot(ctx context.Context, ag *sshagent.Agent, key *sshagent.Key, ttl time.Duration) (string, error) {
	if err := sshagent.Supported(key.Public); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > MaxSlotTTL {
		return "", fmt.Errorf("slot lifetime must be between 1s and %s", MaxSlotTTL)
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return "", err
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return "", err
	}
	slotID := "s_" + randomLower(20)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	secret, err := ag.CheckDeterministic(key, ukey.SlotNamespace, ukey.SlotChallenge(a.State.User, slotID, salt))
	if err != nil {
		return "", err
	}
	kek, err := ukey.SlotKEK(secret, salt)
	if err != nil {
		return "", err
	}
	m, err := a.material(st, id)
	if err != nil {
		return "", err
	}
	box, err := ukey.SealSlot(m, kek, a.State.User, slotID)
	if err != nil {
		return "", err
	}
	now := a.Now().UTC().Truncate(time.Second)
	expires := now.Add(ttl)
	link, err := st.NewLink(chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: slotID, SSHKeyFP: key.Fingerprint, Expires: expires}, now, id.Sign)
	if err != nil {
		return "", err
	}
	next, err := st.Next(link)
	if err != nil {
		return "", err
	}
	if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}, AgentSlots: []wire.AgentSlot{{SlotID: slotID, SSHKeyFP: key.Fingerprint, Salt: salt, Box: box, UKeyVersion: next.UKeyVersion, Expires: expires}}}); err != nil {
		return "", err
	}
	a.State.pin(next)
	return slotID, a.State.Save()
}

// DisableAgentSlot holds the account lock; see disableAgentSlot.
func (a *Account) DisableAgentSlot(ctx context.Context, slotID string) error {
	return a.Locked(func() error { return a.disableAgentSlot(ctx, slotID) })
}

// DisableAgentSlot removes a slot from the chain and disables it on the server.
func (a *Account) disableAgentSlot(ctx context.Context, slotID string) error {
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	if s, ok := st.Slots[slotID]; ok && s.Active {
		id, err := a.userKey(ctx, st)
		if err != nil {
			return err
		}
		link, err := st.NewLink(chain.TypeAgentSlotRemove, chain.AgentSlotRemoveBody{SlotID: slotID}, a.Now(), id.Sign)
		if err != nil {
			return err
		}
		next, err := st.Next(link)
		if err != nil {
			return err
		}
		if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}}); err != nil {
			return err
		}
		a.State.pin(next)
		if err := a.State.Save(); err != nil {
			return err
		}
	} else if !ok {
		return fmt.Errorf("no slot %s", slotID)
	}
	if err := a.Client.DisableSlot(ctx, slotID); err != nil && !client.IsCode(err, wire.ErrNotFound) {
		return err
	}
	return nil
}

// Logout ends the session. With forgetDevice it also deletes this device's
// keys and account record, so the next login enrolls a new device.
func (a *Account) Logout(ctx context.Context, forgetDevice bool) error {
	var errs []error
	if err := a.Client.Logout(ctx); err != nil && !client.IsCode(err, wire.ErrUnauthorized) && !client.IsCode(err, wire.ErrDeviceRevoked) {
		errs = append(errs, fmt.Errorf("end server session: %w", err))
	}
	errs = append(errs, a.KR.Delete(SessionTokenName))
	if forgetDevice {
		errs = append(errs, devicekey.Delete(a.KR), Remove())
	}
	return errors.Join(errs...)
}

func randomLower(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b)
}

// Rename holds the account lock; see rename.
func (a *Account) Rename(ctx context.Context, deviceID, name string) error {
	return a.Locked(func() error { return a.rename(ctx, deviceID, name) })
}

// Rename changes a device's name in the chain.
func (a *Account) rename(ctx context.Context, deviceID, name string) error {
	if err := chain.ValidDeviceName(name); err != nil {
		return err
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return err
	}
	link, err := st.NewLink(chain.TypeDeviceRename, chain.DeviceRenameBody{DeviceID: deviceID, Name: name}, a.Now(), id.Sign)
	if err != nil {
		return err
	}
	next, err := st.Next(link)
	if err != nil {
		return err
	}
	if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}}); err != nil {
		return err
	}
	a.State.pin(next)
	if deviceID == a.State.DeviceID {
		a.State.DeviceName = name
	}
	return a.State.Save()
}
