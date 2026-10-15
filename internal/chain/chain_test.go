package chain_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
)

const user = "gh:53101343"

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

type fixture struct {
	t     *testing.T
	u     *identity.Identity
	s     *chain.State
	links []*envelope.Envelope
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	u, err := identity.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, u: u, s: chain.New(user), now: t0}
	master := make([]byte, 32)
	master[0] = 9
	f.add(chain.TypeInit, chain.InitBody{EncPub: hex.EncodeToString(u.Public[:]), SignPub: hex.EncodeToString(u.SignPublic()), MasterPub: hex.EncodeToString(master)}, u.Sign)
	return f
}

func (f *fixture) link(typ string, body any, signers ...ed25519.PrivateKey) *envelope.Envelope {
	f.t.Helper()
	f.now = f.now.Add(time.Minute)
	e, err := f.s.NewLink(typ, body, f.now, signers...)
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixture) add(typ string, body any, signers ...ed25519.PrivateKey) {
	f.t.Helper()
	e := f.link(typ, body, signers...)
	next, err := f.s.Next(e)
	if err != nil {
		f.t.Fatalf("%s: %v", typ, err)
	}
	f.s = next
	f.links = append(f.links, e)
}

func (f *fixture) reject(want string, typ string, body any, signers ...ed25519.PrivateKey) {
	f.t.Helper()
	e := f.link(typ, body, signers...)
	if _, err := f.s.Next(e); err == nil || !strings.Contains(err.Error(), want) {
		f.t.Fatalf("%s: expected error containing %q, got %v", typ, want, err)
	}
}

func newDevice(t *testing.T, id string) (*devicekey.Key, chain.Device) {
	t.Helper()
	k, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k, chain.Device{ID: id, Name: "laptop " + id[2:6], Platform: "darwin/arm64", EncPub: k.EncPubHex(), SignPub: k.SignPubHex(), Created: t0}
}

func (f *fixture) deviceAdd(id, method, approvedBy, slot string) (*devicekey.Key, chain.DeviceAddBody) {
	f.t.Helper()
	k, d := newDevice(f.t, id)
	proof, err := k.Proof(user, d)
	if err != nil {
		f.t.Fatal(err)
	}
	return k, chain.DeviceAddBody{Device: d, Proof: *proof, Method: method, ApprovedBy: approvedBy, Slot: slot}
}

func sshFP() string { return "SHA256:" + strings.Repeat("A", 43) }

func TestFullLifecycle(t *testing.T) {
	f := newFixture(t)
	root := f.s.AccountWords()
	_, first := f.deviceAdd("d_laptop0001", chain.MethodFirst, "", "")
	f.add(chain.TypeDeviceAdd, first, f.u.Sign)
	_, vm := f.deviceAdd("d_vm00000001", chain.MethodApproval, "d_laptop0001", "")
	f.add(chain.TypeDeviceAdd, vm, f.u.Sign)
	f.add(chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: "s_slot000001", SSHKeyFP: sshFP(), Expires: t0.Add(90 * 24 * time.Hour)}, f.u.Sign)
	_, agentVM := f.deviceAdd("d_vm00000002", chain.MethodSSHAgent, "", "s_slot000001")
	f.add(chain.TypeDeviceAdd, agentVM, f.u.Sign)
	_, rec := f.deviceAdd("d_vm00000003", chain.MethodRecovery, "", "")
	f.add(chain.TypeDeviceAdd, rec, f.u.Sign)
	f.add(chain.TypeDeviceRevoke, chain.DeviceRevokeBody{DeviceID: "d_vm00000001", Reason: "lost"}, f.u.Sign)

	next, err := identity.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	f.add(chain.TypeUKeyRotate, chain.UKeyRotateBody{EncPub: hex.EncodeToString(next.Public[:]), SignPub: hex.EncodeToString(next.SignPublic()), Devices: []string{"d_laptop0001", "d_vm00000003"}}, f.u.Sign, next.Sign)

	s := f.s
	if s.UKeyVersion != 2 || s.EncPub != next.Public {
		t.Fatal("rotation not applied")
	}
	if d := s.Devices["d_vm00000002"]; d.Status != chain.StatusRevoked {
		t.Fatal("device left out of a rotation must be revoked")
	}
	if d := s.Devices["d_vm00000001"]; d.Status != chain.StatusRevoked || d.RevokedSeq == 0 {
		t.Fatal("revocation not applied")
	}
	if len(s.ActiveDevices()) != 2 {
		t.Fatalf("active devices: %d", len(s.ActiveDevices()))
	}
	if _, ok := s.UsableSlot("s_slot000001", t0); ok {
		t.Fatal("rotation must deactivate agent slots")
	}
	if s.AccountWords() != root || root == "" {
		t.Fatal("account words must survive key rotation")
	}

	// The old user key can no longer sign links.
	f.u = next
	old, _ := identity.NewRandom()
	f.reject("signature", chain.TypeDeviceRevoke, chain.DeviceRevokeBody{DeviceID: "d_vm00000003"}, old.Sign)

	// Full re-verification gives the same state.
	again, err := chain.Verify(user, f.links)
	if err != nil {
		t.Fatal(err)
	}
	if again.Head() != s.Head() || again.Seq != s.Seq {
		t.Fatal("incremental and full verification disagree")
	}
}

func TestRejectsForgedAndMalformedLinks(t *testing.T) {
	f := newFixture(t)
	_, first := f.deviceAdd("d_laptop0001", chain.MethodFirst, "", "")
	f.add(chain.TypeDeviceAdd, first, f.u.Sign)

	stranger, _ := identity.NewRandom()
	devKey, devBody := f.deviceAdd("d_attack0001", chain.MethodApproval, "d_laptop0001", "")
	f.reject("signature", chain.TypeDeviceAdd, devBody, stranger.Sign)
	f.reject("signature", chain.TypeDeviceAdd, devBody, devKey.Sign)
	f.reject("signature", chain.TypeDeviceAdd, devBody)

	// Approval by an unknown device.
	_, bad := f.deviceAdd("d_attack0002", chain.MethodApproval, "d_nobody0001", "")
	f.reject("approving device", chain.TypeDeviceAdd, bad, f.u.Sign)

	// A second "first" device.
	_, second := f.deviceAdd("d_attack0003", chain.MethodFirst, "", "")
	f.reject("first device", chain.TypeDeviceAdd, second, f.u.Sign)

	// A proof signed by a different key than the device's.
	k, d := newDevice(t, "d_attack0004")
	other, _ := devicekey.Generate()
	forged, err := envelope.New(chain.KindDeviceProof, chain.DeviceProof{User: user, Device: d}, other.Sign)
	if err != nil {
		t.Fatal(err)
	}
	f.reject("device proof", chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *forged, Method: chain.MethodRecovery}, f.u.Sign)

	// A valid proof for another user.
	otherUser, err := envelope.New(chain.KindDeviceProof, chain.DeviceProof{User: "gh:1", Device: d}, k.Sign)
	if err != nil {
		t.Fatal(err)
	}
	f.reject("does not match", chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *otherUser, Method: chain.MethodRecovery}, f.u.Sign)

	// A proof for a different device description.
	d2 := d
	d2.Name = "renamed"
	mismatch, err := k.Proof(user, d2)
	if err != nil {
		t.Fatal(err)
	}
	f.reject("does not match", chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *mismatch, Method: chain.MethodRecovery}, f.u.Sign)

	// Reusing an existing device's keys or id.
	reuse := first
	reuse.Method = chain.MethodRecovery
	f.reject("reused", chain.TypeDeviceAdd, reuse, f.u.Sign)

	// Control characters in device names never get in.
	_, esc := newDevice(t, "d_attack0005")
	esc.Name = "evil\x1b[2J"
	f.reject("device name", chain.TypeDeviceAdd, chain.DeviceAddBody{Device: esc, Proof: *mismatch, Method: chain.MethodRecovery}, f.u.Sign)

	// Revoking an unknown device; adding an expired or unknown slot.
	f.reject("not active", chain.TypeDeviceRevoke, chain.DeviceRevokeBody{DeviceID: "d_nobody0001"}, f.u.Sign)
	f.reject("expiry", chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: "s_slot000001", SSHKeyFP: sshFP(), Expires: t0}, f.u.Sign)
	f.reject("expiry", chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: "s_slot000001", SSHKeyFP: sshFP(), Expires: t0.Add(400 * 24 * time.Hour)}, f.u.Sign)
	_, viaSlot := f.deviceAdd("d_attack0006", chain.MethodSSHAgent, "", "s_nothere001")
	f.reject("slot", chain.TypeDeviceAdd, viaSlot, f.u.Sign)

	// Another init link.
	f.reject("init link", chain.TypeInit, chain.InitBody{EncPub: strings.Repeat("11", 32), SignPub: strings.Repeat("22", 32), MasterPub: strings.Repeat("33", 32)}, f.u.Sign)
}

func TestRotationRules(t *testing.T) {
	f := newFixture(t)
	_, first := f.deviceAdd("d_laptop0001", chain.MethodFirst, "", "")
	f.add(chain.TypeDeviceAdd, first, f.u.Sign)
	next, _ := identity.NewRandom()
	body := chain.UKeyRotateBody{EncPub: hex.EncodeToString(next.Public[:]), SignPub: hex.EncodeToString(next.SignPublic()), Devices: []string{"d_laptop0001"}}
	f.reject("signature", chain.TypeUKeyRotate, body, f.u.Sign)
	f.reject("signature", chain.TypeUKeyRotate, body, next.Sign)
	empty := body
	empty.Devices = nil
	f.reject("at least one", chain.TypeUKeyRotate, empty, f.u.Sign, next.Sign)
	ghost := body
	ghost.Devices = []string{"d_ghost00001"}
	f.reject("inactive", chain.TypeUKeyRotate, ghost, f.u.Sign, next.Sign)
	same := body
	same.EncPub = hex.EncodeToString(f.u.Public[:])
	f.reject("replace both", chain.TypeUKeyRotate, same, f.u.Sign, next.Sign)
	f.add(chain.TypeUKeyRotate, body, f.u.Sign, next.Sign)
}

func TestSequenceTamperingAndPins(t *testing.T) {
	f := newFixture(t)
	_, first := f.deviceAdd("d_laptop0001", chain.MethodFirst, "", "")
	f.add(chain.TypeDeviceAdd, first, f.u.Sign)
	f.add(chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: "s_slot000001", SSHKeyFP: sshFP(), Expires: t0.Add(24 * time.Hour)}, f.u.Sign)

	// Dropping a link breaks the sequence.
	if _, err := chain.Verify(user, []*envelope.Envelope{f.links[0], f.links[2]}); err == nil {
		t.Fatal("gap accepted")
	}
	// Reordering breaks it too.
	if _, err := chain.Verify(user, []*envelope.Envelope{f.links[1], f.links[0]}); err == nil {
		t.Fatal("reordering accepted")
	}
	// Another user's chain is rejected.
	if _, err := chain.Verify("gh:2", f.links); err == nil {
		t.Fatal("chain for another user accepted")
	}
	// Editing a signed body invalidates the signature.
	var l chain.Link
	if err := json.Unmarshal(f.links[2].Body, &l); err != nil {
		t.Fatal(err)
	}
	l.CTime = l.CTime.Add(time.Hour)
	raw, _ := json.Marshal(l)
	tampered := *f.links[2]
	tampered.Body = raw
	if _, err := chain.Verify(user, []*envelope.Envelope{f.links[0], f.links[1], &tampered}); err == nil {
		t.Fatal("tampered body accepted")
	}
	// Unknown fields are rejected rather than ignored.
	var generic map[string]any
	_ = json.Unmarshal(f.links[1].Body, &generic)
	generic["extra"] = true
	raw, _ = json.Marshal(generic)
	extra, err := envelope.NewRaw(chain.KindLink, raw, f.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Verify(user, []*envelope.Envelope{f.links[0], extra}); err == nil {
		t.Fatal("unknown field accepted")
	}

	full, err := chain.Verify(user, f.links)
	if err != nil {
		t.Fatal(err)
	}
	if err := full.CheckPin(3, full.Head()); err != nil {
		t.Fatal(err)
	}
	short, _ := chain.Verify(user, f.links[:2])
	if err := short.CheckPin(3, full.Head()); !errors.Is(err, chain.ErrRollback) {
		t.Fatalf("rollback not detected: %v", err)
	}
	// A fork: same length, different link 3.
	fork := newForkAt(t, f, 2)
	if err := fork.CheckPin(3, full.Head()); !errors.Is(err, chain.ErrRollback) {
		t.Fatalf("fork not detected: %v", err)
	}
}

func newForkAt(t *testing.T, f *fixture, keep int) *chain.State {
	t.Helper()
	s, err := chain.Verify(user, f.links[:keep])
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.NewLink(chain.TypeAgentSlotAdd, chain.AgentSlotAddBody{SlotID: "s_fork000001", SSHKeyFP: sshFP(), Expires: t0.Add(48 * time.Hour)}, t0.Add(time.Hour), f.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Next(e)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"macbook.local":         "macbook.local",
		"":                      "device",
		"\x1b[31mred":           "31mred",
		"../../etc":             "etc",
		"ok name (2)":           "ok name (2)",
		"häst":                  "h-st",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		got := chain.SanitizeName(in)
		if got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
		if chain.ValidDeviceName(got) != nil {
			t.Errorf("SanitizeName(%q) = %q is not a valid name", in, got)
		}
	}
	_ = rand.Reader
}
