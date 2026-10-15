package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/ukey"
	"github.com/mscno/esec-vault/internal/wire"
)

// UI is how the account package talks to the person at the terminal.
type UI interface {
	Printf(format string, args ...any)
	// Confirm asks a yes/no question; false when there is no terminal.
	Confirm(question string) bool
	// Secret reads a value without echo.
	Secret(label string) (string, error)
}

// Account is a signed-in machine.
type Account struct {
	State  *State
	KR     keyring.Keyring
	Device *devicekey.Key
	Client *client.Client
	KS     *keystore.Store
	UI     UI
	Now    func() time.Time
	// ReplaceIdentity allows replacing a local identity that did not come
	// from this account without asking.
	ReplaceIdentity bool
}

// Open loads the signed-in account of this machine.
func Open(kr keyring.Keyring, ui UI) (*Account, error) {
	st, err := LoadState()
	if err != nil {
		return nil, err
	}
	dev, err := devicekey.Load(kr)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	token, err := kr.Get(SessionTokenName)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return nil, err
	}
	c, err := client.New(st.Server)
	if err != nil {
		return nil, err
	}
	c.DeviceID, c.Key, c.Token = st.DeviceID, dev.Sign, token
	return &Account{State: st, KR: kr, Device: dev, Client: c, KS: keystore.New(), UI: ui, Now: time.Now}, nil
}

// Locked runs fn while holding the account lock, after reloading the state
// from disk, so the CLI and the daemon never overwrite each other's pins.
func (a *Account) Locked(fn func() error) error {
	unlock, err := lockAccount()
	if err != nil {
		return err
	}
	defer unlock()
	if fresh, err := LoadState(); err == nil && fresh.User == a.State.User && fresh.DeviceID == a.State.DeviceID {
		a.State = fresh
	}
	return fn()
}

// lockAccount waits up to a minute for the cross-process account lock.
func lockAccount() (func(), error) {
	dir := filepath.Join(paths.Home(), "account.lock.d")
	deadline := time.Now().Add(time.Minute)
	for {
		unlock, err := storage.Lock(dir)
		if err == nil {
			return unlock, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another esec-vault process is busy with the account: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// VerifiedChain fetches the whole chain, verifies it, and checks it against
// this machine's pin. It does not move the pin.
func (a *Account) VerifiedChain(ctx context.Context) (*chain.State, error) {
	links, err := a.Client.Chain(ctx, 0)
	if err != nil {
		return nil, err
	}
	st, err := chain.Verify(a.State.User, links)
	if err != nil {
		return nil, fmt.Errorf("the server's device chain does not verify: %w", err)
	}
	if err := a.State.checkPin(st); err != nil {
		return nil, err
	}
	return st, nil
}

// moveAside renames a file that can no longer be opened by the new identity.
func moveAside(p, tag string) error {
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dst := p + ".pre-" + tag
	if err := os.Rename(p, dst); err != nil {
		return fmt.Errorf("move %s aside: %w", filepath.Base(p), err)
	}
	return nil
}

// Words returns this device's fingerprint words.
func (a *Account) Words() string { return a.Device.Words() }

// userKey returns the user key current in st, fetching and installing it
// from this device's box when the local identity is older or missing.
func (a *Account) userKey(ctx context.Context, st *chain.State) (*identity.Identity, error) {
	if id, err := identity.Load(a.KR); err == nil && id.Public == st.EncPub && bytes.Equal(id.SignPublic(), st.SignPub) {
		return id, nil
	}
	box, err := a.Client.DeviceBox(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch this device's user key: %w", err)
	}
	m, err := ukey.OpenDeviceBox(box.Box, &a.Device.EncPub, &a.Device.EncPriv)
	if err != nil {
		return nil, err
	}
	id, err := m.Check(st)
	if err != nil {
		return nil, err
	}
	if err := a.installIdentity(ctx, id, st); err != nil {
		return nil, err
	}
	return id, nil
}

// installIdentity stores id as this machine's identity, with the server's
// master-wrapped copy after checking that it names exactly id and the
// chain's master key. A local identity from elsewhere is replaced only with
// consent; its backup snapshot is moved aside because it is sealed to it.
func (a *Account) installIdentity(ctx context.Context, id *identity.Identity, st *chain.State) error {
	blob, err := a.Client.Identity(ctx)
	if err != nil {
		return fmt.Errorf("fetch the wrapped identity: %w", err)
	}
	h, err := identity.ReadHeader(blob.Blob)
	if err != nil {
		return err
	}
	if h.MasterPublic != st.MasterPub || h.IdentityPublic != id.Public || !bytes.Equal(h.SignPublic[:], id.SignPublic()) {
		return fmt.Errorf("the server's wrapped identity does not match the verified user key")
	}
	local, err := identity.Load(a.KR)
	switch {
	case err == nil && local.Public == id.Public:
	case err == nil:
		if !a.State.IdentityFromAccount && !a.ReplaceIdentity {
			q := fmt.Sprintf("This machine has a different identity (%s). Replace it with the account's identity? Local keyrings are kept and merged into the account vault.", identity.ShortFingerprint(local.Fingerprint()))
			if !a.UI.Confirm(q) {
				return errors.New("kept the existing identity; rerun with --replace-identity to use the account's identity on this machine")
			}
		}
		if err := moveAside(paths.VaultFile(), identity.ShortFingerprint(local.Fingerprint())); err != nil {
			return err
		}
	case !errors.Is(err, identity.ErrNotFound):
		return err
	}
	if err := identity.Install(a.KR, id, blob.Blob); err != nil {
		return err
	}
	a.State.IdentityFromAccount = true
	return nil
}

// material captures id as the transport form for version.
func (a *Account) material(st *chain.State, id *identity.Identity) (*ukey.Material, error) {
	return ukey.FromIdentity(a.State.User, st.UKeyVersion, id)
}

// boxFor seals the user key to a device of the verified chain.
func (a *Account) boxFor(st *chain.State, id *identity.Identity, d chain.Device) (wire.DeviceBox, error) {
	pub, err := chain.ParseKey32(d.EncPub)
	if err != nil {
		return wire.DeviceBox{}, err
	}
	m, err := a.material(st, id)
	if err != nil {
		return wire.DeviceBox{}, err
	}
	box, err := ukey.SealToDevice(m, pub)
	if err != nil {
		return wire.DeviceBox{}, err
	}
	return wire.DeviceBox{DeviceID: d.ID, UKeyVersion: st.UKeyVersion, Box: box}, nil
}

// self describes this device as the server registered it.
func (a *Account) self(info wire.DeviceInfo) chain.Device {
	return chain.Device{ID: info.ID, Name: info.Name, Platform: info.Platform, EncPub: a.Device.EncPubHex(), SignPub: a.Device.SignPubHex(), Created: info.Created.UTC()}
}
