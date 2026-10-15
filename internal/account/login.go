package account

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/devicekey"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/identity"
	"github.com/mscno/esec-vault/internal/keyring"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/sshagent"
	"github.com/mscno/esec-vault/internal/ukey"
	"github.com/mscno/esec-vault/internal/wire"
)

// Methods for obtaining the user key on a new device.
const (
	LoginApproval = ""
	LoginRecover  = "recover"
	LoginSSHAgent = "ssh-agent"
)

// LoginOptions configures Login.
type LoginOptions struct {
	Server          string
	Name            string
	Method          string
	ReplaceIdentity bool
	// OpenBrowser opens the verification URL; nil prints it only.
	OpenBrowser func(url string) error
	// Agent overrides SSH_AUTH_SOCK for the ssh-agent method (tests).
	AgentSocket string
	// Poll overrides polling intervals (tests).
	Poll time.Duration
	// Mnemonic and Passphrase are read through UI.Secret when empty.
	Mnemonic, Passphrase string
}

// Login signs this machine in, enrolls or re-authenticates its device, makes
// sure it holds the current user key, and syncs the vault.
func Login(ctx context.Context, kr keyring.Keyring, ui UI, opts LoginOptions) (*Account, error) {
	existing, err := LoadState()
	if err != nil && !errors.Is(err, ErrNotLoggedIn) {
		return nil, err
	}
	server := opts.Server
	if server == "" && existing != nil {
		server = existing.Server
	}
	if server == "" {
		server = os.Getenv("ESEC_VAULT_SERVER")
	}
	if server == "" {
		return nil, errors.New("name the server: esec vault login https://vault.example.com")
	}
	c, err := client.New(server)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Server != c.Base {
		return nil, fmt.Errorf("this machine is signed in to %s; run 'esec vault logout --forget-device' before signing in elsewhere", existing.Server)
	}
	dev, _, err := devicekey.LoadOrCreate(kr)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	name := opts.Name
	if name == "" && existing != nil {
		name = existing.DeviceName
	}
	if name == "" {
		host, _ := os.Hostname()
		name = chain.SanitizeName(host)
	}
	if err := chain.ValidDeviceName(name); err != nil {
		return nil, err
	}
	poll := opts.Poll
	tok, err := deviceGrant(ctx, c, ui, dev, name, opts.OpenBrowser, poll)
	if err != nil {
		return nil, err
	}
	if err := kr.Set(SessionTokenName, tok.SessionToken); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}
	st := &State{Server: c.Base, User: tok.User.ID, GitHubID: tok.User.GitHubID, Login: tok.User.Login, DeviceID: tok.Device.ID, DeviceName: tok.Device.Name}
	if existing != nil && existing.User == tok.User.ID {
		st.Chain, st.Vault, st.Events, st.IdentityFromAccount = existing.Chain, existing.Vault, existing.Events, existing.IdentityFromAccount
	}
	if err := st.Save(); err != nil {
		return nil, err
	}
	c.DeviceID, c.Key, c.Token = tok.Device.ID, dev.Sign, tok.SessionToken
	a := &Account{State: st, KR: kr, Device: dev, Client: c, KS: keystore.New(), UI: ui, Now: time.Now, ReplaceIdentity: opts.ReplaceIdentity}
	ui.Printf("✓ Signed in as %s (GitHub %d)\n", tok.User.Login, tok.User.GitHubID)

	switch tok.Device.Status {
	case wire.DeviceActive:
		ui.Printf("Device %q is already trusted.\n", tok.Device.Name)
		chainState, err := a.VerifiedChain(ctx)
		if err != nil {
			return nil, err
		}
		if _, ok := chainState.ActiveDevice(st.DeviceID); !ok {
			return nil, errors.New("the server lists this device as active but the verified chain does not")
		}
		if _, err := a.userKey(ctx, chainState); err != nil {
			return nil, err
		}
		a.State.pin(chainState)
	case wire.DevicePending:
		if err := a.enroll(ctx, tok.Device, opts); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("device status %q", tok.Device.Status)
	}
	if err := a.State.Save(); err != nil {
		return nil, err
	}
	ui.Printf("Account key: %s\n", a.State.Chain.AccountWords)
	return a, nil
}

// deviceGrant runs the device authorization grant and returns the session.
func deviceGrant(ctx context.Context, c *client.Client, ui UI, dev *devicekey.Key, name string, open func(string) error, poll time.Duration) (*wire.TokenResponse, error) {
	reg, err := c.RegisterDevice(ctx, wire.DeviceRegisterRequest{Name: name, Platform: runtime.GOOS + "/" + runtime.GOARCH, EncPub: dev.EncPubHex(), SignPub: dev.SignPubHex()})
	if err != nil {
		return nil, err
	}
	ui.Printf("Open %s\n(or go to %s and enter %s)\n", reg.VerificationURIComplete, reg.VerificationURI, reg.UserCode)
	ui.Printf("Device %q  fingerprint: %s\n", name, dev.Words())
	if open != nil {
		_ = open(reg.VerificationURIComplete)
	}
	c.DeviceID, c.Key = reg.DeviceID, dev.Sign
	interval := time.Duration(reg.Interval) * time.Second
	if poll > 0 {
		interval = poll
	}
	deadline := time.Now().Add(time.Duration(reg.ExpiresIn) * time.Second)
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("the code expired before it was confirmed; run 'esec vault login' again")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		tok, err := c.PollToken(ctx, reg.DeviceCode)
		switch {
		case err == nil:
			return tok, nil
		case client.IsCode(err, wire.ErrAuthorizationPending):
		case client.IsCode(err, wire.ErrSlowDown):
			interval += time.Second
		default:
			return nil, err
		}
	}
}

// enroll gives a pending device the user key: by creating the account, by
// approval from a trusted device, from the recovery phrase, or from an
// SSH-agent unlock slot.
func (a *Account) enroll(ctx context.Context, info wire.DeviceInfo, opts LoginOptions) error {
	d := a.self(info)
	proof, err := a.Device.Proof(a.State.User, d)
	if err != nil {
		return err
	}
	if err := a.Client.UploadProof(ctx, proof); err != nil {
		return fmt.Errorf("upload device proof: %w", err)
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	if st.Seq == 0 {
		return a.createAccount(ctx, d, proof)
	}
	switch opts.Method {
	case LoginRecover:
		id, err := a.fromPhrase(ctx, st, opts)
		if err != nil {
			return err
		}
		return a.selfAdd(ctx, st, d, proof, id, chain.MethodRecovery, "")
	case LoginSSHAgent:
		id, slot, err := a.fromAgent(ctx, st, opts.AgentSocket)
		if err != nil {
			return err
		}
		return a.selfAdd(ctx, st, d, proof, id, chain.MethodSSHAgent, slot)
	case LoginApproval:
		return a.waitForApproval(ctx, d, opts.Poll)
	}
	return fmt.Errorf("unknown login method %q", opts.Method)
}

// createAccount starts the chain with this machine's identity as user key 1
// and this device as the first device, and uploads the first vault.
func (a *Account) createAccount(ctx context.Context, d chain.Device, proof *envelope.Envelope) error {
	id, upgraded, err := identity.EnsureSigningKey(a.KR)
	if errors.Is(err, identity.ErrNotFound) {
		return errors.New("no vault account exists for this GitHub user yet, and this machine has no identity to create one; run 'esec vault identity init' (or 'identity recover'), then 'esec vault login' again")
	}
	if err != nil {
		return err
	}
	if upgraded {
		a.UI.Printf("Added a signing key to your identity (identity.esec is now version 3; your recovery phrase is unchanged).\n")
	}
	wrapped, err := identity.WrappedFile()
	if err != nil {
		return err
	}
	h, err := identity.ReadHeader(wrapped)
	if err != nil {
		return err
	}
	now := a.Now()
	st0 := chain.New(a.State.User)
	initLink, err := st0.NewLink(chain.TypeInit, chain.InitBody{EncPub: hex.EncodeToString(id.Public[:]), SignPub: hex.EncodeToString(id.SignPublic()), MasterPub: hex.EncodeToString(h.MasterPublic[:])}, now, id.Sign)
	if err != nil {
		return err
	}
	st1, err := st0.Next(initLink)
	if err != nil {
		return err
	}
	addLink, err := st1.NewLink(chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *proof, Method: chain.MethodFirst}, now, id.Sign)
	if err != nil {
		return err
	}
	st2, err := st1.Next(addLink)
	if err != nil {
		return err
	}
	box, err := a.boxFor(st2, id, d)
	if err != nil {
		return err
	}
	put, gen, err := a.vaultPut(st2, id, wrapped, 0, 1)
	if err != nil {
		return err
	}
	res, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{initLink, addLink}, DeviceBoxes: []wire.DeviceBox{box}, Identity: wrapped, Vault: put})
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if err := saveBase(put.Blob); err != nil {
		return err
	}
	a.State.pin(st2)
	a.State.IdentityFromAccount = true
	a.State.Vault = VaultPin{Version: res.VaultVersion, Generation: gen, SHA256: sha(put.Blob), SyncedAt: now}
	a.UI.Printf("✓ Created the vault account with this machine's identity as its user key.\n")
	return nil
}

// selfAdd adds this device to the chain with a user key it obtained itself.
func (a *Account) selfAdd(ctx context.Context, st *chain.State, d chain.Device, proof *envelope.Envelope, id *identity.Identity, method, slot string) error {
	link, err := st.NewLink(chain.TypeDeviceAdd, chain.DeviceAddBody{Device: d, Proof: *proof, Method: method, Slot: slot}, a.Now(), id.Sign)
	if err != nil {
		return err
	}
	next, err := st.Next(link)
	if err != nil {
		return err
	}
	box, err := a.boxFor(next, id, d)
	if err != nil {
		return err
	}
	if _, err := a.Client.Commit(ctx, &wire.Commit{Links: []*envelope.Envelope{link}, DeviceBoxes: []wire.DeviceBox{box}}); err != nil {
		return fmt.Errorf("add this device: %w", err)
	}
	if err := a.installIdentity(ctx, id, next); err != nil {
		return err
	}
	a.State.pin(next)
	a.UI.Printf("✓ Added this device using %s.\n", method)
	return nil
}

// fromPhrase recovers the user key from the recovery phrase and the
// server's master-wrapped copy, then checks it against the chain.
func (a *Account) fromPhrase(ctx context.Context, st *chain.State, opts LoginOptions) (*identity.Identity, error) {
	blob, err := a.Client.Identity(ctx)
	if err != nil {
		return nil, err
	}
	h, err := identity.ReadHeader(blob.Blob)
	if err != nil {
		return nil, err
	}
	mnemonic := opts.Mnemonic
	if mnemonic == "" {
		if mnemonic, err = a.UI.Secret("Recovery phrase (24 words): "); err != nil {
			return nil, err
		}
	}
	mnemonic = normalizeMnemonic(mnemonic)
	pass := opts.Passphrase
	if h.Passphrased && pass == "" {
		if pass, err = a.UI.Secret("Recovery passphrase: "); err != nil {
			return nil, err
		}
	}
	masterPub, masterPriv, err := identity.DeriveMaster(mnemonic, pass)
	if err != nil {
		return nil, err
	}
	if masterPub != st.MasterPub {
		return nil, errors.New("that recovery phrase (and passphrase) does not belong to this account")
	}
	id, err := identity.UnwrapBytes(blob.Blob, masterPub, masterPriv, h.Passphrased)
	if err != nil {
		return nil, err
	}
	m, err := ukey.FromIdentity(a.State.User, st.UKeyVersion, id)
	if err != nil {
		return nil, err
	}
	return m.Check(st)
}

// fromAgent unwraps the user key from an agent unlock slot.
func (a *Account) fromAgent(ctx context.Context, st *chain.State, socket string) (*identity.Identity, string, error) {
	var ag *sshagent.Agent
	var err error
	if socket != "" {
		ag, err = sshagent.DialPath(socket)
	} else {
		ag, err = sshagent.Dial()
	}
	if err != nil {
		return nil, "", err
	}
	defer ag.Close()
	slots, err := a.Client.AgentSlots(ctx)
	if err != nil {
		return nil, "", err
	}
	now := a.Now()
	var lastErr error = errors.New("no SSH-agent unlock slot matches a key in the agent; add one with 'esec vault agent-unlock enable' on a trusted device")
	for _, sl := range slots {
		cs, ok := st.UsableSlot(sl.SlotID, now)
		if !ok || cs.SSHKeyFP != sl.SSHKeyFP || sl.UKeyVersion != st.UKeyVersion {
			continue
		}
		key, err := ag.Find(sl.SSHKeyFP)
		if err != nil {
			continue
		}
		a.UI.Printf("Unlocking with SSH key %s (slot %s); your agent may ask for confirmation.\n", key.Fingerprint, sl.SlotID)
		secret, err := ag.Secret(key, ukey.SlotNamespace, ukey.SlotChallenge(a.State.User, sl.SlotID, sl.Salt))
		if err != nil {
			lastErr = err
			continue
		}
		kek, err := ukey.SlotKEK(secret, sl.Salt)
		if err != nil {
			return nil, "", err
		}
		m, err := ukey.OpenSlot(sl.Box, kek, a.State.User, sl.SlotID)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := m.Check(st)
		if err != nil {
			lastErr = err
			continue
		}
		return id, sl.SlotID, nil
	}
	return nil, "", lastErr
}

// waitForApproval waits until a trusted device approves this one, then
// installs the user key from this device's box.
func (a *Account) waitForApproval(ctx context.Context, d chain.Device, poll time.Duration) error {
	a.UI.Printf("Waiting for approval. On a trusted device run: esec vault devices approve\n")
	a.UI.Printf("Check that it shows this fingerprint: %s\n", a.Device.Words())
	a.UI.Printf("Other options: esec vault login --ssh-agent, esec vault login --recover\n")
	if poll <= 0 {
		poll = 3 * time.Second
	}
	for {
		me, err := a.Client.Me(ctx)
		if err != nil {
			return err
		}
		if me.Device.Status == wire.DeviceActive {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	st, err := a.VerifiedChain(ctx)
	if err != nil {
		return err
	}
	ds, ok := st.ActiveDevice(d.ID)
	if !ok {
		return errors.New("the server approved this device, but the verified chain does not include it")
	}
	id, err := a.userKey(ctx, st)
	if err != nil {
		return err
	}
	_ = id
	a.State.pin(st)
	approver := ds.ApprovedBy
	if ad, ok := st.Devices[ds.ApprovedBy]; ok {
		approver = ad.Name
	}
	a.UI.Printf("✓ Approved by %s.\n", approver)
	return nil
}
