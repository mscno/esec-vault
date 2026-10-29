package account

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

// RequestTransfer prepares a source-authorized init for the receiving owner
// to countersign. Keys are sealed only to the verified receiving account.
func (a *Account) RequestTransfer(ctx context.Context, source, destination, login, accountKey string) (string, error) {
	var id string
	err := a.withTeam(ctx, func(t *teamCtx) error {
		old, err := t.requireAdmin(source)
		if err != nil {
			return err
		}
		if old.Archived {
			return fmt.Errorf("source is archived")
		}
		sourceOrg, err := t.requireOrgAdmin(team.OrgOf(source))
		if err != nil {
			return err
		}
		if !sourceOrg.Owner(a.State.User) {
			return fmt.Errorf("source tenant owner authorization is required")
		}
		if !t.trusted(sourceOrg) {
			return errUntrusted(sourceOrg)
		}
		from, err := a.Client.Namespace(ctx, team.OrgOf(source))
		if err != nil {
			return err
		}
		to, err := a.Client.Namespace(ctx, team.OrgOf(destination))
		if err != nil {
			return err
		}
		if from.TenantID == to.TenantID {
			return fmt.Errorf("use access move to rename within a tenant")
		}
		if to.Root == "" {
			return fmt.Errorf("receiving tenant must initialize its signed chain first")
		}
		person, cs, proof, err := t.lookupPerson(login)
		if err != nil {
			return err
		}
		if _, err := checkPerson(person, proof, cs, accountKey); err != nil {
			return err
		}
		keys := t.localKeys(old)
		if len(keys) != len(old.Envs) {
			return fmt.Errorf("prepare the transfer on a device holding all current environment keys")
		}
		now := a.Now().UTC().Truncate(time.Second)
		body := team.InitBody{Creator: person, Predecessor: &team.ProjectRef{Project: source, Root: old.Root()}}
		for _, name := range old.EnvNames() {
			body.Envs = append(body.Envs, old.Envs[name].Env)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		init, err := envelope.New(team.KindLink, team.Link{Project: destination, Seq: 1, CTime: now, Type: team.TypeInit, Signer: person.User, SignerKey: cs.UKeyVersion, SignerSeq: cs.Seq, Body: raw})
		if err != nil {
			return err
		}
		archive, _, err := t.link(old, team.TypeArchive, team.ArchiveBody{Reason: "transfer to " + destination, Successor: &team.ProjectRef{Project: destination, Root: init.Hash()}})
		if err != nil {
			return err
		}
		o := team.TransferOffer{Source: source, Destination: destination, SourceRoot: old.Root(), SourceHead: old.Head(), SourceTenant: from.TenantID, SourceOrgRoot: sourceOrg.Root(), DestinationTenant: to.TenantID, DestinationOrgRoot: to.Root, Sender: a.State.User, SenderKey: t.own.UKeyVersion, Recipient: person.User, RecipientRoot: cs.Root(), RecipientKey: cs.UKeyVersion, RecipientEncPub: hex.EncodeToString(cs.EncPub[:]), Init: init, Archive: archive, Created: now, Expires: now.Add(24 * time.Hour)}
		if err := team.SealTransferKeys(&o, keys, cs.EncPub); err != nil {
			return err
		}
		e, err := envelope.New(team.KindTransferOffer, o, t.id.Sign)
		if err != nil {
			return err
		}
		t.pins.Signed[archive.Hash()] = true
		id, err = a.Client.RequestTransfer(ctx, e)
		return err
	})
	return id, err
}

// AcceptTransfer verifies the source, source owner and selected account key
// before opening keys. It stores keys locally before the server's atomic move,
// so a lost response cannot strand an archived project's only usable copy.
func (a *Account) AcceptTransfer(ctx context.Context, id, accountKey string) error { //nolint:gocyclo // keep source consent, ownership and local key installation in review order
	return a.withTeam(ctx, func(t *teamCtx) error {
		view, err := a.Client.Transfer(ctx, id)
		if err != nil {
			return err
		}
		if view.Summary.Status != "pending" {
			return fmt.Errorf("transfer is no longer pending")
		}
		t.give(view.Project.Chains)
		t.give(view.SourceTenant.Chains)
		var peek team.TransferOffer
		if err := view.Offer.Decode(&peek); err != nil {
			return err
		}
		source, err := team.Verify(peek.Source, view.Project.Links, t.chains)
		if err != nil {
			return err
		}
		o, err := team.CheckTransferOffer(view.Offer, source, t.chains, a.Now())
		if err != nil {
			return err
		}
		if o.Recipient != a.State.User || o.RecipientKey != t.own.UKeyVersion {
			return fmt.Errorf("this account is not the selected recipient")
		}
		known, err := a.Client.PersonByID(ctx, o.Sender)
		if err != nil {
			return err
		}
		person, cs, proof, err := t.lookupPerson(known.User.Login)
		if err != nil {
			return err
		}
		if person.User != o.Sender || cs.Root() != source.Members[o.Sender].Root {
			return fmt.Errorf("sender's identity was substituted")
		}
		if _, err := checkPerson(person, proof, cs, accountKey); err != nil {
			return err
		}
		sourceOrg, err := team.VerifyOrg(view.SourceTenant.Canonical, view.SourceTenant.Links, t.chains)
		if err != nil {
			return err
		}
		if sourceOrg.Root() != o.SourceOrgRoot || !sourceOrg.Owner(o.Sender) {
			return fmt.Errorf("source tenant owner did not authorize the offer")
		}
		destOrg, err := t.requireOrgAdmin(team.OrgOf(o.Destination))
		if err != nil {
			return err
		}
		if !destOrg.Owner(a.State.User) || destOrg.Root() != o.DestinationOrgRoot {
			return fmt.Errorf("this account does not own the specified receiving tenant")
		}
		if !t.trusted(destOrg) {
			return errUntrusted(destOrg)
		}
		n, err := a.Client.Namespace(ctx, team.OrgOf(o.Destination))
		if err != nil {
			return err
		}
		if n.TenantID != o.DestinationTenant {
			return fmt.Errorf("destination tenant identity changed")
		}
		keys, err := team.OpenTransferKeys(o, t.id.Public, t.id.Private)
		if err != nil {
			return err
		}
		entries := map[string]string{}
		for env, key := range keys {
			entries[team.EnvKey(env)] = key
			pub, _ := team.PublicHex(key)
			entries[team.PubKeyEntry(pub)] = key
		}
		if existing, err := a.KS.Read(o.Destination); err == nil {
			if !maps.Equal(existing, entries) {
				return fmt.Errorf("a different local destination keyring exists")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if err := a.KS.Write(o.Destination, entries, false); err != nil {
			return err
		}
		init := team.SignTransferInit(o, t.id.Sign)
		st, err := team.Verify(o.Destination, []*envelope.Envelope{init}, t.chains)
		if err != nil {
			return err
		}
		if err := a.Client.AcceptTransfer(ctx, id, init); err != nil {
			return err
		}
		t.pin(st)
		t.pins.Accepted[st.Project] = true
		t.pins.Signed[init.Hash()] = true
		for env := range keys {
			t.pins.hold(st.Project, env, st.Envs[env].PublicKey)
		}
		return t.ackOwn(st)
	})
}
