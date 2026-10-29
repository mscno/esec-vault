package team

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/mscno/esec-vault/internal/chain"
	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec/pkg/crypto"
)

// KindTransferOffer domain-separates transfer consent from other signatures.
const KindTransferOffer = "project-transfer"

// TransferOffer binds the exact source head, receiving tenant, recipient key,
// destination init and source archive. The unsigned init can be countersigned
// later: envelope hashes exclude signatures, so the source already pins it.
type TransferOffer struct {
	Source             string             `json:"source"`
	Destination        string             `json:"destination"`
	SourceRoot         string             `json:"source_root"`
	SourceHead         string             `json:"source_head"`
	SourceTenant       string             `json:"source_tenant"`
	SourceOrgRoot      string             `json:"source_org_root"`
	DestinationTenant  string             `json:"destination_tenant"`
	DestinationOrgRoot string             `json:"destination_org_root"`
	Sender             string             `json:"sender"`
	SenderKey          uint64             `json:"sender_key"`
	Recipient          string             `json:"recipient"`
	RecipientRoot      string             `json:"recipient_root"`
	RecipientKey       uint64             `json:"recipient_key"`
	RecipientEncPub    string             `json:"recipient_enc_pub"`
	Init               *envelope.Envelope `json:"init"`
	Archive            *envelope.Envelope `json:"archive"`
	Box                []byte             `json:"box"`
	Created            time.Time          `json:"created"`
	Expires            time.Time          `json:"expires"`
}

// TransferKeys binds sealed environment keys to the exact proposed init.
type TransferKeys struct {
	Destination string            `json:"destination"`
	InitHash    string            `json:"init_hash"`
	Recipient   string            `json:"recipient"`
	Keys        map[string]string `json:"keys"`
}

// CheckTransferOffer validates source consent, recipient identity and freshness.
func CheckTransferOffer(e *envelope.Envelope, source *State, chains Chains, now time.Time) (*TransferOffer, error) {
	var o TransferOffer
	if err := e.Check(); err != nil {
		return nil, err
	}
	if e.Kind != KindTransferOffer {
		return nil, errors.New("not a project transfer offer")
	}
	if err := e.Decode(&o); err != nil {
		return nil, err
	}
	if err := o.checkSource(source, now); err != nil {
		return nil, err
	}
	sender, err := chains(o.Sender)
	if err != nil {
		return nil, err
	}
	if sender.UKeyVersion != o.SenderKey || sender.Root() != source.Members[o.Sender].Root {
		return nil, errors.New("sender's account key changed")
	}
	if err := e.Require(KindTransferOffer, sender.SignPub); err != nil {
		return nil, err
	}
	recipient, err := chains(o.Recipient)
	if err != nil {
		return nil, err
	}
	if recipient.Root() != o.RecipientRoot || recipient.UKeyVersion != o.RecipientKey || hex.EncodeToString(recipient.EncPub[:]) != o.RecipientEncPub {
		return nil, errors.New("recipient's account key changed; recreate the offer")
	}
	init, err := o.checkRecipientInit(recipient)
	if err != nil {
		return nil, err
	}
	if err := o.checkEnvironments(init, source); err != nil {
		return nil, err
	}
	if err := o.checkArchive(source, chains); err != nil {
		return nil, err
	}
	return &o, nil
}

func (o *TransferOffer) checkSource(source *State, now time.Time) error {
	if o.Source != source.Project || o.SourceRoot != source.Root() || o.SourceHead != source.Head() || source.Archived || !source.Admin(o.Sender) {
		return errors.New("transfer source changed or sender is not its admin")
	}
	if ValidProject(o.Destination) != nil || o.Source == o.Destination || !ValidTenantID(o.SourceTenant) || !ValidTenantID(o.DestinationTenant) || len(o.Box) == 0 || len(o.Box) > 32<<10 {
		return errors.New("invalid transfer identity or delivery")
	}
	if o.Created.IsZero() || o.Created.After(now.Add(10*time.Minute)) || !o.Expires.After(now) || o.Expires.After(o.Created.Add(24*time.Hour)) {
		return errors.New("transfer offer expired or has an invalid lifetime")
	}
	return nil
}
func (o *TransferOffer) checkRecipientInit(recipient *chain.State) (InitBody, error) {
	var init InitBody
	l, err := PeekLink(o.Init)
	if err != nil {
		return init, err
	}
	if err := envelope.DecodeStrict(l.Body, &init); err != nil {
		return init, err
	}
	if l.Project != o.Destination || l.Seq != 1 || l.Prev != "" || l.Type != TypeInit || l.Signer != o.Recipient || l.SignerKey != o.RecipientKey || l.SignerSeq > recipient.Seq || l.SignerDelegate != "" || init.Creator.User != o.Recipient || init.Creator.Root != recipient.Root() {
		return init, errors.New("destination init is not for the selected recipient")
	}
	return init, nil
}
func (o *TransferOffer) checkEnvironments(init InitBody, source *State) error {
	if init.Predecessor == nil || init.Predecessor.Project != o.Source || init.Predecessor.Root != o.SourceRoot || len(init.Envs) != len(source.Envs) {
		return errors.New("destination does not preserve the source project")
	}
	seen := map[string]bool{}
	for _, env := range init.Envs {
		e, ok := source.Envs[env.Name]
		if !ok || seen[env.Name] || e.PublicKey != env.PublicKey {
			return errors.New("destination environment keys do not match the source")
		}
		seen[env.Name] = true
	}
	return nil
}
func (o *TransferOffer) checkArchive(source *State, chains Chains) error {
	archived, err := source.Next(o.Archive, chains)
	if err != nil {
		return err
	}
	if !archived.Archived || archived.Successor == nil || archived.Successor.Project != o.Destination || archived.Successor.Root != o.Init.Hash() {
		return errors.New("source archive does not authorize this destination")
	}
	return nil
}

// SealTransferKeys encrypts delivery only to the selected recipient account.
func SealTransferKeys(o *TransferOffer, keys map[string]string, pub [32]byte) error {
	plain, err := json.Marshal(TransferKeys{Destination: o.Destination, InitHash: o.Init.Hash(), Recipient: o.Recipient, Keys: keys})
	if err != nil {
		return err
	}
	o.Box, err = crypto.SealAnonymous(plain, &pub)
	return err
}

// OpenTransferKeys checks the decrypted keys against the signed init.
func OpenTransferKeys(o *TransferOffer, pub, priv [32]byte) (map[string]string, error) {
	plain, err := crypto.OpenAnonymous(o.Box, &pub, &priv)
	if err != nil {
		return nil, errors.New("transfer keys cannot be opened by this account")
	}
	var p TransferKeys
	if err := envelope.DecodeStrict(plain, &p); err != nil {
		return nil, err
	}
	if p.Destination != o.Destination || p.InitHash != o.Init.Hash() || p.Recipient != o.Recipient {
		return nil, errors.New("transfer key delivery was substituted")
	}
	l, err := PeekLink(o.Init)
	if err != nil {
		return nil, err
	}
	var init InitBody
	if err := envelope.DecodeStrict(l.Body, &init); err != nil {
		return nil, err
	}
	if len(p.Keys) != len(init.Envs) {
		return nil, errors.New("transfer is missing environment keys")
	}
	for _, env := range init.Envs {
		pub, err := PublicHex(p.Keys[env.Name])
		if err != nil || pub != env.PublicKey {
			return nil, errors.New("transfer environment key does not match its signed public key")
		}
	}
	return p.Keys, nil
}

// SignTransferInit accepts exactly the body the source already authorized.
func SignTransferInit(o *TransferOffer, key ed25519.PrivateKey) *envelope.Envelope {
	e := *o.Init
	e.Sigs = nil
	e.Passkey = nil
	e.AddSignature(key)
	return &e
}
