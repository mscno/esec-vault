package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/team"
)

// ProjectTransferCmd moves immediately or offers a project to another owner.
type ProjectTransferCmd struct {
	Source     string `arg:"" optional:"" help:"Source project (default: nearest esec.toml)"`
	To         string `required:"" help:"Destination project id, TENANT/PROJECT"`
	Recipient  string `help:"Receiving tenant owner's GitHub login; creates a 24-hour acceptance request"`
	AccountKey string `help:"Receiving owner's account key words, instead of a GitHub SSH proof"`
	Yes        bool   `help:"Skip confirmation"`
}

// Run implements project transfer.
func (c *ProjectTransferCmd) Run(ctx *cliCtx) error {
	if c.Recipient == "" {
		return (&AccessMoveCmd{Project: c.Source, To: c.To, Yes: c.Yes}).Run(ctx)
	}
	source, err := projectFlag(c.Source)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Offer %s to %s in %s? Keys are encrypted to that account; its owner must accept. No source collaborators are copied.", source, c.Recipient, c.To)) {
		return errors.New("cancelled")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	id, err := a.RequestTransfer(bg, source, c.To, c.Recipient, c.AccountKey)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Transfer offered: %s\nRecipient: esec vault transfers accept %s\nSource stays active until acceptance. The offer expires in 24 hours.\n", id, id)
	return nil
}

// TransfersCmd reviews and resolves pending transfer offers.
type TransfersCmd struct {
	List   TransfersListCmd   `cmd:"" default:"withargs" help:"List pending incoming and outgoing transfers."`
	Show   TransfersShowCmd   `cmd:"" help:"Inspect an offer without decrypting its keys."`
	Accept TransfersAcceptCmd `cmd:"" help:"Verify the source owner and accept a transfer atomically."`
	Reject TransfersCancelCmd `cmd:"" help:"Reject an incoming offer."`
	Cancel TransfersCancelCmd `cmd:"" help:"Cancel an outgoing offer."`
}

// TransfersListCmd lists offers without decrypting any keys.
type TransfersListCmd struct {
	JSON bool `help:"Print JSON"`
}

// Run implements transfers list.
func (c *TransfersListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	list, err := a.Client.Transfers(bg)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(list)
	}
	for _, v := range list {
		direction := "incoming"
		if v.Sender == a.State.User {
			direction = "outgoing"
		}
		fmt.Printf("%s %s %s -> %s\n", v.ID, direction, v.Source, v.Destination)
	}
	if len(list) == 0 {
		fmt.Println("No pending transfers.")
	}
	return nil
}

// TransfersShowCmd shows public metadata and encrypted delivery.
type TransfersShowCmd struct {
	ID   string `arg:""`
	JSON bool   `help:"Print public offer metadata and ciphertext, never private keys"`
}

// Run implements transfers show.
func (c *TransfersShowCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	v, err := a.Client.Transfer(bg, c.ID)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(v)
	}
	var o team.TransferOffer
	if err := v.Offer.Decode(&o); err != nil {
		return err
	}
	fmt.Printf("%s\n%s -> %s\nSender: %s; receiver: %s\nExpires: %s\nDestination access: receiver only; no source collaborators or machines.\n", c.ID, o.Source, o.Destination, o.Sender, o.Recipient, o.Expires.Format(time.RFC3339))
	return nil
}

// TransfersAcceptCmd verifies consent and countersigns the exact destination.
type TransfersAcceptCmd struct {
	ID         string `arg:""`
	AccountKey string `help:"Source owner's account key words, instead of a GitHub SSH proof"`
	Yes        bool   `help:"Skip confirmation"`
}

// Run implements transfers accept.
func (c *TransfersAcceptCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	view, err := a.Client.Transfer(bg, c.ID)
	if err != nil {
		return err
	}
	var o team.TransferOffer
	if err := view.Offer.Decode(&o); err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Accept %s as %s from %s? Only your account gets destination access. Old readers still know the existing keys; rotate and re-encrypt to revoke them.", o.Source, o.Destination, o.Sender)) {
		return errors.New("cancelled")
	}
	if err := a.AcceptTransfer(bg, c.ID, c.AccountKey); err != nil {
		return err
	}
	fmt.Printf("✓ Accepted %s. Source is archived; update project in esec.toml to %q. Rotate keys to revoke former readers.\n", c.ID, o.Destination)
	return nil
}

// TransfersCancelCmd rejects or withdraws an offer.
type TransfersCancelCmd struct {
	ID string `arg:""`
}

// Run implements transfers cancel and reject.
func (c *TransfersCancelCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.Client.CancelTransfer(bg, c.ID); err != nil {
		return err
	}
	fmt.Println("✓ Transfer cancelled. Source project is unchanged.")
	return nil
}
