package wire

import "github.com/mscno/esec-vault/internal/envelope"

// TransferRequest submits source consent and a sealed delivery.
type TransferRequest struct {
	Offer *envelope.Envelope `json:"offer"`
}

// TransferAccept supplies the recipient's signature over the exact proposed init.
type TransferAccept struct {
	Init *envelope.Envelope `json:"init"`
}

// TransferSummary contains no private environment keys.
type TransferSummary struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Sender      string `json:"sender"`
	Recipient   string `json:"recipient"`
	Expires     int64  `json:"expires"`
	Status      string `json:"status"`
}

// TransferView includes the public chains needed to verify a pending offer.
type TransferView struct {
	Summary      TransferSummary    `json:"summary"`
	Offer        *envelope.Envelope `json:"offer"`
	Project      ProjectChain       `json:"project"`
	SourceTenant OrgChain           `json:"source_tenant"`
}
