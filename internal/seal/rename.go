package seal

import (
	"fmt"
	"time"

	"filippo.io/age"
	coreseal "github.com/mscno/esec/pkg/seal"
)

// Rename reseals a key to exactly the signed recipients, including recovery.
// It never resolves readers anew or weakens guarded recipients.
func Rename(project, old, next, private string, data []byte, record *Record, signer Signer) ([]byte, *Record, error) {
	if record == nil {
		return nil, nil, fmt.Errorf("seal has no signed record")
	}
	if err := record.Verify(project, old); err != nil {
		return nil, nil, err
	}
	if record.Sealed != coreseal.Hash(data) {
		return nil, nil, fmt.Errorf("seal differs from its signed record")
	}
	pub, err := coreseal.PublicHex(private)
	if err != nil || pub != record.Key {
		return nil, nil, fmt.Errorf("seal key does not match its record")
	}
	var recipients []age.Recipient
	for _, reader := range record.Readers {
		for _, name := range reader.Recipients {
			r, err := coreseal.ParseRecipient(name)
			if err != nil {
				return nil, nil, err
			}
			recipients = append(recipients, r)
		}
	}
	if len(record.Recovery) == 0 {
		return nil, nil, fmt.Errorf("seal has no recovery recipient")
	}
	for _, name := range record.Recovery {
		r, err := coreseal.ParseRecipient(name)
		if err != nil {
			return nil, nil, err
		}
		recipients = append(recipients, r)
	}
	sealed, err := coreseal.Seal(coreseal.Payload{Project: project, Env: next, Guard: record.Guard, Private: private}, recipients...)
	if err != nil {
		return nil, nil, err
	}
	rec := *record
	rec.Sealed = coreseal.Hash(sealed)
	rec.At = time.Now().UTC()
	rec.Sign(project, next, signer.By, signer.Key)
	return sealed, &rec, nil
}
