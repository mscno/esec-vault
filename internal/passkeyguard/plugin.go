package passkeyguard

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

type recipient struct{ credential Credential }

func (r recipient) Wrap(key []byte) ([]*age.Stanza, error) {
	x, err := age.ParseX25519Recipient(r.credential.Recipient)
	if err != nil {
		return nil, err
	}
	inner, err := x.Wrap(key)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{Type: "esec-passkey-v1", Args: []string{r.credential.keyID()}, Body: body}}, nil
}

// One combined identity lets the system choose among all registered
// credentials in a single sheet, rather than prompting for each key.
type identities struct {
	credentials []Credential
	attempted   bool
	err         error
	id          age.Identity
	selected    string
}

func passkeyStanzas(stanzas []*age.Stanza) map[string][]*age.Stanza {
	available := map[string][]*age.Stanza{}
	for _, s := range stanzas {
		if s.Type != "esec-passkey-v1" || len(s.Args) != 1 || len(s.Body) > 1024 {
			continue
		}
		var inner []*age.Stanza
		if json.Unmarshal(s.Body, &inner) != nil || len(inner) != 1 || inner[0] == nil || inner[0].Type != "X25519" {
			continue
		}
		available[s.Args[0]] = inner
	}
	return available
}

func (i *identities) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	available := passkeyStanzas(stanzas)
	if !i.attempted {
		var candidates []Credential
		var inputs []Input
		var rp string
		for _, c := range i.credentials {
			if available[c.keyID()] == nil || (rp != "" && rp != c.RPID) {
				continue
			}
			rp = c.RPID
			candidates = append(candidates, c)
			inputs = append(inputs, Input{CredentialID: c.ID, Salt: c.Salt})
		}
		if len(candidates) == 0 {
			return nil, age.ErrIncorrectIdentity
		}
		i.attempted = true
		response, err := Native(context.Background(), Request{Operation: "assert", RPID: rp, Credentials: inputs})
		if err != nil {
			i.err = err
			return nil, err
		}
		defer clear(response.PRF)
		for _, c := range candidates {
			if string(c.ID) != string(response.CredentialID) {
				continue
			}
			i.id, i.err = c.open(response.PRF)
			i.selected = c.keyID()
			break
		}
		if i.id == nil && i.err == nil {
			i.err = errors.New("system returned an unrequested passkey")
		}
	}
	if i.err != nil {
		return nil, i.err
	}
	if available[i.selected] == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return i.id.Unwrap(available[i.selected])
}

// RunPlugin serves the age protocol. Encryption needs only the public
// recipient; decryption invokes the native system sheet once per process.
func RunPlugin(args []string) int {
	p, err := plugin.New("passkey")
	if err != nil {
		return 1
	}
	fs := flag.NewFlagSet("age-plugin-passkey", flag.ContinueOnError)
	p.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	shared := &identities{}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		c, err := Decode(data)
		return recipient{c}, err
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		c, err := Decode(data)
		if err != nil {
			return nil, fmt.Errorf("invalid passkey identity: %w", err)
		}
		shared.credentials = append(shared.credentials, c)
		return shared, nil
	})
	return p.Main()
}
