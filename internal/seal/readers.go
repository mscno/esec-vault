// Package seal makes, opens and checks the sealed environment keys of a
// project: .esec/<env>.age (core esec's format) for each environment's
// readers, and .esec/seals.toml, the signed record of who each seal was
// made for. People are named by GitHub id and resolved to keys through
// their signed chains; nobody handles a key string.
package seal

import (
	"fmt"
	"regexp"
	"strings"
)

// Reader kinds.
const (
	// KindPerson is a person, by GitHub id: "mads (gh:583231)".
	KindPerson = "person"
	// KindGroup is a machine group's key: "group acme/backend".
	KindGroup = "group"
	// KindKey is a key named directly: "deploy (age1…)", for machines and
	// for use without a server.
	KindKey = "key"
	// KindMe is whoever seals, before they sign in: "me". Sealing with an
	// account turns it into their GitHub id.
	KindMe = "me"
)

// Reader is one entry of an environment's readers in esec.toml.
type Reader struct {
	Kind string
	// ID is what counts: "gh:583231", "acme/backend", or the recipient.
	ID string
	// Label is for people to read: a login, a machine's name. It never
	// decides anything.
	Label string
}

var (
	personID  = regexp.MustCompile(`^gh:[1-9][0-9]{0,19}$`)
	labelText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)
	groupID   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
)

// ParseReader parses one readers entry.
func ParseReader(s string) (Reader, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "me":
		return Reader{Kind: KindMe, ID: "me"}, nil
	case strings.HasPrefix(s, "group "):
		id := strings.TrimSpace(strings.TrimPrefix(s, "group "))
		if !groupID.MatchString(id) {
			return Reader{}, fmt.Errorf("invalid group %q: use group ORG/NAME", id)
		}
		return Reader{Kind: KindGroup, ID: id}, nil
	case strings.HasSuffix(s, ")") && strings.Contains(s, " ("):
		i := strings.LastIndex(s, " (")
		label, id := strings.TrimSpace(s[:i]), s[i+2:len(s)-1]
		if label != "" && !labelText.MatchString(label) {
			return Reader{}, fmt.Errorf("invalid name %q in reader %q", label, s)
		}
		if personID.MatchString(id) {
			return Reader{Kind: KindPerson, ID: id, Label: label}, nil
		}
		if isRecipient(id) {
			return Reader{Kind: KindKey, ID: id, Label: label}, nil
		}
		return Reader{}, fmt.Errorf("reader %q: %q is neither gh:<id> nor an age recipient", s, id)
	case isRecipient(s):
		return Reader{Kind: KindKey, ID: s}, nil
	}
	return Reader{}, fmt.Errorf("invalid reader %q: use \"login (gh:ID)\", \"group ORG/NAME\", \"NAME (age1…)\" or \"me\"", s)
}

// String is the readers entry, as esec.toml holds it.
func (r Reader) String() string {
	switch r.Kind {
	case KindMe:
		return "me"
	case KindGroup:
		return "group " + r.ID
	}
	if r.Label == "" {
		return r.ID
	}
	return r.Label + " (" + r.ID + ")"
}

// Display is how people see the reader.
func (r Reader) Display() string {
	switch r.Kind {
	case KindPerson:
		if r.Label != "" {
			return r.Label
		}
		return r.ID
	case KindKey:
		if r.Label != "" {
			return r.Label + " (a key)"
		}
		return r.ID[:min(len(r.ID), 16)] + "…"
	}
	return r.String()
}

// ParseReaders parses an environment's readers.
func ParseReaders(list []string) ([]Reader, error) {
	out := make([]Reader, 0, len(list))
	seen := map[string]bool{}
	for _, s := range list {
		r, err := ParseReader(s)
		if err != nil {
			return nil, err
		}
		if seen[r.Kind+r.ID] {
			continue
		}
		seen[r.Kind+r.ID] = true
		out = append(out, r)
	}
	return out, nil
}

// Strings formats readers for esec.toml.
func Strings(readers []Reader) []string {
	out := make([]string, 0, len(readers))
	for _, r := range readers {
		out = append(out, r.String())
	}
	return out
}

func isRecipient(s string) bool {
	return strings.HasPrefix(s, "age1") || strings.HasPrefix(s, "ssh-ed25519 ") || strings.HasPrefix(s, "ssh-rsa ")
}
