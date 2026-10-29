package team

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var tenantIDPattern = regexp.MustCompile(`^t_[0-9a-f]{32}$`)
var namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,38}$`)

// NewTenantID is an immutable identity, independent of a namespace handle.
func NewTenantID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "t_" + hex.EncodeToString(b[:]), nil
}

// ValidTenantID checks the opaque tenant identifier format.
func ValidTenantID(id string) bool { return tenantIDPattern.MatchString(id) }

// ValidNamespace checks a normalized namespace handle.
func ValidNamespace(name string) bool { return namespacePattern.MatchString(name) }

// PersonalCandidates suggests normalized handles; availability must be checked
// separately and the eventual claim remains atomic.
func PersonalCandidates(login string) []string {
	base := strings.ToLower(login)
	if len(base) > 28 {
		base = base[:28]
	}
	if !ValidNamespace(base) {
		base = "personal"
	}
	return []string{base + "-personal", fmt.Sprintf("%s-2", base), fmt.Sprintf("%s-3", base)}
}

// HasNamespace verifies both the current handle and its signed historical aliases.
func (s *OrgState) HasNamespace(name string) bool { return s.Aliases[strings.ToLower(name)] }

// ContainsProject includes resources under signed historical namespace aliases.
func (s *OrgState) ContainsProject(id string) bool { return s.HasNamespace(OrgOf(id)) }

// ValidDisplayName bounds a human-readable label and refuses control characters.
func ValidDisplayName(name string) bool {
	return utf8.ValidString(name) && len(name) <= 100 && name == strings.TrimSpace(name) && strings.IndexFunc(name, unicode.IsControl) == -1
}

func (s *OrgState) applyOwner(l OrgLink) error {
	var b OrgOwnerBody
	if err := decodeOrgBody(l, &b); err != nil {
		return err
	}
	if !s.Admin(b.User) {
		return errors.New("an owner must first be an active tenant admin")
	}
	if !b.Owner && s.Owner(b.User) && s.OwnerCount() == 1 {
		return errors.New("a tenant must retain at least one owner")
	}
	if !s.ExplicitOwners {
		for user := range s.Admins {
			if s.Admin(user) {
				s.Owners[user] = true
			}
		}
		s.ExplicitOwners = true
	}
	s.Owners[b.User] = b.Owner
	return nil
}

func (s *OrgState) applyProfile(l OrgLink) error {
	var b OrgProfileBody
	if err := decodeOrgBody(l, &b); err != nil {
		return err
	}
	if !ValidTenantID(b.TenantID) || !ValidNamespace(b.Namespace) || !ValidDisplayName(b.DisplayName) {
		return errors.New("invalid tenant profile")
	}
	if s.TenantID != "" && s.TenantID != b.TenantID {
		return errors.New("a tenant's identity cannot change")
	}
	s.TenantID, s.Namespace, s.DisplayName = b.TenantID, b.Namespace, b.DisplayName
	s.Aliases[b.Namespace] = true
	return nil
}
