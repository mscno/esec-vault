package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

// queueGroupAlert queues the alert of a group link, if it has one: a
// machine let in (by an admin or a token), a machine or token removed, an
// admin added. They go to the group's admins.
func (s *Server) queueGroupAlert(ctx context.Context, tx queryer, before, after *team.GroupState, l team.GroupLink, ip string, now time.Time) error {
	if !s.alertsOn() {
		return nil
	}
	var kind, title, text, advice string
	actor := groupActor(before, l.Signer)
	switch l.Type {
	case team.GroupMachineAdd:
		var b team.GroupMachineAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		kind, title = alertGroupMachine, "Machine added to "+after.Group
		text = fmt.Sprintf("%s added the machine %s to the machine group %s. It reads every environment the group reads.", actor, quoteName(b.Machine.Name), after.Group)
		advice = "If this was not expected, remove it with 'esec vault group remove " + after.Group + " " + b.Machine.ID + "', and give the group's environments new keys."
	case team.GroupRemove:
		var b team.GroupRemoveBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		c := before.Creds[b.ID]
		if c == nil {
			return nil
		}
		kind, title = alertGroupRemoved, "Machine removed from "+after.Group
		text = fmt.Sprintf("%s removed the %s %s from the machine group %s.", actor, c.Kind, quoteName(c.Name), after.Group)
		if !b.Destroyed {
			text += " It could read the group's environments, so their keys need replacing."
			advice = "Project admins run 'esec vault env rotate ENV' for each environment the group reads; 'esec vault group show " + after.Group + "' lists them."
		}
	case team.GroupAdminAdd:
		var b team.GroupAdminAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return err
		}
		kind, title = alertGroupAdmin, b.Admin.Login+" became an admin of "+after.Group
		text = fmt.Sprintf("%s made %s an admin of the machine group %s. Admins add and remove its machines.", actor, b.Admin.Login, after.Group)
	default:
		return nil
	}
	who := l.Signer
	if team.ValidCredID(who) == nil {
		// A token enrolled the machine: the alert is about the account
		// that created the group.
		who = after.Links[0].Signer
	}
	a, err := s.actorAlert(ctx, tx, kind, who, now)
	if err != nil {
		return err
	}
	a.Group, a.IP, a.URL = after.Group, ip, s.cfg.BaseURL+"/groups/"+after.Group
	a.Title, a.Text, a.Advice = title, text, advice
	recipients := make([]string, 0, len(after.Admins))
	for _, ad := range after.ActiveAdmins() {
		recipients = append(recipients, ad.User)
	}
	return s.queueAlertTo(ctx, tx, a, recipients)
}

// groupActor names who made a group link: an admin's login, or the token.
func groupActor(gs *team.GroupState, signer string) string {
	if a := gs.Admins[signer]; a != nil {
		return a.Login
	}
	if c := gs.Creds[signer]; c != nil {
		return "the enrollment token " + quoteName(c.Name)
	}
	return signer
}

func ed25519Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig)
}

// tokenHash is the hex SHA-256 of an OIDC token, or "" for none.
func tokenHash(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
