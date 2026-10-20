package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

// queueProjectAlert queues the alert of a project link, if it has one:
// members joining or leaving, and machines added or removed. A removal
// alert goes to every remaining member, since the keys it exposed need
// replacing.
func (s *Server) queueProjectAlert(ctx context.Context, tx queryer, before, after *team.State, l team.Link, ip string, now time.Time) error {
	if !s.alertsOn() {
		return nil
	}
	pa, err := describeProjectLink(before, after, l)
	if err != nil || pa == nil {
		return err
	}
	a, err := s.actorAlert(ctx, tx, pa.kind, l.Signer, now)
	if err != nil {
		return err
	}
	a.Project, a.IP, a.URL = after.Project, ip, s.cfg.BaseURL+"/teams/"+after.Project
	a.Title = projectAlertTitle(pa.kind, pa.subject)
	a.Text, a.Advice = pa.text, pa.advice
	return s.queueAlertTo(ctx, tx, a, pa.recipients)
}

// queueAlertTo queues a to the webhook and by email to recipients (account
// ids) and the operator's addresses.
func (s *Server) queueAlertTo(ctx context.Context, tx queryer, a *alert, recipients []string) error {
	if s.cfg.Alerts.Webhook() {
		if err := s.insertAlert(ctx, tx, a, channelWebhook, ""); err != nil {
			return err
		}
	}
	if !s.cfg.Alerts.Email() {
		return nil
	}
	to := make([]string, 0, len(recipients)+len(s.cfg.Alerts.EmailTo))
	for _, u := range recipients {
		var addr string
		err := tx.QueryRowContext(ctx, `SELECT alert_email FROM users WHERE id = ?`, u).Scan(&addr)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		to = append(to, addr)
	}
	seen := map[string]bool{}
	for _, addr := range append(to, s.cfg.Alerts.EmailTo...) {
		if addr == "" || seen[strings.ToLower(addr)] {
			continue
		}
		seen[strings.ToLower(addr)] = true
		if err := s.insertAlert(ctx, tx, a, channelEmail, addr); err != nil {
			return err
		}
	}
	return nil
}

// projectAlert is what an alert about a project link says, and to whom.
type projectAlert struct {
	kind, subject, text, advice string
	recipients                  []string
}

// describeProjectLink returns the alert of a link, or nil for links that
// raise none.
func describeProjectLink(before, after *team.State, l team.Link) (*projectAlert, error) {
	actor := loginOf(after, l.Signer)
	switch l.Type {
	case team.TypeMemberAdd:
		var b team.MemberAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return nil, err
		}
		role := "reads " + envList(b.Envs)
		if b.Admin {
			role = "admin, reads every environment"
		}
		return &projectAlert{kind: alertMemberAdded, subject: b.Member.Login, recipients: []string{b.Member.User},
			text:   fmt.Sprintf("%s added %s to the shared project %s (%s).", actor, b.Member.Login, after.Project, role),
			advice: "If this was not expected, an admin removes them with 'esec vault team remove " + b.Member.Login + "' in the project, then gives the environments they could read new keys."}, nil
	case team.TypeMemberRemove:
		var b team.MemberRemoveBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return nil, err
		}
		m := before.Members[b.User]
		if m == nil {
			return nil, nil
		}
		text := fmt.Sprintf("%s removed %s from the shared project %s.", actor, m.Login, after.Project)
		if b.User == l.Signer {
			text = fmt.Sprintf("%s left the shared project %s.", m.Login, after.Project)
		}
		if could := before.Access(b.User); len(could) > 0 {
			text += fmt.Sprintf(" They could read %s, so those environments need new keys.", envList(could))
		}
		return &projectAlert{kind: alertMemberRemoved, subject: m.Login, text: text, recipients: append(memberIDs(after), b.User),
			advice: "An admin runs 'esec vault env rotate ENV' in the project for each environment listed, and changes the secret values themselves where they may have been seen. The project page lists what is left to do."}, nil
	case team.TypeMachineAdd:
		var b team.MachineAddBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return nil, err
		}
		text := fmt.Sprintf("%s added the machine %s to the shared project %s. It reads %s", actor, quoteName(b.Machine.Name), after.Project, envList(b.Envs))
		if b.OIDC != nil {
			text += ", from " + b.OIDC.Describe()
		}
		return &projectAlert{kind: alertMachineAdded, subject: b.Machine.Name, text: text + ".", recipients: adminIDs(after),
			advice: "If this was not expected, remove it with 'esec vault machine remove " + b.Machine.ID + "' in the project, and give its environments new keys."}, nil
	case team.TypeMachineRemove:
		var b team.MachineRemoveBody
		if err := envelope.DecodeStrict(l.Body, &b); err != nil {
			return nil, err
		}
		m := before.Machines[b.ID]
		if m == nil {
			return nil, nil
		}
		return &projectAlert{kind: alertMachineRemoved, subject: m.Name, recipients: adminIDs(after),
			text:   fmt.Sprintf("%s removed the machine %s from the shared project %s. It could read %s, so those environments need new keys.", actor, quoteName(m.Name), after.Project, envList(m.Envs)),
			advice: "An admin runs 'esec vault env rotate ENV' in the project for each environment listed."}, nil
	}
	return nil, nil
}

func projectAlertTitle(kind, subject string) string {
	switch kind {
	case alertMemberAdded:
		return subject + " joined a shared project"
	case alertMemberRemoved:
		return subject + " left a shared project"
	case alertMachineAdded:
		return "Machine added to a shared project"
	}
	return "Machine removed from a shared project"
}

// actorAlert starts an alert about something an account did.
func (s *Server) actorAlert(ctx context.Context, q queryer, kind, user string, now time.Time) (*alert, error) {
	u := &userRow{ID: user}
	if err := q.QueryRowContext(ctx, `SELECT github_id, login FROM users WHERE id = ?`, user).Scan(&u.GitHubID, &u.Login); err != nil {
		return nil, err
	}
	return &alert{Type: kind, Time: now.UTC().Truncate(time.Second), Server: s.cfg.BaseURL, Account: alertAccount{ID: u.ID, GitHubID: u.GitHubID, Login: u.Login}}, nil
}

func loginOf(st *team.State, user string) string {
	if m := st.Members[user]; m != nil {
		return m.Login
	}
	return user
}

func memberIDs(st *team.State) []string {
	members := st.ActiveMembers()
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.User)
	}
	return out
}

func adminIDs(st *team.State) []string {
	var out []string
	for _, m := range st.ActiveMembers() {
		if m.Admin {
			out = append(out, m.User)
		}
	}
	return out
}
