package account

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Changes to organisations made on the web pages, signed here. The server
// stores only what people asked for; this device builds each link from the
// verified chains, and reads a KMS key's public half from the KMS itself.

// applyOrgChange signs a change to an organisation.
func (a *Account) applyOrgChange(ctx context.Context, ch ChangeView) ([]string, error) {
	switch ch.Kind {
	case wire.ChangeOrgAdd:
		res, err := a.AddOrgPerson(ctx, ch.Target, ch.Subject, ch.Admin, "")
		if errors.Is(err, ErrNoProof) {
			return nil, fmt.Errorf("%w. Add them by hand with the account key words they read to you: esec vault org add %s %s --account-key '...'", err, ch.Target, ch.Subject)
		}
		if err != nil {
			return nil, err
		}
		role := "a member"
		if ch.Admin {
			role = "an admin"
		}
		return []string{fmt.Sprintf("Added %s to %s as %s, checked with their GitHub SSH key.", res.Login, ch.Target, role)}, nil
	case wire.ChangeOrgRemove:
		removals, err := a.RemoveOrgPerson(ctx, ch.Target, ch.Subject, "removed on the web")
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("Removed %s from %s.", ch.Subject, ch.Target)}
		for _, r := range removals {
			out = append(out, r.Line())
		}
		return out, nil
	case wire.ChangeOrgKMSAdd:
		k, err := orgKMSRequest(ctx, ch.Change)
		if err != nil {
			return nil, err
		}
		if err := a.ApproveKMS(ctx, ch.Target, k); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Approved the KMS key %s for the workloads of %s (public key read from the KMS, fingerprint %s).", k.Name, ch.Target, shortFingerprint(k.Key))}, nil
	case wire.ChangeOrgKMSRemove:
		users, err := a.WithdrawKMS(ctx, ch.Target, ch.Subject, "withdrawn on the web")
		if err != nil {
			return nil, err
		}
		out := []string{fmt.Sprintf("Withdrew the KMS key %s: no new workload uses it.", ch.Subject)}
		if len(users) > 0 {
			out = append(out, fmt.Sprintf("Still using it, until moved to another key: %s.", strings.Join(users, ", ")))
		}
		return out, nil
	case wire.ChangeOrgSettings:
		st, err := orgSettingsOf(ch.Change)
		if err != nil {
			return nil, err
		}
		if err := a.SetOrgSettings(ctx, ch.Target, st); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Set the settings of %s.", ch.Target)}, nil
	case wire.ChangeFlyApp:
		app, err := flyAppOf(ch.Change)
		if err != nil {
			return nil, err
		}
		res, err := a.AddFlyApp(ctx, ch.Target, app)
		if err != nil {
			return nil, err
		}
		return res.Lines(app), nil
	}
	return nil, errUnknownChange(ch)
}

// Lines describes what setting up a Fly.io app did.
func (r *FlyAppResult) Lines(app wire.FlyApp) []string {
	var out []string
	if r.CreatedGroup {
		out = append(out, fmt.Sprintf("Created the group %s.", app.Group))
	}
	for _, g := range r.Granted {
		out = append(out, fmt.Sprintf("%s reads %s.", app.Group, g))
	}
	for _, p := range r.Pending {
		out = append(out, fmt.Sprintf("%s asked to read %s: an admin of that project agrees with: esec vault changes", app.Group, p))
	}
	if r.Rekeyed {
		out = append(out, fmt.Sprintf("%s was set up already: moved it to the key %s.", app.App, app.KMS))
	}
	if r.Key != nil {
		out = append(out, fmt.Sprintf("Its group key is wrapped with %s: %s %s, fingerprint %s.", r.Key.Name, r.Key.Key.Provider, r.Key.Key.Name, shortFingerprint(r.Key.Key)))
	}
	if r.Ref != nil {
		out = append(out, fmt.Sprintf("The Fly.io app %s reads with no secret: its descriptor is on the group's page, and in 'esec vault group show %s'.", app.App, app.Group))
	}
	return out
}

// applyWorkloadRekey moves a workload to another approved key.
func (a *Account) applyWorkloadRekey(ctx context.Context, ch ChangeView) ([]string, error) {
	name, err := kmsNameOf(ch.Change)
	if err != nil {
		return nil, err
	}
	key, err := a.OrgKMSKey(ctx, team.OrgOf(ch.Target), name)
	if err != nil {
		return nil, err
	}
	v, err := a.Group(ctx, ch.Target)
	if err != nil {
		return nil, err
	}
	c, ok := v.State.Cred(ch.Subject)
	if !ok || c.Kind != team.KindWorkload {
		return nil, fmt.Errorf("%s has no workload %s", ch.Target, ch.Subject)
	}
	moved, err := a.RekeyWorkloads(ctx, ch.Target, []string{c.Name}, key.Key)
	if err != nil {
		return nil, err
	}
	if len(moved) == 0 {
		return []string{fmt.Sprintf("%s uses the key %s already.", c.Name, name)}, nil
	}
	return []string{fmt.Sprintf("Moved %s of %s to the key %s; its descriptor stays.", c.Name, ch.Target, name)}, nil
}

func orgKMSRequest(ctx context.Context, c wire.Change) (team.OrgKMSKey, error) {
	req, err := kmsRequestOf(c)
	if err != nil {
		return team.OrgKMSKey{}, err
	}
	k, err := kms.WithPublicKey(ctx, kms.Key{Provider: req.Provider, Name: req.Key, Audience: req.Audience, Principal: req.Principal})
	if err != nil {
		return team.OrgKMSKey{}, err
	}
	return team.OrgKMSKey{Name: req.Name, Key: k, Groups: req.Groups}, nil
}

func kmsRequestOf(c wire.Change) (wire.KMSKeyRequest, error) {
	var req wire.KMSKeyRequest
	if err := envelope.DecodeStrict(c.Data, &req); err != nil {
		return req, errors.New("the change names no KMS key")
	}
	return req, nil
}

func orgSettingsOf(c wire.Change) (team.OrgSettings, error) {
	var st team.OrgSettings
	if err := envelope.DecodeStrict(c.Data, &st); err != nil {
		return st, errors.New("the change holds no settings")
	}
	return st, nil
}

func flyAppOf(c wire.Change) (wire.FlyApp, error) {
	var app wire.FlyApp
	if err := envelope.DecodeStrict(c.Data, &app); err != nil {
		return app, errors.New("the change describes no Fly.io app")
	}
	return app, nil
}

func kmsNameOf(c wire.Change) (string, error) {
	var d struct {
		KMS string `json:"kms"`
	}
	if err := envelope.DecodeStrict(c.Data, &d); err != nil || d.KMS == "" {
		return "", errors.New("the change names no KMS key")
	}
	return d.KMS, nil
}

func shortFingerprint(k kms.Key) string {
	fp := strings.TrimPrefix(k.Fingerprint(), "kms:")
	return fp[:16]
}

// describeOrg describes the changes to organisations, and made through
// them.
func (ch ChangeView) describeOrg() ([]string, bool) {
	switch ch.Kind {
	case wire.ChangeOrgCreate:
		return []string{fmt.Sprintf("CREATE the organisation %s, with you as its admin: from then on only its people create projects and groups named %s/...", ch.Subject, ch.Subject)}, true
	case wire.ChangeOrgAdd:
		if ch.Admin {
			return []string{fmt.Sprintf("%s: make %s an ADMIN of the organisation (they approve KMS keys and set its rules)", ch.Target, ch.Subject)}, true
		}
		return []string{fmt.Sprintf("%s: add %s as a member of the organisation", ch.Target, ch.Subject)}, true
	case wire.ChangeOrgRemove:
		return []string{fmt.Sprintf("%s: remove %s from the organisation, and from every project and group of %s you administer", ch.Target, ch.Subject, ch.Target)}, true
	case wire.ChangeOrgKMSAdd:
		req, err := kmsRequestOf(ch.Change)
		if err != nil {
			return []string{"approve a KMS key (damaged)"}, true
		}
		out := []string{
			fmt.Sprintf("%s: APPROVE the KMS key %q for workloads: whoever controls it can read what they read", ch.Target, req.Name),
			fmt.Sprintf("provider %s, key %s", req.Provider, req.Key),
			fmt.Sprintf("audience %s", req.Audience),
		}
		if req.Principal != "" {
			out = append(out, "acting as "+req.Principal)
		}
		if len(req.Groups) > 0 {
			out = append(out, "only for "+strings.Join(req.Groups, ", "))
		}
		return append(out, "check that this is your key: this device reads its public half from the KMS"), true
	case wire.ChangeOrgKMSRemove:
		return []string{fmt.Sprintf("%s: withdraw the KMS key %s (no new workload uses it)", ch.Target, ch.Subject)}, true
	case wire.ChangeOrgSettings:
		st, err := orgSettingsOf(ch.Change)
		if err != nil {
			return []string{"change an organisation's settings (damaged)"}, true
		}
		return append([]string{ch.Target + ": set the organisation's settings to"}, SettingsLines(st)...), true
	case wire.ChangeFlyApp:
		app, err := flyAppOf(ch.Change)
		if err != nil {
			return []string{"set up a Fly.io app (damaged)"}, true
		}
		out := []string{fmt.Sprintf("%s: let the Fly.io app %s (of the Fly.io organisation %s) read keys with no secret, as a workload of %s, wrapped with the key %s", ch.Target, app.App, app.FlyOrg, app.Group, app.KMS)}
		for _, r := range app.Reads {
			out = append(out, fmt.Sprintf("%s reads %s of %s", app.Group, orNothing(r.Envs), r.Project))
		}
		return out, true
	case wire.ChangeWorkloadRekey:
		name, _ := kmsNameOf(ch.Change)
		return []string{fmt.Sprintf("%s: move the workload %s to the KMS key %s", ch.Target, ch.Subject, name)}, true
	}
	return nil, false
}

// SettingsLines describes an organisation's settings, one line each.
func SettingsLines(st team.OrgSettings) []string {
	yes := func(b bool, on, off string) string {
		if b {
			return on
		}
		return off
	}
	days := func(n int, what string) string {
		if n == 0 {
			return what + ": no limit"
		}
		return fmt.Sprintf("%s: %d days", what, n)
	}
	out := []string{
		yes(st.MembersOnly, "only its people join its projects and groups", "anyone may be added to its projects and groups"),
		yes(st.RequireGitHubProof, "people are checked with a GitHub SSH proof only", "people are checked with a GitHub SSH proof or account key words"),
		days(st.MaxTokenDays, "longest enrollment token"),
		yes(st.NoServerSigning, "the server signs no removals", "the server may sign removals for people who let it"),
	}
	if st.ReviewDays > 0 {
		out = append(out, fmt.Sprintf("review access every %d days", st.ReviewDays))
	}
	if st.FlyOrg != "" {
		out = append(out, "Fly.io organisation: "+st.FlyOrg)
	}
	if st.DefaultKMS != "" {
		out = append(out, "default KMS key: "+st.DefaultKMS)
	}
	return out
}
