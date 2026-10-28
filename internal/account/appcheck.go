package account

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// Check levels.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Check is one finding of a preflight check, with how to fix it.
type Check struct {
	Name   string `json:"name"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// AppCheckInput is what an app's repository says about it.
type AppCheckInput struct {
	Project string
	Env     string
	// FilePublicKeys are the public keys of the env's secrets files.
	FilePublicKeys map[string]string
	// FlyApp is the app fly.toml names; Workload its ESEC_VAULT_WORKLOAD.
	FlyApp   string
	Workload string
}

// CheckApp checks, from the verified chains, that an app will get the keys
// of its environment: the project, the secrets files' key, the workload its
// configuration names, what its group reads, the keys delivered, and its
// KMS key. Each finding says how to fix it.
func (a *Account) CheckApp(ctx context.Context, in AppCheckInput) ([]Check, error) { //nolint:gocyclo,maintidx // one check after another, in the order a deploy needs them
	var out []Check
	add := func(name, level, detail, fix string) {
		out = append(out, Check{Name: name, Level: level, Detail: detail, Fix: fix})
	}
	err := a.withTeam(ctx, func(t *teamCtx) error {
		st, err := t.state(in.Project)
		if err != nil {
			add("project", CheckFail, err.Error(), "")
			return nil
		}
		if st == nil {
			add("project", CheckFail, in.Project+" is not a shared project", "esec vault access create")
			return nil
		}
		if st.Archived {
			add("project", CheckFail, in.Project+" is archived", "esec vault access archive --undo")
			return nil
		}
		e, ok := st.Envs[in.Env]
		if !ok {
			add("environment", CheckFail, fmt.Sprintf("%s has no environment %s (it has %s)", in.Project, in.Env, strings.Join(st.EnvNames(), ", ")), "esec vault env add "+in.Env)
			return nil
		}
		add("project", CheckOK, fmt.Sprintf("%s, environment %s (key since %s)", in.Project, in.Env, e.Since.Local().Format("2006-01-02")), "") //nolint:gosmopolitan // shown to the local user
		for file, pub := range in.FilePublicKeys {
			switch {
			case pub == e.PublicKey:
				add("secrets file", CheckOK, file+" is encrypted to the current "+in.Env+" key", "")
			case slices.Contains(e.Retired, pub):
				add("secrets file", CheckFail, file+" is encrypted to an earlier "+in.Env+" key, which deployments no longer get", "esec vault env rotate "+in.Env+" (re-encrypts it), or re-encrypt it with the current key")
			default:
				add("secrets file", CheckFail, file+" is encrypted to a key that is not "+in.Project+"'s "+in.Env+" key", "check esec.toml and the file name; esec vault access show")
			}
		}
		if exposed := len(e.Exposed); exposed > 0 {
			add("rotation", CheckWarn, fmt.Sprintf("someone who lost access may still hold the %s key (%d)", in.Env, exposed), "esec vault env rotate "+in.Env)
		}
		if in.Workload == "" {
			if in.FlyApp != "" {
				add("workload", CheckFail, "fly.toml has no ESEC_VAULT_WORKLOAD in [env]", "esec vault app init --env "+in.Env)
			}
			return nil
		}
		ref, err := team.ParseWorkloadRef(in.Workload)
		if err != nil {
			// A finding, not a failure of the check.
			add("workload", CheckFail, "ESEC_VAULT_WORKLOAD: "+err.Error(), "copy it again from esec vault group show GROUP, or esec vault app init")
			return nil //nolint:nilerr // reported as a finding
		}
		if strings.TrimRight(ref.Server, "/") != strings.TrimRight(a.State.Server, "/") {
			add("workload", CheckFail, "the descriptor names the server "+ref.Server+", not "+a.State.Server, "")
		}
		gs, err := t.group(ref.Group)
		if err != nil || gs == nil {
			add("workload", CheckFail, "the group "+ref.Group+" cannot be read", "")
			return nil //nolint:nilerr // reported as a finding
		}
		if gs.Root() != ref.Root {
			add("workload", CheckFail, "the descriptor names another "+ref.Group+" than the server has (its first link differs): the group was made again", "esec vault app init --env "+in.Env)
			return nil
		}
		c, ok := gs.Cred(ref.ID)
		if !ok || c.Kind != team.KindWorkload {
			add("workload", CheckFail, "the descriptor's workload is not in "+ref.Group+" (removed?)", "esec vault app init --env "+in.Env)
			return nil
		}
		add("workload", CheckOK, fmt.Sprintf("%s in %s, %s", c.Name, ref.Group, c.OIDC.Describe()), "")
		if in.FlyApp != "" {
			if c.OIDC == nil || c.OIDC.Provider != team.ProviderFly || !slices.Contains(c.OIDC.FlyApps, in.FlyApp) {
				add("fly app", CheckFail, "the workload is bound to "+c.OIDC.Describe()+", not to the app fly.toml names ("+in.FlyApp+"): it would get no keys", "esec vault app init --env "+in.Env)
			} else {
				add("fly app", CheckOK, "bound to "+in.FlyApp, "")
			}
		}
		pg, granted := st.Group(gs.Group)
		trusted := gs.Access[in.Project] == st.Root()
		switch {
		case !granted || pg.Root != gs.Root() || !slices.Contains(pg.Envs, in.Env):
			add("reads", CheckFail, gs.Group+" does not read "+in.Env+" of "+in.Project, "esec vault access grant "+gs.Group+" --env "+in.Env+" --project "+in.Project)
		case !trusted:
			add("reads", CheckFail, gs.Group+" does not take keys from "+in.Project+" yet (its admins agree)", "esec vault access grant "+gs.Group+" --env "+in.Env+" --project "+in.Project+"  (by an admin of the group)")
		default:
			add("reads", CheckOK, gs.Group+" reads "+in.Env+" of "+in.Project, "")
		}
		if status, err := t.a.Client.ProjectStatus(t.ctx, in.Project); err == nil {
			for _, h := range status.Holders {
				if h.ID == team.GroupHolder(gs.Group) {
					if v := h.Envs[in.Env]; v != wire.KeyHeld && granted {
						add("key sent", CheckFail, "the current "+in.Env+" key has not been sealed to "+gs.Group+" yet", "esec vault access sync  (on an admin's device of "+in.Project+")")
					} else if granted {
						add("key sent", CheckOK, "the "+in.Env+" key is sealed to "+gs.Group, "")
					}
				}
			}
		}
		var used *wire.CredStatus
		if gs.Admin(a.State.User) {
			if s, err := t.a.Client.GroupStatus(t.ctx, gs.Group); err == nil {
				for i, cs := range s.Creds {
					if cs.ID == c.ID {
						used = &s.Creds[i]
					}
				}
			}
		}
		switch {
		case used == nil:
			add("group key", CheckWarn, "this account is not an admin of "+gs.Group+", so it cannot see whether the workload's group key was sent", "")
		case used.Suspended:
			add("group key", CheckFail, "the workload is blocked on the web, waiting for its removal to be signed", "esec vault changes")
		case !used.HasKey:
			add("group key", CheckFail, "the group key has not been wrapped for the workload yet", "esec vault access sync  (on an admin's device of "+gs.Group+")")
		default:
			add("group key", CheckOK, "wrapped for the workload with its KMS key", "")
		}
		if c.KMS != nil {
			os, err := t.orgOf(gs.Group)
			switch {
			case err != nil:
				add("kms key", CheckWarn, err.Error(), "")
			case os == nil:
				add("kms key", CheckWarn, c.KMS.Provider+" "+c.KMS.Name+" (no organisation approves keys for "+team.OrgOf(gs.Group)+")", "esec vault org create "+team.OrgOf(gs.Group))
			case os.CheckKMS(*c.KMS, gs.Group) != nil:
				add("kms key", CheckFail, os.CheckKMS(*c.KMS, gs.Group).Error(), "esec vault org rekey "+os.Org+" --to NAME")
			default:
				k := os.KMSFor(*c.KMS)
				add("kms key", CheckOK, fmt.Sprintf("%s (%s %s), approved by %s", k.Name, c.KMS.Provider, c.KMS.Name, os.Org), "")
				if len(k.Groups) == 0 {
					add("kms key", CheckWarn, k.Name+" is shared by every group: each app allowed to decrypt with it could open the others' keys", "esec vault kms setup gcp --fly-app "+in.FlyApp+" --apply --approve, then esec vault org rekey")
				}
			}
		}
		if used != nil {
			switch {
			case used.LastUsed.IsZero():
				add("started", CheckWarn, "the workload never fetched its keys yet", "deploy it: fly deploy")
			case used.LastUsed.Before(e.Since):
				add("started", CheckWarn, "the workload last started "+used.LastUsed.Local().Format(time.DateTime)+", before the current "+in.Env+" key: it gets it at its next start", "fly deploy (or fly apps restart)") //nolint:gosmopolitan // shown to the local user
			default:
				add("started", CheckOK, "last fetched its keys "+used.LastUsed.Local().Format(time.DateTime), "") //nolint:gosmopolitan // shown to the local user
			}
		}
		return nil
	})
	return out, err
}

// FlyAppEnv sets up a Fly.io app to read env of project, keeping what its
// group reads of the project already, and returns what AddFlyApp did.
func (a *Account) FlyAppEnv(ctx context.Context, project, env, app, flyOrg, kmsName string) (*FlyAppResult, error) {
	org := team.OrgOf(project)
	group := org + "/" + app
	envs := []string{env}
	if v, err := a.Team(ctx, project); err == nil {
		if pg, ok := v.State.Group(group); ok {
			envs = team.SortEnvs(append(slices.Clone(pg.Envs), env))
		}
	}
	return a.AddFlyApp(ctx, org, wire.FlyApp{App: app, FlyOrg: flyOrg, Group: group, KMS: kmsName, Reads: []wire.ProjectEnvs{{Project: project, Envs: slices.Compact(envs)}}})
}
