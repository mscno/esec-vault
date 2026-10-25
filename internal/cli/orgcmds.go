package cli

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// OrgCmd manages organisations: the "acme" of acme/store, with a signed
// chain of its people, approved KMS keys and rules.
type OrgCmd struct {
	Show      OrgShowCmd      `cmd:"" default:"withargs" help:"Show an organisation: people, approved KMS keys, rules, projects and groups (default)."`
	Create    OrgCreateCmd    `cmd:"" help:"Set up an organisation's signed chain, with you as its admin."`
	Trust     OrgTrustCmd     `cmd:"" help:"Confirm an organisation's fingerprint on this device, so it applies the organisation's removals and keys."`
	Add       OrgAddCmd       `cmd:"" help:"Add someone to an organisation."`
	Remove    OrgRemoveCmd    `cmd:"" help:"Remove someone from an organisation, and from every project and group of it you administer."`
	KMS       OrgKMSCmd       `cmd:"" name:"kms" help:"List, approve and withdraw the KMS keys its workloads may use."`
	Set       OrgSetCmd       `cmd:"" help:"Change an organisation's rules and defaults."`
	FlyApp    OrgFlyAppCmd    `cmd:"" name:"fly-app" help:"Set up a Fly.io app to read keys with no secret: its group, what it reads, its workload."`
	Workloads OrgWorkloadsCmd `cmd:"" help:"List the workloads of its groups: what they read, their keys, when they last started."`
	Rekey     OrgRekeyCmd     `cmd:"" help:"Move workloads to another approved KMS key, across its groups."`
}

// OrgCreateCmd starts an organisation's chain.
type OrgCreateCmd struct {
	Org string `arg:"" help:"Organisation, such as acme: the first part of its project ids"`
}

// Run implements org create.
func (c *OrgCreateCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	// Only one this account created, and this device anchored, counts.
	if v, err := a.Org(bg, c.Org); err == nil && v.State != nil && v.Trusted && v.State.Admin(a.State.User) && v.State.Links[0].Signer == a.State.User && v.State.Links[0].SignerDelegate == "" {
		fmt.Printf("✓ %s exists already, with you as an admin; nothing changed.\n", v.State.Org)
		return nil
	}
	st, err := a.CreateOrg(bg, c.Org)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Created the organisation %s, with you as its admin.\n", st.Org)
	fmt.Printf("  Fingerprint: %s\n", st.Words())
	fmt.Printf("  From now on only its people create projects and groups named %s/... on this server.\n", st.Org)
	fmt.Printf("Next: add people (esec vault org add %s LOGIN [--admin]), approve a KMS key for workloads (esec vault org kms add %s NAME ...), and set its rules (esec vault org set %s --members-only).\n", st.Org, st.Org, st.Org)
	fmt.Printf("Or do it all on %s/orgs/%s.\n", a.State.Server, st.Org)
	return nil
}

// OrgTrustCmd anchors an organisation's chain on this device.
type OrgTrustCmd struct {
	Org         string `arg:"" help:"Organisation, such as acme"`
	Fingerprint string `help:"Its fingerprint words, from an admin ('esec vault org ORG' on their device): checked instead of asking"`
}

// Run implements org trust.
func (c *OrgTrustCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if c.Fingerprint == "" {
		v, err := a.Org(bg, c.Org)
		if err != nil {
			return err
		}
		if v.State == nil {
			return fmt.Errorf("%s has no organisation chain", c.Org)
		}
		var admins []string
		for _, p := range v.State.ActiveAdmins() {
			admins = append(admins, p.Login)
		}
		fmt.Printf("The organisation %s, as the server shows it: admins %s.\n", v.State.Org, safetext.Clean(strings.Join(admins, ", ")))
		fmt.Printf("Fingerprint: %s\n", v.State.Words())
		if !confirm("Does an admin's device show the same words (esec vault org " + v.State.Org + ")? Say no if you cannot check") {
			return errors.New("not confirmed: this device keeps applying none of its removals and approved keys")
		}
		c.Fingerprint = v.State.Words()
	}
	st, err := a.TrustOrg(bg, c.Org, c.Fingerprint)
	if err != nil {
		return err
	}
	fmt.Printf("✓ This device now applies %s's chain: it takes those who leave out of what you administer, and wraps workload keys with the keys it approved.\n", st.Org)
	return nil
}

// OrgAddCmd adds someone to an organisation.
type OrgAddCmd struct {
	Org        string `arg:"" help:"Organisation, such as acme"`
	Login      string `arg:"" help:"Their GitHub login"`
	Admin      bool   `help:"As an admin: they add people, approve KMS keys and set the rules"`
	AccountKey string `name:"account-key" help:"Their account key words (from 'esec vault status'), when they have no GitHub SSH proof"`
}

// Run implements org add.
func (c *OrgAddCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if v, err := a.Org(bg, c.Org); err == nil && v.State != nil && v.State.Admin(a.State.User) {
		if p, ok := v.State.PersonByLogin(c.Login); ok && (!c.Admin || v.State.Admin(p.User)) {
			fmt.Printf("✓ %s is in %s already; nothing changed.\n", safetext.Clean(p.Login), v.State.Org)
			return nil
		}
	}
	res, err := a.AddOrgPerson(bg, c.Org, c.Login, c.Admin, c.AccountKey)
	if err != nil {
		return err
	}
	role := "a member"
	if c.Admin {
		role = "an admin"
	}
	fmt.Printf("✓ Added %s to %s as %s (checked with %s; account %s).\n", safetext.Clean(res.Login), c.Org, role, verifiedText(res.Verified), res.AccountWords)
	fmt.Println("  Belonging to the organisation gives no keys: grant them projects or add them to groups as before.")
	return nil
}

// OrgRemoveCmd removes someone from an organisation.
type OrgRemoveCmd struct {
	Org   string `arg:"" help:"Organisation, such as acme"`
	Login string `arg:"" help:"Their GitHub login (yours: leave it)"`
	Yes   bool   `help:"Do not ask"`
}

// Run implements org remove.
func (c *OrgRemoveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	if !c.Yes && !confirm(fmt.Sprintf("Remove %s from %s, and from every project and group of %s you administer?", c.Login, c.Org, c.Org)) {
		return errors.New("not removed")
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	removals, err := a.RemoveOrgPerson(bg, c.Org, c.Login, "removed from the organisation")
	if err != nil {
		return err
	}
	fmt.Printf("✓ Removed %s from %s.\n", safetext.Clean(c.Login), c.Org)
	for _, r := range removals {
		fmt.Println("  " + safetext.Clean(r.Line()))
	}
	fmt.Println("  The devices of the other admins of its projects and groups take them out of theirs on their next sync.")
	return nil
}

// OrgSetCmd changes an organisation's settings; flags not given stay.
type OrgSetCmd struct {
	Org                string  `arg:"" help:"Organisation, such as acme"`
	MembersOnly        *bool   `name:"members-only" negatable:"" help:"Only its people may join its projects and groups"`
	RequireGitHubProof *bool   `name:"require-github-proof" negatable:"" help:"Add people only with a GitHub SSH proof, not account key words"`
	ServerSigning      *bool   `name:"server-signing" negatable:"" help:"Let the server sign removals made on the web for people who allow it (--no-server-signing: never)"`
	MaxTokenDays       *int    `name:"max-token-days" help:"Longest enrollment token, in days (0: no limit)"`
	ReviewDays         *int    `name:"review-days" help:"Ask admins to review who reads each project every so many days (0: never)"`
	FlyOrg             *string `name:"fly-org" help:"The Fly.io organisation new workloads run in, by default"`
	DefaultKMS         *string `name:"default-kms" help:"The approved KMS key new workloads use, by default"`
}

// Run implements org set.
func (c *OrgSetCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	v, err := a.Org(bg, c.Org)
	if err != nil {
		return err
	}
	if v.State == nil {
		return fmt.Errorf("%s has no organisation chain yet; set it up with 'esec vault org create %s'", c.Org, c.Org)
	}
	st := v.State.Settings
	if c.MembersOnly != nil {
		st.MembersOnly = *c.MembersOnly
	}
	if c.RequireGitHubProof != nil {
		st.RequireGitHubProof = *c.RequireGitHubProof
	}
	if c.ServerSigning != nil {
		st.NoServerSigning = !*c.ServerSigning
	}
	if c.MaxTokenDays != nil {
		st.MaxTokenDays = *c.MaxTokenDays
	}
	if c.ReviewDays != nil {
		st.ReviewDays = *c.ReviewDays
	}
	if c.FlyOrg != nil {
		st.FlyOrg = *c.FlyOrg
	}
	if c.DefaultKMS != nil {
		st.DefaultKMS = *c.DefaultKMS
	}
	if err := a.SetOrgSettings(bg, v.State.Org, st); err != nil {
		return err
	}
	fmt.Printf("✓ %s:\n", v.State.Org)
	for _, l := range account.SettingsLines(st) {
		fmt.Println("  " + l)
	}
	return nil
}

// OrgKMSCmd manages the KMS keys an organisation approved.
type OrgKMSCmd struct {
	List   OrgKMSListCmd   `cmd:"" default:"withargs" help:"List the approved keys (default)."`
	Add    OrgKMSAddCmd    `cmd:"" help:"Approve a KMS key; this device reads its public key from the KMS."`
	Remove OrgKMSRemoveCmd `cmd:"" help:"Withdraw a key: no new workload uses it."`
}

// OrgKMSListCmd lists approved keys.
type OrgKMSListCmd struct {
	Org  string `arg:"" help:"Organisation, such as acme"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// Run implements org kms list.
func (c *OrgKMSListCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	v, err := a.Org(bg, c.Org)
	if err != nil {
		return err
	}
	if v.State == nil {
		return fmt.Errorf("%s has no organisation chain yet", c.Org)
	}
	keys := v.State.ActiveKMS()
	if c.JSON {
		return printJSON(nonNil(keys))
	}
	if len(keys) == 0 {
		fmt.Printf("%s approved no KMS key yet: esec vault org kms add %s NAME --gcp-key ... --gcp-provider ...\n", v.State.Org, v.State.Org)
		return nil
	}
	for _, k := range keys {
		printKMSKey(k, v.State.Settings.DefaultKMS)
	}
	return nil
}

func printKMSKey(k *team.OrgKMSState, def string) {
	tag := ""
	if k.Name == def {
		tag = " (default)"
	}
	fmt.Printf("  %s%s: %s %s\n", k.Name, tag, k.Key.Provider, safetext.Clean(k.Key.Name))
	if len(k.Groups) > 0 {
		fmt.Printf("      only for %s\n", strings.Join(k.Groups, ", "))
	}
}

// OrgKMSAddCmd approves a key.
type OrgKMSAddCmd struct {
	Org  string `arg:"" help:"Organisation, such as acme"`
	Name string `arg:"" help:"A name for it, such as gcp-prod or fly-store"`

	GCPKey            string   `name:"gcp-key" help:"Cloud KMS key version: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N"`
	GCPProvider       string   `name:"gcp-provider" help:"Workload identity provider that trusts the workloads' OIDC tokens"`
	GCPServiceAccount string   `name:"gcp-service-account" help:"A service account the workloads act as"`
	OpenBaoKey        string   `name:"openbao-key" help:"Or an OpenBao Transit key version: https://HOST/MOUNT/KEY/VERSION"`
	OpenBaoRole       string   `name:"openbao-role" help:"OpenBao JWT auth mount and role, such as jwt/fly-store"`
	OpenBaoAudience   string   `name:"openbao-audience" default:"esec-openbao" help:"The audience the OpenBao role binds"`
	PublicKey         string   `name:"public-key" type:"existingfile" help:"The key's public key (PEM); default: ask gcloud, or OpenBao with BAO_TOKEN and BAO_ADDR"`
	Groups            []string `sep:"," help:"Only these groups' workloads may use it, such as acme/fly-store for a key of one app"`
	Default           bool     `help:"Use it for new workloads by default"`
}

// Run implements org kms add.
func (c *OrgKMSAddCmd) Run(ctx *cliCtx) error {
	w := GroupWorkloadCmd{GCPKey: c.GCPKey, GCPProvider: c.GCPProvider, GCPServiceAccount: c.GCPServiceAccount, OpenBaoKey: c.OpenBaoKey, OpenBaoRole: c.OpenBaoRole, OpenBaoAudience: c.OpenBaoAudience, PublicKey: c.PublicKey}
	key, err := w.kmsKey()
	if err != nil {
		return err
	}
	pemText, err := w.publicKey(key)
	if err != nil {
		return err
	}
	if key.PublicKey, err = kms.PublicKeyFromPEM(pemText); err != nil {
		return err
	}
	if err := key.Validate(); err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.ApproveKMS(bg, c.Org, team.OrgKMSKey{Name: c.Name, Key: key, Groups: c.Groups}); err != nil {
		return err
	}
	fmt.Printf("✓ %s approved the KMS key %s (%s %s).\n", c.Org, c.Name, key.Provider, safetext.Clean(key.Name))
	fmt.Println("  Devices now wrap the group keys of its workloads only with keys it approved.")
	if c.Default {
		v, err := a.Org(bg, c.Org)
		if err != nil {
			return err
		}
		st := v.State.Settings
		st.DefaultKMS = c.Name
		if err := a.SetOrgSettings(bg, c.Org, st); err != nil {
			return err
		}
		fmt.Println("  New workloads use it by default.")
	}
	return nil
}

// OrgKMSRemoveCmd withdraws a key.
type OrgKMSRemoveCmd struct {
	Org  string `arg:"" help:"Organisation, such as acme"`
	Name string `arg:"" help:"The key's name"`
}

// Run implements org kms remove.
func (c *OrgKMSRemoveCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	users, err := a.WithdrawKMS(bg, c.Org, c.Name, "withdrawn")
	if err != nil {
		return err
	}
	fmt.Printf("✓ Withdrew %s: no new workload of %s uses it.\n", c.Name, c.Org)
	if len(users) > 0 {
		fmt.Printf("  Still using it, until you move them: %s\n", safetext.Clean(strings.Join(users, ", ")))
		fmt.Println("  Move one with: esec vault group rekey-workloads GROUP --workload NAME ... (or on the organisation's Workloads page)")
	}
	return nil
}

// OrgFlyAppCmd sets up Fly.io apps as workloads.
type OrgFlyAppCmd struct {
	Org    string   `arg:"" help:"Organisation, such as acme"`
	Apps   []string `arg:"" name:"app" help:"The Fly.io apps; each gets its own group, ORG/APP"`
	Read   []string `help:"What each reads, as PROJECT:ENV[,ENV]; repeat for more projects, such as --read acme/store:prod"`
	Group  string   `help:"The group, for one app (default: ORG/APP, created when missing)"`
	KMS    string   `name:"kms" help:"The approved KMS key (default: the app's own key esec-APP if approved for it, else the organisation's default)"`
	FlyOrg string   `name:"fly-org" help:"Its Fly.io organisation (default: the organisation's setting)"`
	Out    string   `help:"For one app: write its descriptor to this file too"`
	JSON   bool     `help:"Print JSON, for scripts and agents: each app's group, descriptor and what changed"`
}

// flyAppJSON is what org fly-app prints for each app with --json.
type flyAppJSON struct {
	App          string   `json:"app"`
	Group        string   `json:"group"`
	KMS          string   `json:"kms"`
	Descriptor   string   `json:"descriptor,omitempty"`
	CreatedGroup bool     `json:"created_group"`
	Rekeyed      bool     `json:"rekeyed"`
	Granted      []string `json:"granted"`
	Pending      []string `json:"pending"`
	Error        string   `json:"error,omitempty"`
}

// Run implements org fly-app.
func (c *OrgFlyAppCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // defaults, then each app in turn
	if len(c.Apps) > 1 && (c.Group != "" || c.Out != "") {
		return errors.New("--group and --out are for one app at a time")
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Duration(5*len(c.Apps)) * time.Minute)
	defer cancel()
	v, err := a.Org(bg, c.Org)
	if err != nil {
		return err
	}
	if v.State == nil {
		return fmt.Errorf("%s has no organisation chain yet; set it up with 'esec vault org create %s'", c.Org, c.Org)
	}
	var reads []wire.ProjectEnvs
	for _, r := range c.Read {
		project, envs, ok := strings.Cut(r, ":")
		if !ok || envs == "" {
			return fmt.Errorf("--read is PROJECT:ENV[,ENV], such as %s/store:prod", v.State.Org)
		}
		reads = append(reads, wire.ProjectEnvs{Project: project, Envs: team.SortEnvs(strings.Split(envs, ","))})
	}
	var out []flyAppJSON
	failed := 0
	for _, name := range c.Apps {
		app := wire.FlyApp{App: name, FlyOrg: c.FlyOrg, Group: c.Group, KMS: c.KMS, Reads: reads}
		if app.FlyOrg == "" {
			app.FlyOrg = v.State.Settings.FlyOrg
		}
		if app.FlyOrg == "" {
			return fmt.Errorf("name the Fly.io organisation: --fly-org (or set a default: esec vault org set %s --fly-org SLUG)", v.State.Org)
		}
		if app.Group == "" {
			app.Group = v.State.Org + "/" + name
		}
		if app.KMS == "" {
			// A key made for this app (kms setup gcp makes esec-APP) comes
			// before the organisation's default.
			if k, ok := v.State.KMSByName("esec-" + name); ok && slices.Contains(k.Groups, app.Group) {
				app.KMS = k.Name
			} else {
				app.KMS = v.State.Settings.DefaultKMS
			}
		}
		if app.KMS == "" {
			return fmt.Errorf("name the KMS key: --kms NAME (esec vault org kms %s lists them)", v.State.Org)
		}
		if k, ok := v.State.KMSByName(app.KMS); ok && len(k.Groups) == 0 {
			fmt.Fprintf(os.Stderr, "Note: %s is not limited to one app's group; every app allowed to decrypt with it could open what is wrapped for the others. A key per app is safer: esec vault kms setup gcp --fly-app %s --apply --approve\n", k.Name, name)
		}
		res, err := a.AddFlyApp(bg, v.State.Org, app)
		r := flyAppJSON{App: name, Group: app.Group, KMS: app.KMS, Granted: []string{}, Pending: []string{}}
		if res != nil {
			r.CreatedGroup, r.Rekeyed, r.Granted, r.Pending = res.CreatedGroup, res.Rekeyed, nonNil(res.Granted), nonNil(res.Pending)
			if res.Ref != nil {
				r.Descriptor = res.Ref.String()
			}
		}
		if err != nil {
			failed++
			r.Error = err.Error()
		}
		out = append(out, r)
		if c.JSON {
			continue
		}
		if len(c.Apps) > 1 {
			fmt.Printf("%s:\n", name)
		}
		if res != nil {
			for _, l := range res.Lines(app) {
				fmt.Println(safetext.Clean(l))
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "! %s: %v\n", name, err)
			continue
		}
		if r.Descriptor != "" {
			fmt.Println("\nIts descriptor is not a secret: put it in the app's plain configuration, such as fly.toml:")
			fmt.Printf("\n  [env]\n    ESEC_VAULT_WORKLOAD = %q\n\n", r.Descriptor)
		}
		if c.Out != "" && r.Descriptor != "" {
			if err := os.WriteFile(c.Out, []byte(r.Descriptor+"\n"), 0o600); err != nil {
				return err
			}
			fmt.Printf("Wrote the descriptor to %s.\n", c.Out)
		}
	}
	if c.JSON {
		if err := printJSON(out); err != nil {
			return err
		}
	} else {
		fmt.Println("Start each app with: esec-vault machine run -- ./your-command")
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d app(s) failed", failed, len(c.Apps))
	}
	return nil
}
