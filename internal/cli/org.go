package cli

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// OrgShowCmd shows an organisation: its people, keys and rules from its
// signed chain, the shared projects and groups you can see, and the policy
// the server enforces for it.
type OrgShowCmd struct {
	Org  string `arg:"" optional:"" help:"Organisation, such as acme (default: list yours)"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// orgJSON is what org prints with --json.
type orgJSON struct {
	TenantID    string                `json:"tenant_id"`
	Namespace   string                `json:"namespace"`
	DisplayName string                `json:"display_name"`
	Owners      []string              `json:"owners,omitempty"`
	Org         string                `json:"org"`
	Kind        string                `json:"kind"`
	Signed      bool                  `json:"signed"`
	Trusted     bool                  `json:"trusted"`
	Words       string                `json:"fingerprint,omitempty"`
	Admins      []string              `json:"admins,omitempty"`
	Members     []string              `json:"members,omitempty"`
	Left        map[string][]string   `json:"left,omitempty"`
	KMS         []*team.OrgKMSState   `json:"kms,omitempty"`
	Settings    *team.OrgSettings     `json:"settings,omitempty"`
	Projects    []wire.ProjectSummary `json:"projects"`
	Groups      []wire.GroupSummary   `json:"groups"`
	Policy      *wire.OrgPolicy       `json:"policy"`
}

// Run implements org.
func (c *OrgShowCmd) Run(ctx *cliCtx) error { //nolint:gocyclo,maintidx // a listing, then one organisation's sections
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	projects, err := a.TeamSummaries(bg)
	if err != nil {
		return err
	}
	groups, err := a.Groups(bg)
	if err != nil {
		return err
	}
	if c.Org == "" {
		count := map[string][2]int{}
		for _, p := range projects {
			n := count[orgName(p.ID)]
			n[0]++
			count[orgName(p.ID)] = n
		}
		for _, g := range groups {
			n := count[orgName(g.ID)]
			n[1]++
			count[orgName(g.ID)] = n
		}
		signed := map[string]bool{}
		kinds := map[string]string{}
		currentCounts := map[string][2]int{}
		for name, n := range count {
			current := name
			if info, err := a.Client.Namespace(bg, name); err == nil {
				current = info.Name
				kinds[current] = info.Kind
			}
			old := currentCounts[current]
			currentCounts[current] = [2]int{old[0] + n[0], old[1] + n[1]}
		}
		count = currentCounts
		if names, err := a.Client.Namespaces(bg); err == nil {
			for _, n := range names {
				kinds[n.Name] = n.Kind
				if _, ok := count[n.Name]; !ok {
					count[n.Name] = [2]int{}
				}
			}
		}
		if list, err := a.Orgs(bg); err == nil {
			for _, o := range list {
				name := o.Namespace
				if name == "" {
					name = o.Org
				}
				signed[name] = true
				if _, ok := count[name]; !ok {
					count[name] = [2]int{}
				}
			}
		}
		orgs := mapKeys(count)
		slices.Sort(orgs)
		if c.JSON {
			return printJSON(nonNil(orgs))
		}
		if len(orgs) == 0 {
			fmt.Println("No organisations yet: share a project (esec vault access create), or set one up (esec vault org create ORG).")
			return nil
		}
		for _, o := range orgs {
			tag := ""
			if signed[strings.ToLower(o)] {
				tag = "  (signed chain)"
			}
			fmt.Printf("%-24s %-8s %d project(s), %d group(s)%s\n", safetext.Clean(o), kinds[o], count[o][0], count[o][1], tag)
		}
		fmt.Println("Show one with: esec vault org ORG")
		return nil
	}
	v, err := a.Org(bg, strings.ToLower(c.Org))
	if err != nil {
		return err
	}
	os := v.State
	in := func(id string) bool {
		if os != nil {
			return os.ContainsProject(id)
		}
		return strings.EqualFold(orgName(id), c.Org)
	}
	projects = slices.DeleteFunc(projects, func(p wire.ProjectSummary) bool { return !in(p.ID) })
	groups = slices.DeleteFunc(groups, func(g wire.GroupSummary) bool { return !in(g.ID) })
	kind := "legacy"
	info, err := a.Client.Namespace(bg, strings.ToLower(c.Org))
	if err != nil && !client.IsCode(err, wire.ErrNotFound) {
		return err
	}
	if err == nil {
		kind = info.Kind
	} else {
		info = nil
	}
	if os != nil && os.TenantID != "" && info != nil && (os.TenantID != info.TenantID || os.Namespace != info.Name) {
		return fmt.Errorf("tenant profile does not match its signed chain")
	}
	if c.JSON {
		out := orgJSON{Org: strings.ToLower(c.Org), Kind: kind, Projects: nonNil(projects), Groups: nonNil(groups), Policy: v.Policy}
		if info != nil {
			out.TenantID, out.Namespace, out.DisplayName = info.TenantID, info.Name, info.DisplayName
		}
		if os != nil {
			out.Signed, out.Trusted, out.Words, out.KMS, out.Settings, out.Left = true, v.Trusted, os.Words(), os.ActiveKMS(), &os.Settings, v.Left
			for _, p := range os.ActiveAdmins() {
				out.Admins = append(out.Admins, p.Login)
				if os.Owner(p.User) {
					out.Owners = append(out.Owners, p.Login)
				}
			}
			for _, p := range os.People() {
				if !os.Admin(p.User) {
					out.Members = append(out.Members, p.Login)
				}
			}
		}
		return printJSON(out)
	}
	if os == nil && len(projects)+len(groups) == 0 && kind == "legacy" {
		return fmt.Errorf("you have no shared project or group in %s, and it has no organisation chain (esec vault org create %s)", c.Org, strings.ToLower(c.Org))
	}
	fmt.Printf("%s  (%s/orgs/%s)\n", safetext.Clean(c.Org), a.State.Server, safetext.Clean(strings.ToLower(c.Org)))
	fmt.Printf("Tenant: %s\n", kind)
	if os == nil {
		fmt.Printf("No signed chain yet. A namespace reservation is required; its owner sets it up with: esec vault org create %s\n", strings.ToLower(c.Org))
	} else {
		fmt.Printf("Fingerprint: %s\n", os.Words())
		if !v.Trusted {
			fmt.Printf("  ! not confirmed on this device: compare the words with an admin's, then: esec vault org trust %s\n", os.Org)
		}
		fmt.Println("People:")
		for _, p := range os.People() {
			role := "member"
			if os.Admin(p.User) {
				role = "admin"
			}
			if os.Owner(p.User) {
				role = "owner"
			}
			fmt.Printf("  %-24s %s\n", safetext.Clean(p.Login), role)
		}
		for _, login := range slices.Sorted(maps.Keys(v.Left)) {
			ids := v.Left[login]
			fmt.Printf("  ! %s left, but still reads %s; their admins' devices take them out on their next sync\n", safetext.Clean(login), safetext.Clean(strings.Join(ids, ", ")))
		}
		fmt.Println("Approved KMS keys:")
		if len(os.ActiveKMS()) == 0 {
			fmt.Printf("  none: esec vault org kms add %s NAME --gcp-key ... --gcp-provider ...\n", os.Org)
		}
		for _, k := range os.ActiveKMS() {
			printKMSKey(k, os.Settings.DefaultKMS)
		}
		fmt.Println("Rules (signed, checked by devices and the server):")
		for _, l := range account.SettingsLines(os.Settings) {
			fmt.Println("  " + l)
		}
	}
	if len(projects) > 0 {
		fmt.Println("Projects:")
		for _, p := range projects {
			role := "reads " + joinOr(p.Envs, "nothing")
			if p.Admin {
				role = "admin"
			}
			fmt.Printf("  %-32s %-22s %d member(s), %d group(s), %d machine(s)\n", safetext.Clean(p.ID), safetext.Clean(role), p.Members, p.Groups, p.Machines)
		}
	}
	if len(groups) > 0 {
		fmt.Println("Groups:")
		for _, g := range groups {
			role := "reads your projects"
			switch {
			case g.Admin:
				role = "admin"
			case g.Member:
				role = "member"
			}
			fmt.Printf("  %-32s %-22s %d people, %d machine(s), reads %s\n", safetext.Clean(g.ID), role, g.People, g.Machines, safetext.Clean(joinOr(g.Projects, "nothing")))
		}
	}
	fmt.Println("Policy the server enforces (the stricter of the server admins' and the organisation's):")
	fmt.Println("  " + policyText(v.Policy))
	return nil
}

func orgName(id string) string {
	org, _, _ := strings.Cut(id, "/")
	return org
}

func policyText(p *wire.OrgPolicy) string {
	var parts []string
	if p.MaxTokenDays > 0 {
		parts = append(parts, fmt.Sprintf("tokens last at most %d days", p.MaxTokenDays))
	}
	if p.RequireGitHubProof {
		parts = append(parts, "people are added only with a GitHub SSH proof")
	}
	if p.NoServerSigning {
		parts = append(parts, "the server signs no removals")
	}
	if p.ReviewDays > 0 {
		parts = append(parts, fmt.Sprintf("access is reviewed every %d days", p.ReviewDays))
	}
	if p.MembersOnly {
		parts = append(parts, "only the organisation's people join its projects and groups")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

// AccessReviewCmd reviews who reads a project.
type AccessReviewCmd struct {
	Project string   `help:"Project id (default: nearest esec.toml)"`
	Remove  []string `sep:"," help:"Take access away from these (logins, groups, machine:NAME) and keep everyone else, without asking"`
	KeepAll bool     `name:"keep-all" help:"Keep everyone, without asking, and record the review"`
	Yes     bool     `help:"Do not ask before removing"`
}

// Run implements access review.
func (c *AccessReviewCmd) Run(ctx *cliCtx) error { //nolint:gocyclo // every kind of reader, asked about in turn
	project, err := projectFlag(c.Project)
	if err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(10 * time.Minute)
	defer cancel()
	v, err := a.Team(bg, project)
	if err != nil {
		return err
	}
	st := v.State
	if !st.Admin(a.State.User) {
		return fmt.Errorf("only an admin of %s reviews who reads it", project)
	}
	if rs, err := a.ReviewStatus(bg, project); err == nil && rs.Last != nil {
		fmt.Printf("Last reviewed by %s on %s.\n", safetext.Clean(rs.Last.By), rs.Last.Reviewed.Local().Format("2006-01-02")) //nolint:gosmopolitan // shown to the local user
	}
	type reader struct{ name, reads string }
	var readers []reader
	for _, m := range st.ActiveMembers() {
		if !m.Admin {
			readers = append(readers, reader{m.Login, joinOr(st.Access(m.User), "nothing")})
		}
	}
	for _, g := range st.ActiveGroups() {
		readers = append(readers, reader{g.Group, strings.Join(g.Envs, ", ")})
	}
	for _, m := range st.ActiveMachines() {
		readers = append(readers, reader{"machine:" + m.Name, strings.Join(m.Envs, ", ")})
	}
	interactive := !c.KeepAll && len(c.Remove) == 0
	var kept, removed []string
	for _, m := range st.ActiveMembers() {
		if m.Admin {
			kept = append(kept, m.Login)
		}
	}
	for _, r := range readers {
		drop := slices.ContainsFunc(c.Remove, func(n string) bool { return strings.EqualFold(n, r.name) })
		if interactive {
			drop = confirm(fmt.Sprintf("%s reads %s. Take it away?", r.name, r.reads))
			if unanswered {
				return errors.New("nothing answered on stdin: run it in a terminal, or say who goes with --remove LOGIN,... (or --keep-all)")
			}
		}
		if drop {
			removed = append(removed, r.name)
		} else {
			kept = append(kept, r.name)
		}
	}
	for _, n := range c.Remove {
		if !slices.ContainsFunc(readers, func(r reader) bool { return strings.EqualFold(r.name, n) }) {
			return fmt.Errorf("%s reads nothing of %s that a review can take away (admins are removed with esec vault access set --no-admin)", n, project)
		}
	}
	if len(removed) > 0 && !c.Yes && !interactive && !confirm(fmt.Sprintf("Take access to %s away from %s?", project, strings.Join(removed, ", "))) {
		return errors.New("cancelled")
	}
	var rotate []string
	for _, n := range removed {
		var envs []string
		switch {
		case strings.HasPrefix(n, "machine:"):
			m, err := a.RemoveMachine(bg, project, strings.TrimPrefix(n, "machine:"), "access review")
			if err != nil {
				return err
			}
			envs = m.Envs
		case strings.Contains(n, "/"):
			res, err := a.GrantGroup(bg, n, project, nil)
			if err != nil {
				return err
			}
			envs = res.Exposed
		default:
			if envs, err = a.RemoveMember(bg, project, n, "access review"); err != nil {
				return err
			}
		}
		fmt.Printf("✓ Took %s away from %s.\n", project, safetext.Clean(n))
		rotate = append(rotate, envs...)
	}
	if err := a.RecordReview(bg, project, kept, removed); err != nil {
		return err
	}
	fmt.Printf("✓ Recorded the review of %s: %d kept, %d removed.\n", project, len(kept), len(removed))
	printRotations(team.SortEnvs(rotate), "Those removed could read")
	return nil
}
