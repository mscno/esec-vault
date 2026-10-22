package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// OrgCmd shows an organisation: its shared projects and groups you can see,
// and the policy the server enforces for it.
type OrgCmd struct {
	Org  string `arg:"" optional:"" help:"Organisation, such as acme (default: list yours)"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// orgJSON is what org prints with --json.
type orgJSON struct {
	Org      string                `json:"org"`
	Projects []wire.ProjectSummary `json:"projects"`
	Groups   []wire.GroupSummary   `json:"groups"`
	Policy   *wire.OrgPolicy       `json:"policy"`
}

// Run implements org.
func (c *OrgCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
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
		orgs := mapKeys(count)
		slices.Sort(orgs)
		if c.JSON {
			return printJSON(nonNil(orgs))
		}
		if len(orgs) == 0 {
			fmt.Println("No organisations yet: share a project (esec vault access create) or create a group.")
			return nil
		}
		for _, o := range orgs {
			fmt.Printf("%-24s %d project(s), %d group(s)\n", o, count[o][0], count[o][1])
		}
		fmt.Println("Show one with: esec vault org ORG")
		return nil
	}
	in := func(id string) bool { return strings.EqualFold(orgName(id), c.Org) }
	projects = slices.DeleteFunc(projects, func(p wire.ProjectSummary) bool { return !in(p.ID) })
	groups = slices.DeleteFunc(groups, func(g wire.GroupSummary) bool { return !in(g.ID) })
	policy, err := a.OrgPolicy(bg, c.Org)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(orgJSON{Org: c.Org, Projects: nonNil(projects), Groups: nonNil(groups), Policy: policy})
	}
	if len(projects)+len(groups) == 0 {
		return fmt.Errorf("you have no shared project or group in %s", c.Org)
	}
	fmt.Printf("%s  (%s/orgs/%s)\n", c.Org, a.State.Server, c.Org)
	if len(projects) > 0 {
		fmt.Println("Projects:")
		for _, p := range projects {
			role := "reads " + joinOr(p.Envs, "nothing")
			if p.Admin {
				role = "admin"
			}
			fmt.Printf("  %-32s %-22s %d member(s), %d group(s), %d machine(s)\n", p.ID, role, p.Members, p.Groups, p.Machines)
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
			fmt.Printf("  %-32s %-22s %d people, %d machine(s), reads %s\n", g.ID, role, g.People, g.Machines, joinOr(g.Projects, "nothing"))
		}
	}
	fmt.Println("Policy (set by the server's admins, checked by the server):")
	fmt.Println("  " + policyText(policy))
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
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

// AccessReviewCmd reviews who reads a project.
type AccessReviewCmd struct {
	Project string   `help:"Project id (default: nearest .esec-project)"`
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
