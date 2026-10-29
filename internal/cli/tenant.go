package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// OrgOwnerCmd changes the signed tenant ownership roster.
type OrgOwnerCmd struct {
	Org    string `arg:""`
	Login  string `arg:""`
	Remove bool   `help:"Remove ownership but retain admin rights"`
}

// Run implements org owner.
func (c *OrgOwnerCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.SetOrgOwner(bg, c.Org, c.Login, !c.Remove); err != nil {
		return err
	}
	fmt.Printf("✓ Ownership of %s updated for %s.\n", c.Org, c.Login)
	return nil
}

// OrgRenameCmd updates a tenant's handle or display name.
type OrgRenameCmd struct {
	Org         string `arg:""`
	Namespace   string `arg:"" optional:""`
	DisplayName string `help:"Human-readable tenant name (not its namespace)"`
}

// Run implements org rename.
func (c *OrgRenameCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.SetTenantProfile(bg, c.Org, c.Namespace, c.DisplayName); err != nil {
		return err
	}
	fmt.Println("✓ Tenant profile updated. Its identity and history are unchanged; previous namespaces stay reserved.")
	return nil
}

// PersonalCmd manages the one personal tenant of an account.
type PersonalCmd struct {
	Show   PersonalShowCmd   `cmd:"" default:"withargs" help:"Show your personal namespace."`
	Choose PersonalChooseCmd `cmd:"" help:"Pick an available personal namespace after a login-name collision."`
	Rename PersonalRenameCmd `cmd:"" help:"Rename your personal namespace, keeping its identity and history."`
}

// PersonalShowCmd displays the selected personal namespace.
type PersonalShowCmd struct {
	JSON bool `help:"Print JSON"`
}

func personalNamespace(names []wire.Namespace, user string) *wire.Namespace {
	for _, n := range names {
		if n.Kind == "personal" && n.Owner == user {
			return &n
		}
	}
	return nil
}

// Run implements personal show.
func (c *PersonalShowCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	names, err := a.Client.Namespaces(bg)
	if err != nil {
		return err
	}
	n := personalNamespace(names, a.State.User)
	if c.JSON {
		return printJSON(n)
	}
	if n == nil {
		fmt.Println("Choose your personal namespace: esec vault personal choose NAME")
		return nil
	}
	fmt.Printf("%s · personal · %s\n", n.Name, n.TenantID)
	return nil
}

// PersonalChooseCmd finishes personal onboarding after a collision.
type PersonalChooseCmd struct {
	Namespace string `arg:""`
}

// Run implements personal choose.
func (c *PersonalChooseCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	if err := a.Client.ChoosePersonal(bg, strings.ToLower(c.Namespace)); err != nil {
		return err
	}
	if err := ensurePersonalChain(a, strings.ToLower(c.Namespace)); err != nil {
		return err
	}
	fmt.Printf("✓ Personal namespace: %s\n", strings.ToLower(c.Namespace))
	return nil
}

// PersonalRenameCmd preserves personal identity while changing its handle.
type PersonalRenameCmd struct {
	Namespace   string `arg:""`
	DisplayName string `help:"Human-readable personal tenant name"`
}

// Run implements personal rename.
func (c *PersonalRenameCmd) Run(ctx *cliCtx) error {
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	bg, cancel := timeout(time.Minute)
	defer cancel()
	names, err := a.Client.Namespaces(bg)
	if err != nil {
		return err
	}
	n := personalNamespace(names, a.State.User)
	if n == nil {
		return fmt.Errorf("choose a personal namespace first")
	}
	if err := ensurePersonalChain(a, n.Name); err != nil {
		return err
	}
	if err := a.SetTenantProfile(bg, n.Name, c.Namespace, c.DisplayName); err != nil {
		return err
	}
	fmt.Println("✓ Personal namespace renamed; GitHub login and tenant identity are unchanged.")
	return nil
}

// A name collision never undoes successful authentication. Non-interactive
// clients can supply --personal-namespace or finish onboarding later.
func finishPersonalLogin(a *account.Account, wanted string) error {
	bg, cancel := timeout(time.Minute)
	defer cancel()
	names, err := a.Client.Namespaces(bg)
	if err != nil {
		return fmt.Errorf("signed in, but namespace lookup failed: %w", err)
	}
	n := personalNamespace(names, a.State.User)
	if n != nil {
		if wanted != "" && strings.ToLower(wanted) != n.Name {
			return fmt.Errorf("signed in; personal namespace is %s (use personal rename to change it)", n.Name)
		}
		fmt.Printf("Personal tenant: %s\n", n.Name)
		return ensurePersonalChain(a, n.Name)
	}
	fmt.Println("Signed in. Your GitHub username is unavailable as a personal namespace; choose another.")
	var suggestions []string
	for _, name := range team.PersonalCandidates(a.State.Login) {
		if _, err := a.Client.Namespace(bg, name); client.IsCode(err, wire.ErrNotFound) {
			suggestions = append(suggestions, name)
		}
	}
	if len(suggestions) > 0 {
		fmt.Println("Available suggestions:", strings.Join(suggestions, ", "))
	}
	for tries := 0; tries < 5; tries++ {
		name := wanted
		if name == "" {
			var err error
			name, err = promptLine("Personal namespace (empty to finish later): ")
			if err != nil || name == "" {
				fmt.Println("Finish later: esec vault personal choose NAME")
				return nil
			}
		}
		if err := a.Client.ChoosePersonal(bg, strings.ToLower(name)); err != nil {
			if wanted != "" {
				return err
			}
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		fmt.Printf("✓ Personal namespace: %s\n", strings.ToLower(name))
		return ensurePersonalChain(a, strings.ToLower(name))
	}
	fmt.Println("Finish later: esec vault personal choose NAME")
	return nil
}

func ensurePersonalChain(a *account.Account, name string) error {
	bg, cancel := timeout(time.Minute)
	defer cancel()
	v, err := a.Org(bg, name)
	if err != nil {
		return err
	}
	if v.State != nil {
		return nil
	}
	_, err = a.CreateOrg(bg, name)
	if err != nil {
		return fmt.Errorf("signed in; personal tenant initialization is pending: %w", err)
	}
	return nil
}
