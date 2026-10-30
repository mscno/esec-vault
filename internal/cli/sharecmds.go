package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"

	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/seal"
)

// ShareCmd adds readers to environments.
type ShareCmd struct {
	Envs       []string `arg:"" sep:"," help:"Environments, such as dev,staging"`
	With       []string `required:"" sep:"," help:"Who: GitHub logins (alice), groups (group acme/backend), or keys (deploy=age1…)"`
	Project    string   `help:"Project id (default: the checkout here)"`
	AccountKey string   `help:"The account key words of the person (from their esec vault status), when they have not published a GitHub proof"`
	// Yes is accepted so scripts and esec setup can pass it. share does not ask.
	Yes bool `help:"Accepted for scripts; share does not ask a question"`
}

// Run implements share.
func (c *ShareCmd) Run(ctx *cliCtx) error {
	root, pf, err := checkoutFor(c.Project)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	var add []seal.Reader
	for _, w := range c.With {
		r, note, err := s.findReader(w, c.AccountKey)
		if err != nil {
			return err
		}
		if note != "" {
			fmt.Fprintln(os.Stderr, note)
		}
		add = append(add, r)
	}
	t := sealTarget{root, pf}
	for _, env := range c.Envs {
		if pf.Env[env].Key == "" {
			return fmt.Errorf("%s has no environment %s", pf.Project, env)
		}
		readers, err := readersOf(pf, env)
		if err != nil {
			return err
		}
		before := len(readers)
		for _, r := range add {
			if !hasReader(readers, r) {
				readers = append(readers, r)
			}
		}
		if len(readers) == before {
			fmt.Printf("%s already reads %s\n", names(add), env)
			continue
		}
		if err := resealEnv(s, t, env, readers); err != nil {
			return fmt.Errorf("%s: %w", env, err)
		}
		fmt.Printf("✓ %s %s: shared with %s\n", pf.Project, env, names(add))
	}
	fmt.Println("Commit .esec/ and esec.toml: the change is reviewed like code. Readers open the key with their own keys; nothing else to send.")
	return nil
}

// findReader turns who into a reader: a GitHub login (pinned by its
// numeric id), a group, or a named key.
func (s *sealing) findReader(who, accountKey string) (seal.Reader, string, error) {
	who = strings.TrimSpace(strings.TrimPrefix(who, "@"))
	switch {
	case strings.HasPrefix(who, "group "):
		r, err := seal.ParseReader(who)
		return r, "", err
	case strings.Contains(who, "="):
		name, key, _ := strings.Cut(who, "=")
		r, err := seal.ParseReader(strings.TrimSpace(name) + " (" + strings.TrimSpace(key) + ")")
		return r, "", err
	case strings.HasPrefix(who, "age1") || strings.HasPrefix(who, "ssh-"):
		r, err := seal.ParseReader(who)
		return r, "", err
	}
	if s.acct == nil {
		return seal.Reader{}, "", fmt.Errorf("sign in to a vault server to share with GitHub users (esec vault login), or share a key: --with %s=age1…", who)
	}
	found, err := s.acct.FindPerson(s.bg(), who, accountKey)
	if err != nil {
		return seal.Reader{}, "", err
	}
	r := seal.Reader{Kind: seal.KindPerson, ID: found.User, Label: found.Login}
	if found.Person == nil {
		return r, fmt.Sprintf("%s (%s) has no esec vault account yet: they are sealed in once they sign in and someone runs esec vault seal sync (the Mac app and setup do it for you).", found.Login, found.User), nil
	}
	return r, "", nil
}

func hasReader(list []seal.Reader, r seal.Reader) bool {
	for _, x := range list {
		if x.Kind == r.Kind && x.ID == r.ID {
			return true
		}
	}
	return false
}

func names(list []seal.Reader) string {
	out := make([]string, 0, len(list))
	for _, r := range list {
		out = append(out, r.Display())
	}
	return strings.Join(out, ", ")
}

// UnshareCmd removes readers from environments.
type UnshareCmd struct {
	Envs    []string `arg:"" sep:"," help:"Environments"`
	With    []string `required:"" sep:"," help:"Who: GitHub logins, groups (group acme/backend), or key names"`
	Project string   `help:"Project id (default: the checkout here)"`
	Rotate  bool     `help:"Also rotate the keys: removing a reader does not take back a key they may have kept"`
	Yes     bool     `help:"Do not ask before rotating"`
}

// Run implements unshare.
func (c *UnshareCmd) Run(ctx *cliCtx) error {
	root, pf, err := checkoutFor(c.Project)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	t := sealTarget{root, pf}
	for _, env := range c.Envs {
		readers, err := readersOf(pf, env)
		if err != nil {
			return err
		}
		removed := false
		for _, w := range c.With {
			who := unshareTarget(readers, w)
			var gone bool
			readers, gone = removeReader(readers, who)
			removed = removed || gone
		}
		if !removed {
			return fmt.Errorf("%s does not read %s", strings.Join(c.With, ", "), env)
		}
		if len(readers) == 0 {
			return fmt.Errorf("%s would have no reader left (its recovery key aside); share it with someone first", env)
		}
		if err := resealEnv(s, t, env, readers); err != nil {
			return err
		}
		fmt.Printf("✓ %s %s: no longer sealed to %s\n", pf.Project, env, strings.Join(c.With, ", "))
		if c.Rotate {
			if !c.Yes && !confirm(fmt.Sprintf("Rotate %s now (new key, files re-encrypted)?", env)) {
				continue
			}
			rot := &rotator{ctx: ctx, s: s}
			res, err := rot.rotate(pf.Project, env, root)
			if err != nil && res == nil {
				return err
			}
			fmt.Printf("✓ %s rotated: new public key %s\n", env, res.NewPublic)
		}
	}
	if !c.Rotate {
		fmt.Println("They may have kept the key: rotate to be sure (esec vault env rotate ENV), and change values they may have read at their providers.")
	}
	return nil
}

// unshareTarget finds the reader who names: a login, a key's name, a group.
func unshareTarget(readers []seal.Reader, who string) seal.Reader {
	who = strings.TrimSpace(strings.TrimPrefix(who, "@"))
	for _, r := range readers {
		if strings.EqualFold(r.Label, who) || r.ID == who || r.String() == who {
			return r
		}
	}
	if r, err := seal.ParseReader(who); err == nil {
		return r
	}
	return seal.Reader{Kind: "none", ID: who}
}

// CICmd gives CI jobs and deploys their own key to environments.
type CICmd struct {
	Add    CIAddCmd    `cmd:"" help:"Give a CI job or deploy its own age key, sealed into environments; it then needs only esec."`
	Remove CIRemoveCmd `cmd:"" help:"Stop sealing environments to a CI key."`
}

// CIAddCmd adds a CI key.
type CIAddCmd struct {
	Name    string   `arg:"" help:"A name for it, such as deploy or github-actions"`
	Envs    []string `name:"env" sep:"," required:"" help:"Environments it reads, such as staging,prod"`
	Project string   `help:"Project id (default: the checkout here)"`
	GitHub  string   `name:"github" help:"Store the key as the secret ESEC_AGE_IDENTITY of this GitHub repository (OWNER/REPO), with gh"`
	Fly     string   `help:"Store the key as the secret ESEC_AGE_IDENTITY of this Fly app, with fly"`
}

// Run implements ci add.
func (c *CIAddCmd) Run(ctx *cliCtx) error {
	root, pf, err := checkoutFor(c.Project)
	if err != nil {
		return err
	}
	if !labelOK(c.Name) {
		return fmt.Errorf("invalid name %q: letters, digits, dots, dashes", c.Name)
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	reader := seal.Reader{Kind: seal.KindKey, ID: id.Recipient().String(), Label: c.Name}
	t := sealTarget{root, pf}
	for _, env := range c.Envs {
		readers, err := readersOf(pf, env)
		if err != nil {
			return err
		}
		for _, r := range readers {
			if r.Kind == seal.KindKey && r.Label == c.Name {
				return fmt.Errorf("%s already reads %s: esec vault ci remove %s first", c.Name, env, c.Name)
			}
		}
		if err := resealEnv(s, t, env, append(readers, reader)); err != nil {
			return err
		}
	}
	secret := id.String()
	switch {
	case c.GitHub != "":
		if err := storeSecret(secret, "gh", "secret", "set", "ESEC_AGE_IDENTITY", "--repo", c.GitHub); err != nil {
			return fmt.Errorf("the key is sealed in, but storing it in GitHub failed (%w): run esec vault ci remove %s and try again", err, c.Name)
		}
		fmt.Printf("✓ Stored as the secret ESEC_AGE_IDENTITY of %s. In the workflow: env: ESEC_AGE_IDENTITY: ${{ secrets.ESEC_AGE_IDENTITY }}\n", c.GitHub)
	case c.Fly != "":
		if err := storeSecret("ESEC_AGE_IDENTITY="+secret+"\n", "fly", "secrets", "import", "--app", c.Fly); err != nil {
			return fmt.Errorf("the key is sealed in, but storing it in Fly failed (%w): run esec vault ci remove %s and try again", err, c.Name)
		}
		fmt.Printf("✓ Stored as the secret ESEC_AGE_IDENTITY of the Fly app %s.\n", c.Fly)
	default:
		fmt.Fprintln(os.Stderr, "Its key, shown once (store it as the CI secret ESEC_AGE_IDENTITY; it is not kept anywhere):")
		fmt.Println(secret)
	}
	fmt.Printf("✓ %s reads %s of %s with esec alone: esec run %s -- COMMAND. Commit .esec/ and esec.toml.\n", c.Name, strings.Join(c.Envs, ", "), pf.Project, c.Envs[0])
	return nil
}

// storeSecret runs a CLI (gh, fly) with the secret on its standard input,
// never on its command line.
func storeSecret(secret string, name string, args ...string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s is not installed", name)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(secret)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return errors.New(safetext.Clean(strings.TrimSpace(out.String())))
	}
	return nil
}

// CIRemoveCmd removes a CI key.
type CIRemoveCmd struct {
	Name    string   `arg:"" help:"The CI key's name"`
	Envs    []string `name:"env" sep:"," help:"Environments (default: every one it reads)"`
	Project string   `help:"Project id (default: the checkout here)"`
}

// Run implements ci remove.
func (c *CIRemoveCmd) Run(ctx *cliCtx) error {
	root, pf, err := checkoutFor(c.Project)
	if err != nil {
		return err
	}
	s, err := newSealing(ctx)
	if err != nil {
		return err
	}
	t := sealTarget{root, pf}
	n := 0
	for _, env := range pf.Envs() {
		if len(c.Envs) > 0 && !containsString(c.Envs, env) {
			continue
		}
		readers, err := readersOf(pf, env)
		if err != nil {
			return err
		}
		left, removed := removeReader(readers, seal.Reader{Kind: seal.KindKey, Label: c.Name})
		if !removed {
			continue
		}
		if err := resealEnv(s, t, env, left); err != nil {
			return err
		}
		fmt.Printf("✓ %s %s: no longer sealed to %s\n", pf.Project, env, c.Name)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no environment of %s is sealed to %s", pf.Project, c.Name)
	}
	fmt.Println("Delete its ESEC_AGE_IDENTITY secret where you stored it; rotate (esec vault env rotate ENV) if it may have leaked.")
	return nil
}

func labelOK(s string) bool {
	_, err := seal.ParseReader(s + " (age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq)")
	return err == nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
