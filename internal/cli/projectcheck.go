package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

// ProjectCheckCmd asks the vault server whether a project id can be created.
// It writes nothing and prints no secret. Exit 0 includes "taken": the JSON
// says so. Exit 1 is a server or sign-in failure. Exit 80 is a bad id.
type ProjectCheckCmd struct {
	ID   string `arg:"" help:"Project id (org/repo[/path])"`
	JSON bool   `help:"Print JSON, for scripts and agents"`
}

// projectCheckJSON is the contract esec setup reads.
type projectCheckJSON struct {
	Project      string          `json:"project"`
	Available    bool            `json:"available"`
	Relation     string          `json:"relation"`
	Namespace    *projectCheckNS `json:"namespace,omitempty"`
	LocalKeyring bool            `json:"local_keyring"`
	Error        string          `json:"error,omitempty"`
}

type projectCheckNS struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	YouMayCreate bool   `json:"you_may_create"`
	Reason       string `json:"reason,omitempty"`
}

// Run implements project check.
func (c *ProjectCheckCmd) Run(ctx *cliCtx) error {
	if err := projectfile.ValidateOrgRepo(c.ID); err != nil {
		return &exitCodeError{code: 80, msg: err.Error()}
	}
	res, err := inspectProject(ctx, c.ID)
	if err != nil {
		return err
	}
	if c.JSON {
		return printJSON(res)
	}
	fmt.Printf("%s: %s\n", res.Project, res.Relation)
	if res.Namespace != nil && res.Namespace.Reason != "" {
		fmt.Println(res.Namespace.Reason)
	}
	if res.LocalKeyring {
		fmt.Println("a keyring for this project is already on this machine")
	}
	return nil
}

func inspectProject(ctx *cliCtx, id string) (projectCheckJSON, error) {
	res := projectCheckJSON{Project: id, LocalKeyring: localKeyring(id)}
	nsName := team.OrgOf(id)
	if reservedNamespaceName(nsName) {
		res.Relation = "system"
		res.Namespace = &projectCheckNS{Name: nsName, Kind: "system", Reason: nsName + " is a reserved name"}
		return res, nil
	}
	if _, err := account.LoadState(); errors.Is(err, account.ErrNotLoggedIn) {
		return res, fmt.Errorf("not signed in to a vault server: esec vault login")
	} else if err != nil {
		return res, err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return res, err
	}
	bg, cancel := timeout(20 * time.Second)
	defer cancel()
	ns, err := a.Client.Namespace(bg, nsName)
	switch {
	case client.IsCode(err, wire.ErrNotFound):
		res.Relation = "available"
		res.Available = false
		res.Namespace = &projectCheckNS{Name: nsName, Kind: "missing", Reason: "namespace " + nsName + " does not exist; create it first (esec vault org create, or esec vault personal choose)"}
		return res, nil
	case err != nil:
		return res, err
	}
	return finishCheck(bg, a, res, nsName, ns)
}

func localKeyring(project string) bool {
	p := filepath.Join(paths.KeyringDir(), projectfile.KeyringName(project))
	info, err := os.Lstat(p)
	return err == nil && info.Mode()&os.ModeSymlink == 0
}

// reservedNamespaceName matches the server's reserved handles. A check must
// refuse these even when the server has not stored them.
func reservedNamespaceName(name string) bool {
	switch strings.ToLower(name) {
	case "admin", "api", "auth", "system", "support", "www", "vault", "esec", "orgs", "projects", "settings", "login", "device", "devices", "account", "groups", "changes", "teams", "v1":
		return true
	}
	return false
}
