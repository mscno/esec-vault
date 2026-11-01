package cli

import (
	"context"
	"strings"

	"github.com/mscno/esec-vault/internal/account"
	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/wire"
)

// finishCheck applies a resolved namespace and whether the project is shared.
func finishCheck(bg context.Context, a *account.Account, res projectCheckJSON, asked string, ns *wire.Namespace) (projectCheckJSON, error) {
	kind := ns.Kind
	if kind == "" {
		kind = "unknown"
	}
	current := ns.Name
	if current == "" {
		current = ns.Canonical
	}
	nsOut := &projectCheckNS{Name: current, Kind: kind}
	if current != "" && !strings.EqualFold(current, asked) {
		res.Relation = "alias"
		nsOut.Reason = asked + " is a previous name of " + current + "; use " + current
		res.Namespace = nsOut
		return res, nil
	}
	if kind == "legacy" {
		res.Relation = "legacy"
		nsOut.Reason = asked + " is a legacy name; an operator must approve it before new projects"
		res.Namespace = nsOut
		return res, nil
	}
	may, reason := mayCreate(bg, a, asked, ns)
	nsOut.YouMayCreate = may
	nsOut.Reason = reason
	res.Namespace = nsOut

	rel, err := projectRelation(bg, a, res.Project)
	if err != nil {
		return res, err
	}
	switch rel {
	case "yours":
		res.Relation = "yours"
		return res, nil
	case "taken":
		res.Relation = "taken"
		if nsOut.Reason == "" {
			nsOut.Reason = res.Project + " already exists and is not yours"
		}
		return res, nil
	}
	if may {
		res.Relation = "available"
		res.Available = true
		return res, nil
	}
	res.Relation = "reserved"
	if nsOut.Reason == "" {
		nsOut.Reason = "you cannot create projects in " + asked
	}
	return res, nil
}

func mayCreate(bg context.Context, a *account.Account, asked string, ns *wire.Namespace) (bool, string) {
	switch ns.Kind {
	case "personal":
		if ns.Owner == a.State.User {
			return true, ""
		}
		return false, asked + " is someone else's personal namespace"
	case "team", "organisation":
		if ns.Owner == a.State.User {
			return true, ""
		}
		view, err := a.Org(bg, asked)
		if client.IsCode(err, wire.ErrForbidden) {
			return false, asked + " is an organisation, and you are not in it"
		}
		if err != nil {
			return false, err.Error()
		}
		if view != nil && view.State != nil && !view.State.In(a.State.User) {
			return false, asked + " is an organisation, and you are not in it"
		}
		if ns.Owner != "" && ns.Owner != a.State.User && (view == nil || view.State == nil) {
			return false, asked + " is reserved for another account"
		}
		return true, ""
	default:
		return false, "namespace " + asked + " is not one you can create in"
	}
}

// projectRelation is yours, taken, or "" when the server has no such project.
func projectRelation(bg context.Context, a *account.Account, id string) (string, error) {
	if strings.Count(id, "/") != 1 {
		// The server's project API is org/repo. A longer id is a local
		// subproject; membership of the parent is not this id.
		return "", nil
	}
	_, err := a.Client.ProjectChain(bg, id)
	switch {
	case err == nil:
		return "yours", nil
	case client.IsCode(err, wire.ErrNotFound):
		return "", nil
	case client.IsCode(err, wire.ErrForbidden):
		return "taken", nil
	default:
		return "", err
	}
}
