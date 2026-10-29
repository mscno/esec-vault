package server

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/mscno/esec-vault/internal/team"
	"github.com/mscno/esec-vault/internal/wire"
)

func (s *Server) updateTenantProfile(ctx context.Context, tx *sql.Tx, os *team.OrgState) error {
	n, err := namespace(ctx, tx, os.Org)
	if err != nil {
		return err
	}
	if n == nil || n.TenantID != os.TenantID || reservedNamespace(os.Namespace) {
		return clientErr(http.StatusBadRequest, wire.ErrInvalidRequest, "invalid tenant identity or reserved namespace")
	}
	other, err := namespace(ctx, tx, os.Namespace)
	if err != nil {
		return err
	}
	if other != nil && other.TenantID != n.TenantID {
		return clientErr(http.StatusConflict, wire.ErrConflict, "namespace %s is unavailable", os.Namespace)
	}
	if other == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO namespaces(name,kind,owner,created_at,tenant_id) VALUES (?,'legacy','',?,?)`, os.Namespace, s.now().Unix(), n.TenantID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE tenants SET namespace=?,display_name=? WHERE id=?`, os.Namespace, os.DisplayName, n.TenantID)
	return err
}

// sameTenant compares immutable identities rather than mutable handles.
func sameTenant(ctx context.Context, q queryer, a, b string) (bool, error) {
	if team.OrgOf(a) == team.OrgOf(b) {
		return true, nil
	}
	x, err := namespace(ctx, q, team.OrgOf(a))
	if err != nil {
		return false, err
	}
	y, err := namespace(ctx, q, team.OrgOf(b))
	if err != nil {
		return false, err
	}
	return x != nil && y != nil && x.TenantID != "" && x.TenantID == y.TenantID, nil
}
