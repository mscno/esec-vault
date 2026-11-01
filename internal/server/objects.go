package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/mscno/esec-vault/internal/wire"
)

var objectID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) apiVaultObjectGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := r.PathValue("id")
	if !objectID.MatchString(id) {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid object id")
		return
	}
	var blob []byte
	err := s.db.sql.QueryRowContext(r.Context(), `SELECT blob FROM vault_objects WHERE user_id = ? AND id = ?`, c.user.ID, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound, "object not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.VaultObject{Blob: blob})
}

func (s *Server) apiVaultObjectPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := r.PathValue("id")
	var object wire.VaultObject
	if !objectID.MatchString(id) || decodeStrict(c.body, &object) != nil || len(object.Blob) < 40 || len(object.Blob) > 5<<20 {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "invalid encrypted object")
		return
	}
	sum := sha256.Sum256(object.Blob)
	if hex.EncodeToString(sum[:]) != id {
		writeErr(w, http.StatusBadRequest, wire.ErrInvalidRequest, "object digest mismatch")
		return
	}
	ctx := r.Context()
	err := s.db.tx(ctx, func(tx *sql.Tx) error { return s.putObject(ctx, tx, c.user.ID, id, object.Blob) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) putObject(ctx context.Context, tx *sql.Tx, user, id string, blob []byte) error {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_objects WHERE user_id = ? AND id = ?`, user, id).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	var count, bytes int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),coalesce(SUM(length(blob)),0) FROM vault_objects WHERE user_id = ?`, user).Scan(&count, &bytes); err != nil {
		return err
	}
	// Bound orphan uploads as well as committed history. Objects are not
	// automatically pruned: older retained vaults may still reference them.
	if count >= 50000 || bytes+int64(len(blob)) > 1<<30 {
		return clientErr(http.StatusRequestEntityTooLarge, wire.ErrInvalidRequest, "encrypted file archive quota reached (1 GiB or 50000 revisions)")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO vault_objects(user_id,id,blob,created_at) VALUES(?,?,?,?)`, user, id, blob, s.now().Unix())
	return err
}
