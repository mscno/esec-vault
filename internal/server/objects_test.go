package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/mscno/esec-vault/internal/client"
	"github.com/mscno/esec-vault/internal/wire"
)

func TestArchiveObjectsRequireActiveAccountAndMatchingDigest(t *testing.T) {
	h := harness(t)
	d := signIn(t, h, nil, "owner")
	create(t, d)
	ctx := context.Background()
	blob := bytes.Repeat([]byte{0x7d}, 64)
	sum := sha256.Sum256(blob)
	id := hex.EncodeToString(sum[:])
	// A database object belonging to a different account is never visible
	// even when an active device knows its exact ciphertext hash.
	if _, err := h.DB.SQL().Exec(`INSERT INTO vault_objects(user_id,id,blob,created_at) VALUES(?,?,?,0)`, "gh:7", id, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := d.c.VaultObject(ctx, id); !client.IsCode(err, wire.ErrNotFound) {
		t.Fatalf("foreign object disclosed: %v", err)
	}
	if err := d.c.PutVaultObject(ctx, id, blob); err != nil {
		t.Fatal(err)
	}
	if err := d.c.PutVaultObject(ctx, id, blob); err != nil {
		t.Fatal("idempotent retry failed", err)
	}
	got, err := d.c.VaultObject(ctx, id)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatal("own object unavailable")
	}
	changed := bytes.Clone(blob)
	changed[0]++
	if err := d.c.PutVaultObject(ctx, id, changed); err == nil {
		t.Fatal("immutable ciphertext replaced")
	}
	pending := signIn(t, h, nil, "pending")
	if _, err := pending.c.VaultObject(ctx, id); err == nil {
		t.Fatal("pending device read file history")
	}
	if err := pending.c.PutVaultObject(ctx, id, blob); err == nil {
		t.Fatal("pending device uploaded history")
	}
}
