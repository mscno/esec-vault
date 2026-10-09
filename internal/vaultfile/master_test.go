package vaultfile

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestDailyOpenRejectsDamagedOrRemovedRecoveryCopy(t *testing.T) {
	idPub, idPriv := testKey(t)
	masterPub, _ := testKey(t)
	data, err := Seal(&Vault{}, &idPub, &masterPub)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	bad[len(bad)-1] ^= 1
	if _, err := Open(bad, &idPub, &idPriv); err == nil {
		t.Fatal("daily verification accepted corrupted recovery copy")
	}
	end := headerLen + int(binary.BigEndian.Uint32(data[9:13]))
	stripped := append([]byte(nil), data[:end]...)
	stripped[8] = 0
	if _, err := Open(stripped, &idPub, &idPriv); err == nil {
		t.Fatal("accepted stripped recovery copy")
	}
}

// A blob sealed to both the identity and the master must open with either.
// The master copy is what lets a machine with no identity recover.
func TestSealToBothIdentityAndMaster(t *testing.T) {
	idPub, idPriv := testKey(t)
	masterPub, masterPriv := testKey(t)

	v := &Vault{
		Projects:   map[string]map[string]string{"org/repo": {"K": "v"}},
		Generation: 5,
		CreatedAt:  time.Now().UTC(),
	}
	data, err := Seal(v, &idPub, &masterPub)
	if err != nil {
		t.Fatal(err)
	}
	if !HasMasterCopy(data) {
		t.Fatal("blob should advertise a master copy")
	}

	viaIdentity, err := Open(data, &idPub, &idPriv)
	if err != nil {
		t.Fatalf("identity copy must open: %v", err)
	}
	viaMaster, err := OpenWithMaster(data, &masterPub, &masterPriv)
	if err != nil {
		t.Fatalf("master copy must open: %v", err)
	}
	if viaIdentity.Projects["org/repo"]["K"] != "v" || viaMaster.Projects["org/repo"]["K"] != "v" {
		t.Fatal("both copies must yield the same content")
	}
	if viaIdentity.Generation != 5 || viaMaster.Generation != 5 {
		t.Fatalf("generation mismatch: %d vs %d", viaIdentity.Generation, viaMaster.Generation)
	}
	if viaIdentity.CreatedAt.Unix() != viaMaster.CreatedAt.Unix() {
		t.Fatal("both copies must carry the same timestamp")
	}
}

// A master copy must not open with the wrong key.
func TestOpenWithMasterRejectsWrongKey(t *testing.T) {
	idPub, _ := testKey(t)
	masterPub, _ := testKey(t)
	_, otherMasterPriv := testKey(t)
	otherMasterPub, _ := testKey(t)

	data, err := Seal(&Vault{}, &idPub, &masterPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithMaster(data, &otherMasterPub, &otherMasterPriv); err == nil {
		t.Fatal("a wrong master key must not open the blob")
	}
}

// Tampering with the master copy must be caught.
func TestOpenWithMasterDetectsTampering(t *testing.T) {
	idPub, _ := testKey(t)
	masterPub, masterPriv := testKey(t)
	data, err := Seal(&Vault{Projects: map[string]map[string]string{"o/r": {"K": "v"}}}, &idPub, &masterPub)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	bad[len(bad)-2] ^= 0xff
	if _, err := OpenWithMaster(bad, &masterPub, &masterPriv); err == nil {
		t.Fatal("expected tamper detection on the master copy")
	}
}

// A blob with no master copy cannot be opened from the phrase alone; the error
// must say so rather than looking like corruption.
func TestOpenWithMasterWithoutMasterCopy(t *testing.T) {
	idPub, _ := testKey(t)
	data, err := Seal(&Vault{}, &idPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if HasMasterCopy(data) {
		t.Fatal("should have no master copy")
	}
	masterPub, masterPriv := testKey(t)
	_, err = OpenWithMaster(data, &masterPub, &masterPriv)
	if !errors.Is(err, ErrNoMasterCopy) {
		t.Fatalf("expected ErrNoMasterCopy, got %v", err)
	}
}

// The identity key must not open a master-only read path.
func TestSealToIdentityOnlyIsNotMasterReadable(t *testing.T) {
	idPub, idPriv := testKey(t)
	masterPub, masterPriv := testKey(t)
	data, err := Seal(&Vault{}, &idPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, &idPub, &idPriv); err != nil {
		t.Fatalf("identity read path must still work: %v", err)
	}
	if _, err := OpenWithMaster(data, &masterPub, &masterPriv); err == nil {
		t.Fatal("master read path must not work without a master copy")
	}
}

// Open tolerates master keys on the general path, so callers holding either
// key can use the same entry point.
func TestOpenFallsBackToMasterCopy(t *testing.T) {
	idPub, _ := testKey(t)
	masterPub, masterPriv := testKey(t)
	data, err := Seal(&Vault{Projects: map[string]map[string]string{"o/r": {"K": "v"}}}, &idPub, &masterPub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(data, &masterPub, &masterPriv)
	if err != nil {
		t.Fatalf("Open should fall back to the master copy: %v", err)
	}
	if got.Projects["o/r"]["K"] != "v" {
		t.Fatal("content mismatch via the fallback path")
	}
}

func TestReadWithMaster(t *testing.T) {
	idPub, _ := testKey(t)
	masterPub, masterPriv := testKey(t)
	path := t.TempDir() + "/vault.esec"
	if err := Write(path, &Vault{Projects: map[string]map[string]string{"o/r": {"K": "v"}}}, &idPub, &masterPub); err != nil {
		t.Fatal(err)
	}
	v, err := ReadWithMaster(path, &masterPub, &masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	if v.Projects["o/r"]["K"] != "v" {
		t.Fatal("round trip through file failed")
	}
}
