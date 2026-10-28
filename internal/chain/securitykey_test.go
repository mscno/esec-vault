package chain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSecurityKeyLinks(t *testing.T) {
	s := &State{SecurityKeys: map[string]*SecurityKeyState{}}
	link := func(seq int64, typ string, body any) Link {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return Link{Seq: uint64(seq), Type: typ, CTime: time.Unix(seq, 0), Body: raw} //nolint:gosec // small positive test sequence numbers
	}
	k := SecurityKey{ID: "yubikey:15584441:1", Kind: SecurityKeyYubiKey, Name: "blue", Serial: "15584441",
		Recipient: "age1yubikey1qf28gwqh38gcsqlukuyk0vpae0lw26dvt05rvm7k0y2t90367cunzs00yyk"}
	if err := s.applySecurityKeyAdd(link(2, TypeSecurityKeyAdd, SecurityKeyAddBody{Key: k})); err != nil {
		t.Fatal(err)
	}
	if got := s.ActiveSecurityKeys(); len(got) != 1 || got[0].Name != "blue" {
		t.Fatalf("active: %+v", got)
	}
	again := k
	again.ID = "yubikey:15584441:2"
	if err := s.applySecurityKeyAdd(link(3, TypeSecurityKeyAdd, SecurityKeyAddBody{Key: again})); err == nil {
		t.Fatal("a recipient was registered twice")
	}
	bad := k
	bad.ID, bad.Recipient = "x", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	if err := s.applySecurityKeyAdd(link(4, TypeSecurityKeyAdd, SecurityKeyAddBody{Key: bad})); err == nil {
		t.Fatal("a software key was registered as a security key")
	}
	if err := s.applySecurityKeyRemove(link(5, TypeSecurityKeyRemove, SecurityKeyRemoveBody{ID: k.ID})); err != nil {
		t.Fatal(err)
	}
	if len(s.ActiveSecurityKeys()) != 0 {
		t.Fatal("removed key still active")
	}
	if err := s.applySecurityKeyRemove(link(6, TypeSecurityKeyRemove, SecurityKeyRemoveBody{ID: k.ID})); err == nil {
		t.Fatal("removed twice")
	}
}
