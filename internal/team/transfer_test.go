package team_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/mscno/esec-vault/internal/envelope"
	"github.com/mscno/esec-vault/internal/team"
)

func TestTransferConsentAndSealedDelivery(t *testing.T) {
	alice, bob := newAcct(t, 1, "alice"), newAcct(t, 2, "bob")
	w := newWorld(t, alice, bob)
	pub, priv := newKey(t)
	w.add(alice, team.TypeInit, team.InitBody{Creator: alice.person(), Envs: []team.Env{{Name: "dev", PublicKey: pub}}})
	source := w.st
	dest := "receiving/api"
	body := team.InitBody{Creator: bob.person(), Envs: []team.Env{{Name: "dev", PublicKey: pub}}, Predecessor: &team.ProjectRef{Project: project, Root: source.Root()}}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	init, err := envelope.New(team.KindLink, team.Link{Project: dest, Seq: 1, CTime: w.now, Type: team.TypeInit, Signer: bob.user, SignerKey: bob.st.UKeyVersion, SignerSeq: bob.st.Seq, Body: raw})
	if err != nil {
		t.Fatal(err)
	}
	archive := w.link(alice, team.TypeArchive, team.ArchiveBody{Successor: &team.ProjectRef{Project: dest, Root: init.Hash()}})
	sid, _ := team.NewTenantID()
	did, _ := team.NewTenantID()
	o := team.TransferOffer{Source: project, Destination: dest, SourceRoot: source.Root(), SourceHead: source.Head(), SourceTenant: sid, DestinationTenant: did, Sender: alice.user, SenderKey: alice.st.UKeyVersion, Recipient: bob.user, RecipientRoot: bob.st.Root(), RecipientKey: bob.st.UKeyVersion, RecipientEncPub: hex.EncodeToString(bob.u.Public[:]), Init: init, Archive: archive, Created: w.now, Expires: w.now.Add(time.Hour)}
	if err := team.SealTransferKeys(&o, map[string]string{"dev": priv}, bob.u.Public); err != nil {
		t.Fatal(err)
	}
	e, err := envelope.New(team.KindTransferOffer, o, alice.u.Sign)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := team.CheckTransferOffer(e, source, w.chains, w.now)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := team.OpenTransferKeys(checked, bob.u.Public, bob.u.Private)
	if err != nil || keys["dev"] != priv {
		t.Fatalf("recipient key delivery: %v", err)
	}
	if _, err := team.OpenTransferKeys(checked, alice.u.Public, alice.u.Private); err == nil {
		t.Fatal("sender key decrypted recipient-only delivery")
	}
	signed := team.SignTransferInit(checked, bob.u.Sign)
	if signed.Hash() != init.Hash() {
		t.Fatal("countersigning changed the authorized destination root")
	}
	if _, err := team.Verify(dest, []*envelope.Envelope{signed}, w.chains); err != nil {
		t.Fatalf("accepted destination: %v", err)
	}
	if _, err := team.CheckTransferOffer(e, source, w.chains, w.now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired offer remained valid")
	}
	bad := o
	bad.Destination = "receiving/substituted"
	tampered, _ := envelope.New(team.KindTransferOffer, bad)
	tampered.Sigs = e.Sigs
	if _, err := team.CheckTransferOffer(tampered, source, w.chains, w.now); err == nil {
		t.Fatal("substituted signed destination accepted")
	}
	// Even a source-signed offer must preserve its signed environment keys.
	wrongPub, _ := newKey(t)
	body.Envs[0].PublicKey = wrongPub
	wrongRaw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := team.PeekLink(init)
	l.Body = wrongRaw
	bad = o
	bad.Init, _ = envelope.New(team.KindLink, l)
	wrongOffer, _ := envelope.New(team.KindTransferOffer, bad, alice.u.Sign)
	if _, err := team.CheckTransferOffer(wrongOffer, source, w.chains, w.now); err == nil {
		t.Fatal("source and destination environment identities diverged")
	}
	w.add(alice, team.TypeEnvSet, team.EnvSetBody{Env: team.Env{Name: "qa", PublicKey: wrongPub}})
	if _, err := team.CheckTransferOffer(e, w.st, w.chains, w.now); err == nil {
		t.Fatal("offer survived a changed source head")
	}
	bob.rotate(w.now.Add(time.Minute))
	if _, err := team.CheckTransferOffer(e, source, w.chains, w.now); err == nil {
		t.Fatal("offer survived recipient key rotation")
	}
}
