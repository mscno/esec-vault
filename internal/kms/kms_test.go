package kms_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/servertest"
)

func TestGCPWrapUnwrap(t *testing.T) {
	gcp := servertest.NewFakeGCP(t)
	fly := servertest.NewFakeFly(t, "acme", "store")
	for _, kv := range gcp.Env() {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	pub, err := kms.PublicKeyFromPEM([]byte(gcp.PublicKeyPEM()))
	if err != nil {
		t.Fatal(err)
	}
	key := kms.Key{Provider: "gcp", Name: gcp.KeyName, Audience: gcp.Provider, PublicKey: pub}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	box, err := key.Wrap([]byte("the group key"))
	if err != nil {
		t.Fatal(err)
	}
	token := func(_ context.Context, aud string) (string, error) { return fly.Token(aud), nil }
	plain, err := key.Unwrap(context.Background(), box, token)
	if err != nil || string(plain) != "the group key" {
		t.Fatalf("unwrap: %q %v", plain, err)
	}
	// The provider's attribute condition refuses another app.
	gcp.SetAllow(func(c map[string]any) bool { return c["app_name"] == "web" })
	if _, err := key.Unwrap(context.Background(), box, token); err == nil || !strings.Contains(err.Error(), "attribute condition") {
		t.Fatalf("another app: %v", err)
	}
	// Names are checked.
	for _, bad := range []kms.Key{
		{Provider: "gcp", Name: "keyRings/x", Audience: gcp.Provider, PublicKey: pub},
		{Provider: "gcp", Name: gcp.KeyName, Audience: "pools/x", PublicKey: pub},
		{Provider: "nope", Name: gcp.KeyName, Audience: gcp.Provider, PublicKey: pub},
		{Provider: "gcp", Name: gcp.KeyName, Audience: gcp.Provider, PublicKey: "AAAA"},
	} {
		if bad.Validate() == nil {
			t.Fatalf("valid: %+v", bad)
		}
	}
	if key.Fingerprint() == (kms.Key{Provider: "gcp", Name: gcp.KeyName + "2", Audience: gcp.Provider, PublicKey: pub}).Fingerprint() {
		t.Fatal("fingerprint ignores the key name")
	}
}

func TestOpenBaoWrapUnwrap(t *testing.T) {
	bao := servertest.NewFakeOpenBao(t, map[string]any{"org_name": "acme", "app_name": "store"})
	fly := servertest.NewFakeFly(t, "acme", "store")
	pemText, err := kms.OpenBaoPublicKey(context.Background(), bao.KeyName(), "root")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kms.PublicKeyFromPEM(pemText)
	if err != nil {
		t.Fatal(err)
	}
	key := kms.Key{Provider: "openbao", Name: bao.KeyName(), Audience: bao.Audience, Principal: "jwt/" + bao.Role, PublicKey: pub}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	box, err := key.Wrap([]byte("the group key"))
	if err != nil {
		t.Fatal(err)
	}
	token := func(_ context.Context, aud string) (string, error) { return fly.Token(aud), nil }
	plain, err := key.Unwrap(context.Background(), box, token)
	if err != nil || string(plain) != "the group key" {
		t.Fatalf("unwrap: %q %v", plain, err)
	}
	fly.SetMachine("acme", "web")
	if _, err := key.Unwrap(context.Background(), box, token); err == nil || !strings.Contains(err.Error(), "bound claim") {
		t.Fatalf("another app: %v", err)
	}
	for _, bad := range []string{"http://bao.example.com/transit/k/1", "https://bao.example.com/transit/k", "https://bao.example.com/transit/k/v1"} {
		if (kms.Key{Provider: "openbao", Name: bad, Audience: "a", Principal: "jwt/r", PublicKey: pub}).Validate() == nil {
			t.Fatalf("valid: %s", bad)
		}
	}
}
