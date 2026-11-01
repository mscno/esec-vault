package securitykey

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUnchangedRegistryDoesNotTriggerFileWatchers(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	detected, _ := Parse(listOutput)
	r := &Registry{Source: "account"}
	if err := r.Add(FromDetected(detected[0], "daily key")); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	// Give the existing file an unmistakable timestamp: another atomic
	// rewrite (even with identical bytes) wakes the app's directory watch.
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(File(), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(File())
	r.Refresh(r.SecurityKeys())
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(File())
	if !os.SameFile(before, after) || !after.ModTime().Equal(stamp) {
		t.Fatal("unchanged registry replaced the watched file")
	}
	r.Keys[0].Name = "renamed key"
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got.Keys[0].Name != "renamed key" {
		t.Fatalf("a real change was not saved: %+v %v", got, err)
	}
}

func TestUnprovisionedReusesDetectedKeys(t *testing.T) {
	prev := Run
	t.Cleanup(func() { Run = prev })
	Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "ykman" || strings.Join(args, " ") != "list --serials" {
			t.Fatalf("a second age scan reopened the card: %s %v", name, args)
		}
		return []byte("15584441\n31415926\n"), nil
	}
	found, _ := Parse(listOutput)
	none, err := DetectUnprovisionedWith(context.Background(), found)
	if err != nil || len(none) != 1 || none[0] != "31415926" {
		t.Fatalf("unprovisioned: %v %v", none, err)
	}
}
