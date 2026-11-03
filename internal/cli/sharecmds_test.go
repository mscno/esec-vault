package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCIAddRejectsInvalidDestinationsBeforeOpeningAccount(t *testing.T) {
	for _, cmd := range []CIAddCmd{{Stage: true}, {Stage: true, GitHub: "example/repo"}, {Fly: "example", GitHub: "example/repo"}} {
		if err := cmd.Run(nil); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
}

func TestFlyIdentityStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FLY_TEST_OUTPUT", dir)
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FLY_TEST_OUTPUT/args\"\ncat > \"$FLY_TEST_OUTPUT/stdin\"\n"
	if err := os.WriteFile(filepath.Join(dir, "fly"), []byte(stub), 0700); err != nil { //nolint:gosec // executable fixture in t.TempDir
		t.Fatal(err)
	}
	for _, stage := range []bool{false, true} {
		if err := storeFlyIdentity("synthetic-identity", "example-app", stage); err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(filepath.Join(dir, "args")) //nolint:gosec // output from the synthetic CLI fixture
		if err != nil {
			t.Fatal(err)
		}
		want := "secrets\nimport\n--app\nexample-app\n"
		if stage {
			want += "--stage\n"
		}
		if string(args) != want || strings.Contains(string(args), "synthetic-identity") {
			t.Fatalf("unexpected arguments: %q", args)
		}
		input, err := os.ReadFile(filepath.Join(dir, "stdin")) //nolint:gosec // synthetic identity only
		if err != nil || string(input) != "ESEC_AGE_IDENTITY=synthetic-identity\n" {
			t.Fatal("identity was not passed exclusively on standard input")
		}
	}
}
