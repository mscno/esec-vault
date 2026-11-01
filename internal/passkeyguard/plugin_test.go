package passkeyguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

func TestNativePasskeyAgePluginRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	prf := bytes.Repeat([]byte{42}, 32)
	c := fakeCredential(t, 4, prf)
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^TestNativePasskeyPluginProcess$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-passkey"), []byte(script), 0700); err != nil { //nolint:gosec // Executable plugin test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ESEC_TEST_NATIVE_PLUGIN", "1")
	r, err := plugin.NewRecipient(c.EncodeRecipient(), &plugin.ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("test secret")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, data, _ := plugin.ParseRecipient(c.EncodeRecipient())
	id, err := plugin.NewIdentity(plugin.EncodeIdentity("passkey", data), &plugin.ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := age.Decrypt(bytes.NewReader(out.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(opened)
	if err != nil || string(got) != "test secret" {
		t.Fatalf("plugin output: %q %v", got, err)
	}
	t.Setenv("ESEC_TEST_NATIVE_CANCEL", "1")
	if _, err := age.Decrypt(bytes.NewReader(out.Bytes()), id); err == nil {
		t.Fatal("cancelled native sheet decrypted")
	}
}

func TestNativePasskeyPluginProcess(t *testing.T) {
	if os.Getenv("ESEC_TEST_NATIVE_PLUGIN") != "1" {
		return
	}
	Native = func(_ context.Context, request Request) (Response, error) {
		if os.Getenv("ESEC_TEST_NATIVE_CANCEL") == "1" {
			return Response{}, errors.New("cancelled")
		}
		if request.Operation != "assert" || len(request.Credentials) != 1 {
			return Response{}, errors.New("invalid native request")
		}
		return Response{CredentialID: request.Credentials[0].CredentialID, PRF: bytes.Repeat([]byte{42}, 32)}, nil
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		t.Fatal("missing plugin args")
	}
	os.Exit(RunPlugin(args[1:]))
}
