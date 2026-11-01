package passkeyguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Input binds one allowed credential to its PRF salt.
type Input struct {
	CredentialID []byte `json:"credentialID"`
	Salt         []byte `json:"salt"`
}

// Request is sent to the signed app through a private pipe.
type Request struct {
	Operation   string  `json:"operation"`
	RPID        string  `json:"rpID"`
	Provider    string  `json:"provider,omitempty"`
	Name        string  `json:"name,omitempty"`
	UserID      []byte  `json:"userID,omitempty"`
	Salt        []byte  `json:"salt,omitempty"`
	Credentials []Input `json:"credentials,omitempty"`
}

// Response contains the selected credential and ephemeral encryption secret.
type Response struct {
	CredentialID []byte `json:"credentialID,omitempty"`
	PRF          []byte `json:"prf,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Native launches the signed app's system-sheet helper. PINs, biometrics
// and password-manager selection stay entirely in AuthenticationServices.
// Tests replace this function; callers never log a response's secret.
var Native = runNative

func appBinary() (string, error) {
	home, _ := os.UserHomeDir()
	candidates := []string{os.Getenv("ESEC_VAULT_APP_BIN")}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "EsecVault"))
	}
	candidates = append(candidates, filepath.Join(home, "Applications/EsecVault.app/Contents/MacOS/EsecVault"), "/Applications/EsecVault.app/Contents/MacOS/EsecVault", filepath.Join(home, "Applications/esec Vault.app/Contents/MacOS/EsecVault"))
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 { //nolint:gosec // Inspect an explicitly configured or conventional local app path.
			return path, nil
		}
	}
	return "", errors.New("install the signed EsecVault Mac app to use native passkeys")
}

func runNative(ctx context.Context, req Request) (Response, error) {
	var result Response
	if runtime.GOOS != "darwin" {
		return result, errors.New("native passkey unlocking currently requires macOS")
	}
	path, err := appBinary()
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--passkey-helper")
	cmd.Stdin = bytes.NewReader(data)
	// Bound output and suppress stderr: neither errors nor diagnostics may
	// accidentally include a PRF result from the native helper.
	var out bytes.Buffer
	defer func() { clear(out.Bytes()) }()
	cmd.Stdout = &limitedBuffer{buffer: &out, remaining: 8192}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("native passkey request: %w", ctx.Err())
		}
		return result, errors.New("native passkey helper failed; check the app's signing and associated domain")
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return Response{}, errors.New("invalid native passkey response")
	}
	if result.Error != "" {
		clear(result.PRF)
		return Response{}, errors.New(result.Error)
	}
	if len(result.PRF) != 32 || len(result.CredentialID) == 0 || len(result.CredentialID) > 1024 {
		clear(result.PRF)
		return Response{}, errors.New("the selected passkey does not support encryption (WebAuthn PRF)")
	}
	return result, nil
}

type limitedBuffer struct {
	buffer    *bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, errors.New("native response too large")
	}
	b.remaining -= len(data)
	return b.buffer.Write(data)
}
