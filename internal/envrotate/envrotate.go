// Package envrotate replaces an environment's key pair and re-encrypts every
// secrets file that uses it.
//
// Rotation is staged so a failure never leaves a file that no key opens:
// every file is re-encrypted into a temporary file and verified first, then
// the new key is sealed in the repository, and only then are the temporary
// files moved into place. The old key stays sealed in git history (and in
// this device's keyring cache), so files in git history still decrypt.
package envrotate

import (
	"bytes"

	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"

	"github.com/mscno/esec-vault/internal/keystore"
)

// maxFileSize skips files too large to be secrets files.
const maxFileSize = 10 << 20

// skipDirs are never searched.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true}

// Result describes a rotation.
type Result struct {
	OldPublic string
	NewPublic string
	Files     []string
	// Guarded is set when the environment's keys are guarded.
	Guarded bool
}

// EnvKey returns the keyring entry name of an environment.
func EnvKey(env string) string {
	return esec.EsecPrivateKey + "_" + strings.ToUpper(strings.ReplaceAll(env, ".", "_"))
}

func pubKeyEntry(pub string) string { return esec.EsecPrivateKey + "_" + strings.ToUpper(pub) }

// Find returns the secrets files under root whose public key is pub.
func Find(root string, pub [32]byte) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		format, ferr := fileutils.ParseFormat(d.Name())
		if ferr != nil {
			return nil //nolint:nilerr // not a secrets file name
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // files inside the project being rotated
		if err != nil {
			return err
		}
		got, kerr := esec.ExtractPublicKey(data, esec.FileFormat(format))
		if kerr != nil || got != pub {
			return nil //nolint:nilerr // no public key, or another key
		}
		out = append(out, path)
		return nil
	})
	sort.Strings(out)
	return out, err
}

type staged struct {
	path string
	tmp  string
}

// Options say how to get the old key and keep the new one.
type Options struct {
	// Old is the environment's current private key (hex), opened by the
	// caller: from this device's cache, or from its seal.
	Old string
	// Seal keeps the new key: it seals it in the repository for the
	// environment's readers. It runs before any file is encrypted to the
	// new key; when it fails, nothing changes.
	Seal func(newPriv string) error
	// Cache also files both keys in this device's keyring, for an
	// environment that is not guarded.
	Cache bool
}

// Rotate rotates env of project, re-encrypting matching files under root.
func Rotate(ks *keystore.Store, project, env, root string, opt Options) (*Result, error) {
	if opt.Old == "" || opt.Seal == nil {
		return nil, errors.New("rotation needs the old key and a way to seal the new one")
	}
	oldKey, err := parsePriv(opt.Old)
	if err != nil {
		return nil, err
	}
	oldPub, err := crypto.PublicFromPrivate(oldKey)
	if err != nil {
		return nil, err
	}
	files, err := Find(root, oldPub)
	if err != nil {
		return nil, err
	}
	newPubHex, newPrivHex, err := esec.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	oldPubHex := hex.EncodeToString(oldPub[:])
	var stagedFiles []staged
	cleanup := func() {
		for _, s := range stagedFiles {
			_ = os.Remove(s.tmp)
		}
	}
	for _, f := range files {
		tmp, err := reencrypt(f, opt.Old, oldPubHex, newPubHex, newPrivHex)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("%s: %w (nothing was changed)", f, err)
		}
		stagedFiles = append(stagedFiles, staged{path: f, tmp: tmp})
	}
	if err := opt.Seal(newPrivHex); err != nil {
		cleanup()
		return nil, fmt.Errorf("seal the new key: %w (nothing was changed)", err)
	}
	if opt.Cache {
		entries, err := ks.Read(project)
		if errors.Is(err, fs.ErrNotExist) {
			entries, err = map[string]string{}, nil
		}
		if err == nil {
			entries[EnvKey(env)] = newPrivHex
			entries[pubKeyEntry(newPubHex)] = newPrivHex
			entries[pubKeyEntry(oldPubHex)] = opt.Old
			err = ks.Write(project, entries, true)
		}
		if err != nil {
			// The seal holds the key; the cache is a convenience.
			fmt.Fprintln(os.Stderr, "! the new key is sealed, but this device's keyring was not updated:", err)
		}
	}
	var errs []error
	for _, s := range stagedFiles {
		if err := os.Rename(s.tmp, s.path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w (it still uses the old key, whose seal is in git history)", s.path, err))
		}
	}
	return &Result{OldPublic: oldPubHex, NewPublic: newPubHex, Files: files, Guarded: !opt.Cache}, errors.Join(errs...)
}

var hexKey = regexp.MustCompile(`(?i)[0-9a-f]{64}`)

// reencrypt decrypts path with the old key, swaps the public key, encrypts
// with the new one, verifies the result, and writes it to a temporary file
// beside path.
func reencrypt(path, oldPriv, oldPub, newPub, newPriv string) (string, error) {
	plain, err := esec.DecryptFile(path, "", oldPriv)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	count := 0
	replaced := hexKey.ReplaceAllFunc(plain, func(m []byte) []byte {
		if strings.EqualFold(string(m), oldPub) {
			count++
			return []byte(newPub)
		}
		return m
	})
	if count != 1 {
		return "", fmt.Errorf("expected the public key exactly once in the decrypted file, found it %d times", count)
	}
	format, err := fileutils.ParseFormat(filepath.Base(path))
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(replaced), &out, esec.FileFormat(format)); err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	gotPub, err := esec.ExtractPublicKey(out.Bytes(), esec.FileFormat(format))
	if err != nil || hex.EncodeToString(gotPub[:]) != newPub {
		return "", errors.New("re-encrypted file does not carry the new public key")
	}
	var check bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(out.Bytes()), &check, "", esec.FileFormat(format), "", newPriv); err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	if !bytes.Equal(check.Bytes(), replaced) {
		return "", errors.New("verify: re-encrypted file does not decrypt to the same content")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".esec-rotate-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if _, err := tmp.Write(out.Bytes()); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func parsePriv(s string) ([32]byte, error) {
	var k [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return k, errors.New("stored private key is malformed")
	}
	copy(k[:], raw)
	return k, nil
}
