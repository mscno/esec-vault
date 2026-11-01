package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/keystore"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/vaultfile"
	"github.com/mscno/esec-vault/internal/workspace"
	"github.com/mscno/esec/pkg/projectfile"
	coreseal "github.com/mscno/esec/pkg/seal"
	"golang.org/x/crypto/chacha20poly1305"
)

const maxArchiveFile = 4 << 20

func objectPath(id string) string { return filepath.Join(paths.Home(), "pending-objects", id) }
func digestBytes(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func safeArchivePath(path, kind string) bool {
	if !fs.ValidPath(path) || strings.Contains(path, "\\") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".git" || part == ".esec-keyring" {
			return false
		}
	}
	switch kind {
	case "config":
		return path == "esec.toml"
	case "seal":
		return strings.HasPrefix(path, ".esec/") && (strings.HasSuffix(path, ".age") || path == ".esec/seals.toml") && strings.Count(path, "/") == 1
	case "secrets":
		_, _, err := secretfile.EnvOf(path)
		return err == nil
	}
	return false
}

func readArchiveFile(root *os.Root, path string) ([]byte, error) {
	f, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveFile {
		return nil, errors.New("archive file is not regular or exceeds 4 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxArchiveFile+1))
	if len(b) > maxArchiveFile {
		return nil, errors.New("archive file grew beyond 4 MiB")
	}
	return b, err
}

func (a *Account) collectArtifacts(v *vaultfile.Vault) error {
	if a.State.Chain.Seq == 0 {
		return nil
	} // first-account commit precedes object-upload authorization
	r, err := workspace.Load()
	if err != nil {
		return err
	}
	for _, checkout := range r.Checkouts {
		status := workspace.Check(checkout)
		if status == workspace.StatusGone || status == workspace.StatusMoved {
			continue
		}
		if status != workspace.StatusOK {
			return fmt.Errorf("cannot back up invalid checkout %s", checkout.Path)
		}
		if err := a.collectCheckout(v, checkout); err != nil {
			return err
		}
	}
	return nil
}

func (a *Account) collectCheckout(v *vaultfile.Vault, c workspace.Checkout) error {
	root, err := os.OpenRoot(c.Path)
	if err != nil {
		return err
	}
	defer root.Close()
	files, err := checkoutFiles(root)
	if err != nil {
		return err
	}
	origin := digestBytes([]byte(a.State.DeviceID + "\x00" + c.Path))
	contents := map[string][]byte{}
	for path, kind := range files {
		if !safeArchivePath(path, kind) {
			return errors.New("invalid archive path")
		}
		data, err := readArchiveFile(root, path)
		if err != nil {
			return err
		}
		if kind == "secrets" {
			_, format, _ := secretfile.EnvOf(path)
			if _, err := esec.ExtractPublicKey(data, esec.FileFormat(format)); err != nil {
				return fmt.Errorf("cannot archive secret file without a valid public key: %s", path)
			}
			plain, err := secretfile.Plain(data, format)
			if err != nil || len(plain) != 0 {
				return fmt.Errorf("cannot archive unencrypted or invalid file %s", path)
			}
		}
		contents[path] = data
	}
	if err := validateGuardedArchive(v, root, c); err != nil {
		return err
	}
	// Detect files changing during capture (including config/seal rotations).
	for path, data := range contents {
		now, err := readArchiveFile(root, path)
		if err != nil || !bytes.Equal(data, now) {
			return errors.New("project changed while archiving; retry sync")
		}
	}
	nowFiles, err := checkoutFiles(root)
	if err != nil || !reflect.DeepEqual(files, nowFiles) {
		return errors.New("project file list changed while archiving; retry sync")
	}
	if err := checkMissingArchiveFiles(v, root, c.Project, origin, files); err != nil {
		return err
	}
	return a.recordCapture(v, c, origin, files, contents)
}

func (a *Account) recordCapture(v *vaultfile.Vault, c workspace.Checkout, origin string, files map[string]string, contents map[string][]byte) error {
	revisions := map[string]string{}
	for path, data := range contents {
		if err := a.archiveRevision(v, c.Project, origin, path, files[path], data); err != nil {
			return err
		}
		revisions[path] = fileRevision(c.Project, origin, path, data)
	}
	catalog := v.EnsureCatalog()
	var latest vaultfile.Capture
	var parent string
	for id, capture := range catalog.Captures {
		if capture.Project == c.Project && capture.Checkout == origin && capture.Sequence > latest.Sequence {
			latest, parent = capture, id
		}
	}
	if reflect.DeepEqual(revisions, latest.Files) {
		return nil
	}
	if len(catalog.Captures) >= 50000 {
		return errors.New("project revision catalog limit reached")
	}
	b, err := json.Marshal(revisions)
	if err != nil {
		return err
	}
	id := digestBytes(append([]byte(c.Project+"\x00"+origin+"\x00"+parent+"\x00"), b...))
	catalog.Captures[id] = vaultfile.Capture{Sequence: latest.Sequence + 1, Project: c.Project, Checkout: origin, Device: a.State.DeviceName, Label: filepath.Base(c.Path), Files: revisions, At: a.Now().UTC()}
	return nil
}

func checkoutFiles(root *os.Root) (map[string]string, error) {
	files := map[string]string{"esec.toml": "config"}
	if entries, err := root.Open(".esec"); err == nil {
		items, err := entries.ReadDir(-1)
		entries.Close()
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if strings.HasSuffix(item.Name(), ".age") || item.Name() == "seals.toml" {
				if !item.Type().IsRegular() {
					return nil, fmt.Errorf("archive seal is not a regular file: %s", item.Name())
				}
				files[".esec/"+item.Name()] = "seal"
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if _, _, formatErr := secretfile.EnvOf(path); formatErr == nil {
			if !d.Type().IsRegular() {
				return fmt.Errorf("archive secret path is not a regular file: %s", path)
			}
			files[path] = "secrets"
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv", ".esec-keyring":
				return fs.SkipDir
			}
			if path != "." {
				if _, err := root.Stat(path + "/esec.toml"); err == nil {
					return fs.SkipDir
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// An earlier file may be hidden by replacing an ancestor with a symlink or
// nested project. Treat only actual absence as deletion, never silent exclusion.
func checkMissingArchiveFiles(v *vaultfile.Vault, root *os.Root, project, origin string, files map[string]string) error {
	latest, _, err := selectCapture(v, project, origin)
	if err != nil {
		return nil //nolint:nilerr // no earlier complete capture exists for this checkout
	} // no earlier complete capture for this checkout
	for path := range latest.Files {
		if _, ok := files[path]; ok {
			continue
		}
		_, err := root.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return fmt.Errorf("previously archived path is no longer eligible for backup: %s", path)
	}
	return nil
}

func fileRevision(project, origin, path string, data []byte) string {
	return digestBytes([]byte(project + "\x00" + origin + "\x00" + path + "\x00" + digestBytes(data)))
}

func validateGuardedArchive(v *vaultfile.Vault, root *os.Root, c workspace.Checkout) error {
	pf, err := projectfile.Load(c.Path)
	if err != nil {
		return err
	}
	records := seal.Records{}
	if b, err := readArchiveFile(root, ".esec/seals.toml"); err == nil {
		records, err = seal.ParseRecords(b)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for env, e := range pf.Env {
		rec := records[env]
		if !seal.Guarded(e.Guard) && (rec == nil || !seal.Guarded(rec.Guard)) {
			continue
		}
		// Repository bytes never authorize deletion of private keys. Only an
		// explicit successful guard operation may change the inventory guard.
		key := keyRecord(c.Project, e.Key)
		if _, known := v.EnsureCatalog().Guards[key]; !known {
			for name, value := range v.Projects[c.Project] {
				if strings.HasPrefix(name, "ESEC_PRIVATE_KEY") {
					if pub, err := keystore.PublicHex(value); err == nil && pub == e.Key {
						return fmt.Errorf("guarded environment %s %s still has a clear key; run guard enable explicitly before backup", c.Project, env)
					}
				}
			}
		}
		// This checks record consistency for archival, not signer authority
		// or possession of a usable recovery key. It has no deletion effects.
		b, err := readArchiveFile(root, ".esec/"+env+".age")
		if err != nil || rec == nil || len(rec.Recovery) == 0 || rec.Key != e.Key || rec.Verify(c.Project, env) != nil || coreseal.Hash(b) != rec.Sealed {
			return fmt.Errorf("guarded environment %s %s needs a valid recovery seal before server backup", c.Project, env)
		}
	}
	return nil
}

func (a *Account) archiveRevision(v *vaultfile.Vault, project, origin, path, kind string, data []byte) error {
	c := v.EnsureCatalog()
	digest := digestBytes(data)
	revision := fileRevision(project, origin, path, data)
	if _, ok := c.Artifacts[revision]; ok {
		return nil
	}
	if len(c.Artifacts) >= 50000 {
		return errors.New("file revision catalog limit reached")
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	blob := aead.Seal(nonce, nonce, data, []byte("esec-vault/file/v1\x00"+a.State.User))
	object := digestBytes(blob)
	if err := storage.Write(objectPath(object), blob); err != nil {
		return err
	}
	c.Artifacts[revision] = vaultfile.Artifact{Project: project, Checkout: origin, Path: path, Kind: kind, Digest: digest, Object: object, Key: key, Size: len(data), At: a.Now().UTC()}
	return nil
}

func (a *Account) uploadObjects(ctx context.Context, v, remote *vaultfile.Vault) error {
	if v.Catalog == nil {
		return nil
	}
	for rev, ref := range v.Catalog.Artifacts {
		if remote != nil && remote.Catalog != nil {
			if _, ok := remote.Catalog.Artifacts[rev]; ok {
				continue
			}
		}
		blob, err := os.ReadFile(objectPath(ref.Object))
		if err != nil {
			return fmt.Errorf("pending encrypted revision is missing: %w", err)
		}
		if digestBytes(blob) != ref.Object {
			return errors.New("pending encrypted revision digest mismatch")
		}
		if err := a.Client.PutVaultObject(ctx, ref.Object, blob); err != nil {
			return err
		}
	}
	return nil
}

func (a *Account) openArtifact(ctx context.Context, ref vaultfile.Artifact, objects map[string][]byte) ([]byte, error) {
	if !safeArchivePath(ref.Path, ref.Kind) || ref.Size < 0 || ref.Size > maxArchiveFile {
		return nil, errors.New("invalid archived file metadata")
	}
	blob, ok := objects[ref.Object]
	if !ok {
		if a.Client == nil {
			return nil, errors.New("recovery export is missing an encrypted file object")
		}
		var err error
		blob, err = a.Client.VaultObject(ctx, ref.Object)
		if err != nil {
			return nil, err
		}
	}
	if digestBytes(blob) != ref.Object {
		return nil, errors.New("archived ciphertext digest mismatch")
	}
	aead, err := chacha20poly1305.NewX(ref.Key)
	if err != nil {
		return nil, errors.New("invalid archived key")
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("truncated archived file")
	}
	plain, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], []byte("esec-vault/file/v1\x00"+a.State.User))
	if err != nil {
		return nil, errors.New("archived file authentication failed")
	}
	if len(plain) != ref.Size || digestBytes(plain) != ref.Digest {
		return nil, errors.New("archived file digest mismatch")
	}
	return plain, nil
}

// RestoreProject writes one checkout's latest revisions into a new directory.
// It authenticates all bytes first and never overwrites an existing target.
func (a *Account) RestoreProject(ctx context.Context, project, origin, dest string, revision ...string) error {
	v, err := a.ReadVault(ctx)
	if err != nil {
		return err
	}
	return a.restoreProject(ctx, v, project, origin, dest, revision...)
}

func (a *Account) restoreProject(ctx context.Context, v *vaultfile.Vault, project, origin, dest string, revision ...string) error {
	selected, origin, err := selectCapture(v, project, origin, revision...)
	if err != nil {
		return err
	}
	contents := map[string][]byte{}
	for path, id := range selected.Files {
		ref, ok := v.Catalog.Artifacts[id]
		if !ok || ref.Path != path || ref.Project != project || ref.Checkout != origin {
			return errors.New("invalid project revision reference")
		}
		b, err := a.openArtifact(ctx, ref, v.Objects)
		if err != nil {
			return err
		}
		contents[path] = b
	}
	parent, err := os.OpenRoot(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(dest)
	if name == "." || name == ".." {
		return errors.New("choose a new destination directory")
	}
	if err := parent.Mkdir(name, 0700); err != nil {
		return fmt.Errorf("restore requires a new destination: %w", err)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	for path, b := range contents {
		if err := root.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, werr := f.Write(b)
		if werr == nil {
			werr = f.Sync()
		}
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func selectCapture(v *vaultfile.Vault, project, origin string, revision ...string) (*vaultfile.Capture, string, error) {
	if v.Catalog == nil {
		return nil, "", errors.New("no project files have been archived")
	}
	origins := map[string]bool{}
	for _, ref := range v.Catalog.Captures {
		if ref.Project == project {
			origins[ref.Checkout] = true
		}
	}
	if origin == "" {
		if len(origins) != 1 {
			return nil, "", errors.New("choose a checkout from storage list --json before restoring")
		}
		for id := range origins {
			origin = id
		}
	}
	var selected vaultfile.Capture
	for id, capture := range v.Catalog.Captures {
		if capture.Project != project || capture.Checkout != origin {
			continue
		}
		if len(revision) > 0 && revision[0] != "" {
			if id == revision[0] {
				selected = capture
				break
			}
		} else if capture.Sequence > selected.Sequence {
			selected = capture
		}
	}
	if len(selected.Files) == 0 {
		return nil, "", errors.New("no complete project revision matches this selection")
	}
	return &selected, origin, nil
}
