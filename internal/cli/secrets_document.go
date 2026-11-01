package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/mscno/esec-vault/internal/broker"
	"github.com/mscno/esec-vault/internal/caller"
	"github.com/mscno/esec-vault/internal/paths"
	"github.com/mscno/esec-vault/internal/seal"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/storage"
)

// SecretsShowCmd opens a local file with the same key resolution as esec
// decrypt. Guarded environments still go through the broker's approval path.
type SecretsShowCmd struct {
	File    string `required:"" type:"existingfile" help:"The exact secrets file to open"`
	JSON    bool   `help:"Print JSON (the default for this command)"`
	Sock    string `env:"ESEC_VAULT_SOCK" help:"Broker socket path for guarded reads"`
	Session string `env:"ESEC_VAULT_SESSION" help:"Name shown in the approval dialog and audit log"`
}

type secretDocumentView struct {
	secretfile.Document

	File *secretfile.File `json:"file"`
}

// Run prints the in-memory document.
func (c *SecretsShowCmd) Run(_ *cliCtx) error {
	doc, err := c.document()
	if err != nil {
		return err
	}
	return printJSON(doc)
}

func (c *SecretsShowCmd) document() (*secretDocumentView, error) {
	path, err := filepath.Abs(c.File)
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := secretfile.Parse(path, data)
	if err != nil {
		return nil, errors.New("could not read this secrets file; check its format and public key")
	}
	if f.Project == "" {
		return nil, errors.New("no valid esec.toml above this file; check the project configuration")
	}
	guarded, err := documentIsGuarded(f)
	if err != nil {
		return nil, err
	}
	var doc *secretfile.Document
	if guarded {
		doc, err = c.brokerDocument(f)
	} else {
		doc, err = c.localDocument(f, data)
	}
	if err != nil {
		return nil, err
	}
	if doc.Revision != secretfile.Revision(data) {
		return nil, errors.New("the file changed while opening; open it again")
	}
	return &secretDocumentView{File: f, Document: *doc}, nil
}

func documentIsGuarded(f *secretfile.File) (bool, error) {
	pf, err := projectfile.Load(f.Root)
	if err != nil {
		return false, errors.New("could not read project guard settings; check esec.toml")
	}
	if seal.Guarded(pf.Env[f.Env].Guard) {
		return true, nil
	}
	recs, err := seal.LoadRecords(f.Root)
	if err != nil {
		return false, errors.New("could not read project seal records; check .esec/seals.toml")
	}
	if rec := recs[f.Env]; rec != nil && seal.Guarded(rec.Guard) {
		return true, nil
	}
	// A copied or renamed file must not turn a guarded key into a local read.
	for env, e := range pf.Env {
		if e.Key == f.PublicKey && seal.Guarded(e.Guard) {
			return false, fmt.Errorf("this file uses the guarded key for %s; open that environment's configured file", env)
		}
	}
	for env, rec := range recs {
		if rec != nil && rec.Key == f.PublicKey && seal.Guarded(rec.Guard) {
			return false, fmt.Errorf("this file uses the guarded key for %s; open that environment's configured file", env)
		}
	}
	return false, nil
}

func (c *SecretsShowCmd) localDocument(f *secretfile.File, data []byte) (*secretfile.Document, error) {
	var plain bytes.Buffer
	if _, err := esec.Decrypt(bytes.NewReader(data), &plain, f.Env, esec.FileFormat(f.Format), filepath.Dir(f.Path), ""); err != nil {
		if errors.Is(err, esec.ErrKeyNotFound) {
			return nil, fmt.Errorf("no local key for this file: %w", err)
		}
		return nil, errors.New("could not decrypt this file with the local key; check the keyring and encrypted file")
	}
	values, err := secretfile.DocumentValues(plain.Bytes(), fileutils.FileFormat(f.Format))
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureHome(); err != nil {
		return nil, err
	}
	audit, err := broker.NewAuditLogger(paths.AuditPath())
	if err != nil {
		return nil, fmt.Errorf("could not record local file read: %w", err)
	}
	if err := audit.Log(broker.AuditEntry{
		UID: uint32(os.Getuid()), PID: uint32(os.Getpid()), Op: broker.OpGetSecrets, //nolint:gosec // platform uid/pid fit the audit schema
		Project: f.Project, Env: f.Env, Decision: "allow", Detail: "local file, locally available key",
		Session: c.Session, Caller: caller.Describe(caller.Chain(os.Getpid())),
	}); err != nil {
		return nil, fmt.Errorf("could not record local file read: %w", err)
	}
	return &secretfile.Document{Revision: secretfile.Revision(data), Values: values}, nil
}

func (c *SecretsShowCmd) brokerDocument(f *secretfile.File) (*secretfile.Document, error) {
	sock := c.Sock
	if sock == "" {
		sock = paths.SocketPath()
	}
	client := broker.NewClient(sock)
	client.Timeout = 6 * time.Minute
	resp, err := client.Call(&broker.Request{Op: broker.OpGetSecrets, Project: f.Project, Env: f.Env, Path: f.Path, Format: f.Format, Session: c.Session, Document: true})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	if resp.Document == nil {
		return nil, errors.New("the background service needs updating; use Update Service in EsecVault’s Overview, then retry")
	}
	return resp.Document, nil
}

// SecretsUpdateCmd accepts a revision-checked value edit over stdin.
type SecretsUpdateCmd struct {
	File string `required:"" type:"existingfile" help:"The exact secrets file to update"`
}

type secretUpdate struct {
	Revision string  `json:"revision"`
	Key      string  `json:"key"`
	Value    *string `json:"value"`
	Create   bool    `json:"create"`
}

// Run encrypts and saves an edit, printing only its new revision.
func (c *SecretsUpdateCmd) Run(_ *cliCtx) error {
	// Never put the value in argv or include parser input in diagnostics.
	var update secretUpdate
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 10<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&update); err != nil {
		return errors.New("expected revision, key and value in JSON stdin")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON update")
	}
	revision, err := updateSecretDocument(c.File, update)
	if err != nil {
		return err
	}
	return printJSON(struct {
		Revision string `json:"revision"`
	}{revision})
}

func updateSecretDocument(path string, update secretUpdate) (string, error) {
	if len(update.Revision) != 64 || update.Key == "" || update.Value == nil {
		return "", errors.New("revision, key and value are required")
	}
	// Coordinate app windows and key rotations. Only ciphertext is written.
	unlock, err := storage.LockWait(paths.KeyringDir(), 10*time.Second, nil)
	if err != nil {
		return "", err
	}
	defer unlock()
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if secretfile.Revision(data) != update.Revision {
		return "", errors.New("this file changed on disk; reload it before saving your edit")
	}
	f, err := secretfile.Parse(path, data)
	if err != nil {
		return "", errors.New("could not read this secrets file; nothing was saved")
	}
	if f.Root != "" && f.Env != "" {
		pf, err := projectfile.Load(f.Root)
		if err != nil {
			return "", errors.New("could not read project configuration; nothing was saved")
		}
		if want := pf.Env[f.Env].Key; want != "" && want != f.PublicKey {
			return "", errors.New("the file uses an older environment key; re-encrypt it to the current key before editing")
		}
	}
	if err := validateSecretEdit(data, f, update); err != nil {
		return "", err
	}
	next, err := secretfile.Set(data, fileutils.FileFormat(f.Format), update.Key, *update.Value, update.Create)
	if err != nil {
		return "", errors.New("could not encrypt this value; check the key and file format (nothing was saved)")
	}
	// Detect edits made while encryption was running, including external editors.
	latest, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(latest, data) {
		return "", errors.New("this file changed on disk; reload it before saving your edit")
	}
	if err := storage.WriteKeepMode(path, next); err != nil {
		return "", fmt.Errorf("saving encrypted file: %w", err)
	}
	return secretfile.Revision(next), nil
}

func validateSecretEdit(data []byte, f *secretfile.File, update secretUpdate) error {
	values, err := secretfile.DocumentValues(data, fileutils.FileFormat(f.Format))
	if err != nil {
		return err
	}
	found := false
	for _, entry := range values {
		if entry.Key != update.Key {
			continue
		}
		found = true
		if update.Create {
			return errors.New("this key already exists; edit its value instead")
		}
		if !entry.Editable {
			return errors.New("this value is read-only in the editor")
		}
	}
	if !found {
		if !update.Create {
			return secretfile.ErrNotFound
		}
		if f.Format != string(fileutils.Env) && f.Format != string(fileutils.Eyaml) && f.Format != string(fileutils.Eyml) {
			return errors.New("adding keys is supported in dotenv and YAML files")
		}
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(update.Key) {
			return errors.New("use a key name starting with a letter, followed by letters, digits or underscores")
		}
	}
	return nil
}
