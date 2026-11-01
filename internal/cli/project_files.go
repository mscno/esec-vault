package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec-vault/internal/safetext"
	"github.com/mscno/esec-vault/internal/secretfile"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/format"
	"gopkg.in/yaml.v3"
)

// initFile keeps the exact original until the approved ciphertext is published.
// Only next (ciphertext or a public-key-only document) is ever written.
type initFile struct {
	path, format, publicKey string
	before, content, next   []byte
	info                    os.FileInfo
	encrypted, plain        bool
	normalized              bool
}

func inspectInitFile(dir, f, env string) (*initFile, error) {
	path, _, err := secretsTemplate(dir, f, env, "")
	if err != nil {
		return nil, err
	}
	if existing, _, err := fileutils.Resolve(dir, env, f); err == nil {
		path = existing
	} else if !errors.Is(err, fileutils.ErrNotFound) {
		return nil, err
	}
	p := &initFile{path: path, format: f}
	p.info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if !p.info.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets file %s must be a regular file, not a symlink", path)
	}
	p.before, err = os.ReadFile(path) //nolint:gosec // selected project file, checked regular above
	if err != nil {
		return nil, err
	}
	p.content = p.before
	if len(bytes.TrimSpace(p.before)) == 0 {
		return p, nil
	}
	if f == ".env" {
		p.content, p.normalized, err = initDotenv(p.before)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s as dotenv; check its syntax (nothing changed)", path)
		}
	}
	p.encrypted, err = secretfile.HasEncrypted(p.content, fileutils.FileFormat(f))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s as %s; check its syntax (nothing changed)", path, f)
	}
	// Inspect parsed values as well: quoted dotenv ciphertext is still ciphertext.
	values, err := secretfile.DocumentValues(p.content, fileutils.FileFormat(f))
	if err != nil {
		return nil, fmt.Errorf("cannot read values in %s (nothing changed)", path)
	}
	for _, value := range values {
		if strings.HasPrefix(value.Value, "ESEC[") {
			p.encrypted = true
		}
	}
	pub, err := esec.ExtractPublicKey(p.content, esec.FileFormat(f))
	switch {
	case err == nil:
		p.publicKey = hex.EncodeToString(pub[:])
	case errors.Is(err, format.ErrPublicKeyMissing):
		if p.encrypted {
			return nil, fmt.Errorf("%s contains encrypted values but has no ESEC public key; restore its original public-key header before initializing (nothing changed)", path)
		}
	default:
		return nil, fmt.Errorf("%s has invalid syntax or an invalid ESEC public key; fix it before initializing (nothing changed)", path)
	}
	plain, err := secretfile.Plain(p.content, fileutils.FileFormat(f))
	if err != nil {
		return nil, fmt.Errorf("cannot safely read values in %s; check its syntax (nothing changed)", path)
	}
	p.plain = len(plain) > 0
	return p, nil
}

func (p *initFile) prepare(c *ProjectInitCmd, env, pub string) error {
	if p.info == nil {
		content, err := templateContent(p.format, pub)
		p.next = []byte(content)
		return err
	}
	if p.publicKey != "" && p.publicKey != pub {
		state := "is plaintext but has a different public key"
		if p.encrypted {
			state = "contains values encrypted to a different public key"
		}
		return fmt.Errorf("%s %s from %s's key; import its matching key or explicitly re-encrypt it to the environment key before initializing (nothing changed)", p.path, state, env)
	}
	if !p.plain && p.publicKey != "" {
		return nil
	}
	data := p.content
	var err error
	if p.publicKey == "" {
		data, err = addInitPublicKey(data, p.format, pub)
		if err != nil {
			return fmt.Errorf("cannot add the public key to %s; check its syntax (nothing changed)", p.path)
		}
	}
	var out bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(data), &out, esec.FileFormat(p.format)); err != nil {
		return fmt.Errorf("cannot encrypt %s; check its syntax (nothing changed)", p.path)
	}
	actual, keyErr := esec.ExtractPublicKey(out.Bytes(), esec.FileFormat(p.format))
	if keyErr != nil || hex.EncodeToString(actual[:]) != pub {
		return fmt.Errorf("could not preserve the public key in %s (nothing changed)", p.path)
	}
	plain, err := secretfile.Plain(out.Bytes(), fileutils.FileFormat(p.format))
	if err != nil || len(plain) != 0 {
		return fmt.Errorf("could not fully encrypt %s (nothing changed)", p.path)
	}
	question := fmt.Sprintf("%s contains plaintext values. Encrypt them using %s's existing public key?", safetext.Clean(p.path), env)
	if p.publicKey == "" {
		question = fmt.Sprintf("%s is not encrypted and has no ESEC public key. Add %s's public key and encrypt this file in place?", safetext.Clean(p.path), env)
	} else if p.encrypted {
		question = fmt.Sprintf("%s contains both encrypted and plaintext values. Encrypt the remaining plaintext using %s's public key?", safetext.Clean(p.path), env)
	}
	if p.normalized {
		question = "Dotenv entries will be normalized to single lines; values are preserved, comments are removed. " + question
	}
	if !c.Yes && !confirm(question) {
		return errors.New("encryption cancelled; no project files or environment keys changed (use --yes to approve plaintext encryption in scripts)")
	}
	p.next = out.Bytes()
	return nil
}

func addInitPublicKey(data []byte, f, pub string) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		content, err := templateContent(f, pub)
		return []byte(content), err
	}
	switch f {
	case ".env":
		return append([]byte("ESEC_PUBLIC_KEY="+pub+"\n"), data...), nil
	case ".etoml":
		return append([]byte("ESEC_PUBLIC_KEY = \""+pub+"\"\n"), data...), nil
	case ".ejson":
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		if doc == nil {
			return nil, errors.New("expected an object")
		}
		doc[format.UnderscoredPublicKeyField] = json.RawMessage(`"` + pub + `"`)
		return json.MarshalIndent(doc, "", "  ")
	case ".eyaml", ".eyml":
		var doc yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&doc); err != nil {
			return nil, err
		}
		if err := decoder.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
			return nil, errors.New("expected one YAML document")
		}
		if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
			return nil, errors.New("expected a mapping")
		}
		root := doc.Content[0]
		root.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: format.UnderscoredPublicKeyField}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: pub}}, root.Content...)
		return yaml.Marshal(&doc)
	}
	return nil, errors.New("unsupported format")
}

func checkInitFiles(files []*initFile) error {
	for _, p := range files {
		if err := p.check(); err != nil {
			return err
		}
	}
	return nil
}

func (p *initFile) check() error {
	info, err := os.Lstat(p.path)
	if p.info == nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.info == nil || !info.Mode().IsRegular() || !os.SameFile(info, p.info) || info.Mode() != p.info.Mode() {
		return fmt.Errorf("%s changed during initialization; retry without moving or editing it", p.path)
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, p.before) {
		return fmt.Errorf("%s changed during initialization; retry without editing it", p.path)
	}
	return nil
}

func (p *initFile) publish() error {
	if p.next == nil {
		return nil
	}
	if err := p.check(); err != nil {
		return err
	}
	if p.info == nil {
		return writeNewTemplate(p.path, p.next)
	}
	return storage.WriteKeepMode(p.path, p.next)
}

// initDotenv keeps ordinary dotenv formatting. Multiline and colon assignments
// are normalized before the line-based encryptor sees them, so no continuation
// can remain plaintext or accidentally become a separate key.
func initDotenv(data []byte) ([]byte, bool, error) {
	values, err := godotenv.Unmarshal(string(data))
	if err != nil {
		return nil, false, errors.New("invalid dotenv")
	}
	lines := strings.Split(string(data), "\n")
	normalize := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "export ") {
			lines[i] = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
		}
		parsed, err := godotenv.Unmarshal(line)
		if err != nil || !strings.Contains(line, "=") {
			normalize = true
		}
		for _, value := range parsed {
			if crypto.IsBoxedMessage([]byte(value)) && strings.ContainsAny(line, "\"'") {
				normalize = true
			}
		}
	}
	if !normalize {
		return []byte(strings.Join(lines, "\n")), false, nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`)
	var out strings.Builder
	for _, key := range keys {
		value := values[key]
		if key != format.PublicKeyField && key != format.UnderscoredPublicKeyField && !crypto.IsBoxedMessage([]byte(value)) {
			value = `"` + quote.Replace(value) + `"`
		}
		fmt.Fprintf(&out, "%s=%s\n", key, value)
	}
	return []byte(out.String()), true, nil
}
