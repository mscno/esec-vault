package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// secretsTemplate builds a new file entirely in memory. Only ciphertext is
// written to disk, including when an example contains nonempty defaults.
func secretsTemplate(dir, format, env, pub string) (string, []byte, error) {
	cfg, err := config.LoadDir(dir)
	if err != nil {
		return "", nil, err
	}
	name, err := config.Expand(cfg.Files.Create, env, format)
	if err != nil {
		return "", nil, err
	}
	f, err := fileutils.ParseFormat(name)
	if err != nil || string(f) != format {
		return "", nil, fmt.Errorf("files.create must produce a filename identifying %s", format)
	}
	target := filepath.Join(dir, name)
	var sources []string
	seen := map[string]bool{}
	for _, pattern := range cfg.Files.Templates {
		n, err := config.Expand(pattern, env, format)
		if err != nil {
			return "", nil, err
		}
		p := filepath.Join(dir, n)
		if seen[p] {
			continue
		}
		seen[p] = true
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		if !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("template %s is not a regular file", p)
		}
		if filepath.Clean(p) == filepath.Clean(target) {
			return "", nil, errors.New("example template and destination must differ")
		}
		sources = append(sources, p)
	}
	sort.Strings(sources)
	if len(sources) > 1 {
		return "", nil, fmt.Errorf("ambiguous example templates: %s", strings.Join(sources, ", "))
	}
	plain, err := templateContent(format, env, pub)
	if err != nil {
		return "", nil, err
	}
	if len(sources) == 1 {
		data, err := os.ReadFile(sources[0])
		if err != nil {
			return "", nil, err
		}
		plain, err = populateTemplate(data, format, pub)
		if err != nil {
			return "", nil, fmt.Errorf("invalid example template %s: %w", sources[0], err)
		}
	}
	var encrypted bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader(plain), &encrypted, esec.FileFormat(format)); err != nil {
		return "", nil, fmt.Errorf("encrypt template: %w", err)
	}
	return target, encrypted.Bytes(), nil
}

func populateTemplate(data []byte, format, pub string) (string, error) {
	if format == ".env" {
		m, err := godotenv.Unmarshal(string(data))
		if err != nil {
			return "", errors.New("invalid dotenv syntax")
		}
		delete(m, "_ESEC_PUBLIC_KEY")
		m["ESEC_PUBLIC_KEY"] = pub
		// The esec dotenv transformer consumes literal values, not quoted
		// dotenv syntax. Reject multiline values rather than corrupt them.
		var b strings.Builder
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if crypto.IsBoxedMessage([]byte(m[k])) {
				return "", errors.New("templates must contain plaintext dummy defaults, not ciphertext from another key")
			}
			if strings.ContainsAny(k, "=\r\n\x00") || strings.ContainsAny(m[k], "\r\n\x00") || strings.TrimSpace(m[k]) != m[k] {
				return "", errors.New("dotenv template requires single-line values without surrounding whitespace; use TOML for other values")
			}
			fmt.Fprintf(&b, "%s=%s\n", k, m[k])
		}
		return b.String(), nil
	}
	var m map[string]any
	var err error
	switch format {
	case ".ejson":
		err = json.Unmarshal(data, &m)
	case ".etoml":
		err = toml.Unmarshal(data, &m)
	case ".eyaml", ".eyml":
		err = yaml.Unmarshal(data, &m)
	default:
		return "", errors.New("unsupported template format")
	}
	if err != nil || m == nil {
		return "", errors.New("expected a structured configuration document")
	}
	delete(m, "ESEC_PUBLIC_KEY")
	delete(m, "_ESEC_PUBLIC_KEY")
	if hasBoxedDefault(m) {
		return "", errors.New("templates must contain plaintext dummy defaults, not ciphertext from another key")
	}
	m["_ESEC_PUBLIC_KEY"] = pub
	var out []byte
	switch format {
	case ".ejson":
		out, err = json.MarshalIndent(m, "", "  ")
	case ".etoml":
		out, err = toml.Marshal(m)
	default:
		out, err = yaml.Marshal(m)
	}
	if err != nil {
		return "", errors.New("cannot encode example template")
	}
	return string(out), nil
}

func hasBoxedDefault(v any) bool {
	switch x := v.(type) {
	case string:
		return crypto.IsBoxedMessage([]byte(x))
	case map[string]any:
		for _, v := range x {
			if hasBoxedDefault(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if hasBoxedDefault(v) {
				return true
			}
		}
	}
	return false
}

func creationFormat(dir, explicit string) (string, error) {
	cfg, err := config.LoadDir(dir)
	if err != nil {
		return "", err
	}
	if explicit == "" {
		explicit = os.Getenv("ESEC_FORMAT")
	}
	if explicit == "" {
		explicit = cfg.DefaultFormat
	}
	f, err := fileutils.ParseFormat(explicit)
	return string(f), err
}

// writeNewTemplate refuses to replace any existing destination, including symlinks.
func writeNewTemplate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) //nolint:gosec // explicitly selected destination; O_EXCL refuses existing files and symlinks
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (c *EnvAddCmd) prepareTemplate(project, pub string) (string, []byte, error) {
	if !c.Template {
		return "", nil, nil
	}
	dir := c.Dir
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", nil, err
		}
		found, marker, err := projectfile.FindProjectFile(cwd)
		if err != nil && !errors.Is(err, projectfile.ErrNotFound) {
			return "", nil, err
		}
		if found != project {
			fmt.Fprintln(os.Stderr, "No matching project directory; creating the key only. Pass --dir to also create an encrypted secrets file.")
			return "", nil, nil
		}
		dir = filepath.Dir(marker)
	}
	format, err := creationFormat(dir, c.Format)
	if err != nil {
		return "", nil, err
	}
	if existing, _, err := fileutils.Resolve(dir, c.Env, format); err == nil {
		return "", nil, fmt.Errorf("secrets file %s already exists; import its key first", existing)
	} else if !errors.Is(err, fileutils.ErrNotFound) {
		return "", nil, err
	}
	file, content, err := secretsTemplate(dir, format, c.Env, pub)
	if err != nil {
		return "", nil, err
	}
	if _, err := os.Lstat(file); err == nil {
		return "", nil, fmt.Errorf("secrets file %s already exists", file)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	return file, content, nil
}
