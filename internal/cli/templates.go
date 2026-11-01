package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
)

// secretsTemplate creates only a public-key header. Example files are never read.
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
	content, err := templateContent(format, pub)
	return filepath.Join(dir, name), []byte(content), err
}

func creationFormat(dir, explicit string) (string, error) {
	cfg, err := config.LoadDir(dir)
	if err != nil {
		return "", err
	}
	// esec.toml decides a project's format: every machine and agent must
	// name its files alike. A flag may only agree; ESEC_FORMAT from a shell
	// is a personal default and yields.
	if project := cfg.ProjectFormat; project != "" {
		if explicit != "" && strings.TrimPrefix(explicit, ".") != project {
			return "", fmt.Errorf("--format %s: this project's esec.toml uses %s files (files.format)", explicit, project)
		}
		explicit = project
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
