// Package envrename plans exact environment filenames, never filename aliases.
package envrename

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
)

// Find searches configured filename patterns recursively, stopping at nested
// projects and skipping dependency directories and symlinks. Contents stay intact.
func Find(root, old, next string) ([][2]string, error) {
	cfg, err := config.LoadDir(root)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if dir != root {
			switch d.Name() {
			case ".git", ".esec", "node_modules", "vendor", ".venv":
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(dir, projectfile.ProjectFileName)); err == nil {
				return filepath.SkipDir
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		for _, pattern := range cfg.Files.Patterns {
			if !strings.Contains(pattern, "{env}") {
				continue
			}
			for _, format := range fileutils.ValidFormats() {
				a, err := config.Expand(pattern, old, string(format))
				if err != nil {
					return err
				}
				b, err := config.Expand(pattern, next, string(format))
				if err != nil {
					return err
				}
				from, to := filepath.Join(dir, a), filepath.Join(dir, b)
				if seen[from] {
					continue
				}
				info, err := os.Lstat(from)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("refusing nonregular environment file %s", from)
				}
				if _, err := os.Lstat(to); err == nil {
					return fmt.Errorf("destination exists: %s", to)
				} else if !os.IsNotExist(err) {
					return err
				}
				seen[from] = true
				out = append(out, [2]string{from, to})
			}
		}
		return nil
	})
	return out, err
}
