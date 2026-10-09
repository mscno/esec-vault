package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backend stores opaque ciphertext. List returns logical keys, excluding the
// configured namespace; its output can be passed directly to Get or Delete.
type Backend interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
}

// ErrNotFound identifies absent objects.
var ErrNotFound = errors.New("object not found")

// ErrMissingTool identifies an unavailable external backend executable.
var ErrMissingTool = errors.New("required tool not found")

// New validates a destination and constructs its backend.
func New(e Entry) (Backend, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b Backend
	switch e.Type {
	case TypeFile:
		b = &fileBackend{root: filepath.Join(e.Dir, filepath.FromSlash(e.Prefix))}
	case TypeRclone:
		b = &rcloneBackend{base: e.RcloneRemote + ":" + path.Join(e.Bucket, e.Path, e.Prefix)}
	case TypeRestic:
		b = &resticBackend{repo: e.Repository, prefix: e.Prefix}
	case TypeExec:
		b = &execBackend{command: e.Command, args: e.Args, prefix: e.Prefix}
	default:
		return nil, fmt.Errorf("unknown backend %q", e.Type)
	}
	return checkedBackend{b}, nil
}

type checkedBackend struct{ backend Backend }

func (b checkedBackend) Put(ctx context.Context, key string, data []byte) error {
	if err := validKey(key, false); err != nil {
		return err
	}
	return b.backend.Put(ctx, key, data)
}
func (b checkedBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validKey(key, false); err != nil {
		return nil, err
	}
	return b.backend.Get(ctx, key)
}
func (b checkedBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if err := validKey(strings.TrimSuffix(prefix, "/"), true); err != nil {
		return nil, err
	}
	keys, err := b.backend.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := validKey(key, false); err != nil {
			return nil, err
		}
	}
	sort.Strings(keys)
	return keys, nil
}
func (b checkedBackend) Delete(ctx context.Context, key string) error {
	if err := validKey(key, false); err != nil {
		return err
	}
	return b.backend.Delete(ctx, key)
}

func validKey(key string, empty bool) error {
	if key == "" && empty {
		return nil
	}
	if !filepath.IsLocal(key) || path.Clean(key) != key || strings.ContainsAny(key, "\\\x00\r\n") || strings.HasPrefix(key, "-") {
		return fmt.Errorf("invalid object key %q", key)
	}
	return nil
}

func objectKey(prefix, name string) string { return path.Join(prefix, name) }

// GenerationName is timestamp-ordered and unique even across devices.
func GenerationName(ts time.Time, generation uint64, fingerprint string) string {
	return fmt.Sprintf("vaults/%s-gen%020d-%s.esec", ts.UTC().Format("20060102T150405.000000000Z"), generation, fingerprint)
}

type fileBackend struct{ root string }

func (b *fileBackend) Put(_ context.Context, key string, data []byte) error {
	if err := os.MkdirAll(b.root, 0700); err != nil {
		return err
	}
	r, err := os.OpenRoot(b.root)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.MkdirAll(filepath.Dir(key), 0700); err != nil {
		return err
	}
	tmp := key + "." + rand.Text() + ".tmp"
	defer func() { _ = r.Remove(tmp) }()
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return r.Rename(tmp, key)
}
func (b *fileBackend) Get(_ context.Context, key string) ([]byte, error) {
	r, err := os.OpenRoot(b.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := r.ReadFile(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return data, err
}
func (b *fileBackend) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(b.root, func(p string, d os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(b.root, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) && !strings.HasSuffix(key, ".tmp") {
			keys = append(keys, key)
		}
		return nil
	})
	return keys, err
}
func (b *fileBackend) Delete(_ context.Context, key string) error {
	r, err := os.OpenRoot(b.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	err = r.Remove(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type rcloneBackend struct{ base string }

func (b *rcloneBackend) Put(ctx context.Context, key string, data []byte) error {
	_, err := runTool(ctx, data, "rclone", "rcat", b.base+"/"+key)
	return err
}
func (b *rcloneBackend) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := runTool(ctx, nil, "rclone", "cat", b.base+"/"+key)
	var exit *exec.ExitError
	if errors.As(err, &exit) && (exit.ExitCode() == 3 || exit.ExitCode() == 4) {
		return nil, ErrNotFound
	}
	return out, err
}
func (b *rcloneBackend) List(ctx context.Context, prefix string) ([]string, error) {
	out, err := runTool(ctx, nil, "rclone", "lsf", "--recursive", "--files-only", b.base)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, k := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k != "" && strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
func (b *rcloneBackend) Delete(ctx context.Context, key string) error {
	_, err := runTool(ctx, nil, "rclone", "deletefile", b.base+"/"+key)
	var exit *exec.ExitError
	if errors.As(err, &exit) && (exit.ExitCode() == 3 || exit.ExitCode() == 4) {
		return nil
	}
	return err
}

type resticBackend struct{ repo, prefix string }
type resticSnapshot struct {
	ID   string   `json:"id"`
	Tags []string `json:"tags"`
}

func (b *resticBackend) Put(ctx context.Context, key string, data []byte) error {
	tag := "esec-key=" + hex.EncodeToString([]byte(objectKey(b.prefix, key)))
	_, err := runTool(ctx, data, "restic", "-r", b.repo, "backup", "--stdin", "--stdin-filename", "vault.esec", "--tag", "esec-vault", "--tag", tag)
	return err
}
func (b *resticBackend) Get(ctx context.Context, key string) ([]byte, error) {
	objects, err := b.objects(ctx)
	if err != nil {
		return nil, err
	}
	ids := objects[key]
	if len(ids) == 0 {
		return nil, ErrNotFound
	}
	return runTool(ctx, nil, "restic", "-r", b.repo, "dump", ids[len(ids)-1], "/vault.esec")
}
func (b *resticBackend) List(ctx context.Context, prefix string) ([]string, error) {
	objects, err := b.objects(ctx)
	if err != nil {
		return nil, err
	}
	var keys []string
	for key := range objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
func (b *resticBackend) Delete(ctx context.Context, key string) error {
	objects, err := b.objects(ctx)
	if err != nil {
		return err
	}
	for _, id := range objects[key] {
		if _, err := runTool(ctx, nil, "restic", "-r", b.repo, "forget", id); err != nil {
			return err
		}
	}
	return nil
}
func (b *resticBackend) objects(ctx context.Context) (map[string][]string, error) {
	out, err := runTool(ctx, nil, "restic", "-r", b.repo, "snapshots", "--tag", "esec-vault", "--json")
	if err != nil {
		return nil, err
	}
	var snaps []resticSnapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, err
	}
	objects := map[string][]string{}
	for _, s := range snaps {
		if _, err := hex.DecodeString(s.ID); err != nil || len(s.ID) != 64 {
			return nil, fmt.Errorf("invalid restic snapshot id")
		}
		for _, tag := range s.Tags {
			encoded, ok := strings.CutPrefix(tag, "esec-key=")
			if !ok {
				continue
			}
			key, err := hex.DecodeString(encoded)
			if err != nil {
				return nil, err
			}
			namespace := strings.Trim(b.prefix, "/")
			logical := string(key)
			if namespace != "" {
				var ok bool
				logical, ok = strings.CutPrefix(logical, namespace+"/")
				if !ok {
					continue
				}
			}
			objects[logical] = append(objects[logical], s.ID)
		}
	}
	return objects, nil
}

// Exec adapters receive operation and namespaced key as arguments. Put reads
// stdin; Get emits bytes; List emits a JSON string array. No shell is involved.
type execBackend struct {
	command string
	args    []string
	prefix  string
}

func (b *execBackend) Put(ctx context.Context, key string, data []byte) error {
	_, err := b.run(ctx, "put", key, data)
	return err
}
func (b *execBackend) Get(ctx context.Context, key string) ([]byte, error) {
	return b.run(ctx, "get", key, nil)
}
func (b *execBackend) List(ctx context.Context, prefix string) ([]string, error) {
	out, err := b.run(ctx, "list", prefix, nil)
	if err != nil {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(out, &keys); err != nil {
		return nil, err
	}
	for i, key := range keys {
		if b.prefix != "" {
			var ok bool
			keys[i], ok = strings.CutPrefix(key, strings.Trim(b.prefix, "/")+"/")
			if !ok {
				return nil, fmt.Errorf("adapter returned key outside namespace")
			}
		}
	}
	return keys, nil
}
func (b *execBackend) Delete(ctx context.Context, key string) error {
	_, err := b.run(ctx, "delete", key, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
func (b *execBackend) run(ctx context.Context, op, key string, data []byte) ([]byte, error) {
	args := append([]string(nil), b.args...)
	args = append(args, op, objectKey(b.prefix, key))
	out, err := runTool(ctx, data, b.command, args...)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return nil, ErrNotFound
	}
	return out, err
}

func runTool(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingTool, name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func hashObject(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
