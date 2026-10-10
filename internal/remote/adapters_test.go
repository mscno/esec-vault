package remote

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func exerciseBackend(t *testing.T, entry Entry) {
	t.Helper()
	b, err := New(entry)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "vaults/test file.esec"
	data := []byte{0, 1, 255, 10, 20}
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	got, err := b.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("corrupt roundtrip")
	}
	keys, err := b.List(ctx, "vaults/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("listing cannot feed Get: %v", keys)
	}
	if err := b.Delete(ctx, keys[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object: %v", err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
}

// objectStoreShim stands in for rclone against a store with no real
// directories (S3, R2, B2). There, reading a missing key succeeds and prints
// nothing instead of failing, so a backend that infers absence from the exit
// code alone silently reports "missing object" as "object with content".
const objectStoreShim = `#!/bin/sh
root="$FAKE_RCLONE_ROOT"
op="$1"
shift
target=""
for a in "$@"; do
	case "$a" in
	-*) ;;
	*) target="$a" ;;
	esac
done
rel="${target#*:}"
file="$root/$rel"
case "$op" in
rcat)
	mkdir -p "$(dirname "$file")"
	cat > "$file"
	;;
cat)
	[ -f "$file" ] && cat "$file"
	exit 0
	;;
lsjson)
	if [ -f "$file" ]; then
		printf '[{"Path":"%s","Name":"%s","Size":%s,"IsDir":false}]\n' "$rel" "$(basename "$rel")" "$(wc -c < "$file" | tr -d ' ')"
	else
		printf '[]\n'
	fi
	;;
lsf)
	if [ -d "$file" ]; then
		find "$file" -type f | sed "s|^$file/||"
	fi
	;;
deletefile)
	if [ -f "$file" ]; then
		rm -f "$file"
	else
		echo "object not found" >&2
		exit 4
	fi
	;;
*)
	exit 2
	;;
esac
`

func TestRcloneObjectStoreContract(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell to host the rclone shim")
	}
	bin := t.TempDir()
	shim := filepath.Join(bin, "rclone")
	if err := os.WriteFile(shim, []byte(objectStoreShim), 0o700); err != nil { //nolint:gosec // executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_RCLONE_ROOT", t.TempDir())
	exerciseBackend(t, Entry{Type: TypeRclone, RcloneRemote: "test", Bucket: "backups", Prefix: "nested/v2"})
}

// A missing key on a directory-less store reads back as empty content. The
// backend must report it as absent so pushes are not rejected as conflicting.
func TestRcloneObjectStoreMissingKeyIsNotFound(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell to host the rclone shim")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "rclone"), []byte(objectStoreShim), 0o700); err != nil { //nolint:gosec // executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_RCLONE_ROOT", t.TempDir())
	b, err := New(Entry{Type: TypeRclone, RcloneRemote: "test", Bucket: "backups", Prefix: "nested/v2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(context.Background(), "vaults/never-written.esec"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent key reported as %v, want ErrNotFound", err)
	}
}

func TestRcloneLocalAliasContract(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not installed")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "rclone.conf")
	if err := os.WriteFile(config, []byte("[test]\ntype = alias\nremote = "+dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RCLONE_CONFIG", config)
	exerciseBackend(t, Entry{Type: TypeRclone, RcloneRemote: "test", Bucket: "backups", Prefix: "nested/v2"})
}

func TestResticRepositoryContract(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	t.Setenv("RESTIC_PASSWORD", "test-only-password")
	repo := filepath.Join(t.TempDir(), "repository")
	if out, err := exec.Command("restic", "-r", repo, "init").CombinedOutput(); err != nil {
		t.Fatalf("init: %v: %s", err, out)
	}
	exerciseBackend(t, Entry{Type: TypeRestic, Repository: repo, Prefix: "nested/v2"})
}

func TestExecAdapterContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "adapter.py")
	fixture := `import json, pathlib, sys
root, op, key = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
p = root / key
if op == 'put':
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(sys.stdin.buffer.read())
elif op == 'get':
    if not p.exists(): sys.exit(44)
    sys.stdout.buffer.write(p.read_bytes())
elif op == 'delete':
    if not p.exists(): sys.exit(44)
    p.unlink()
elif op == 'list':
    print(json.dumps([str(x.relative_to(root)) for x in root.rglob('*') if x.is_file() and str(x.relative_to(root)).startswith(key)]))
else: sys.exit(2)
`
	if err := os.WriteFile(script, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	exerciseBackend(t, Entry{Type: TypeExec, Command: python, Args: []string{script, filepath.Join(dir, "objects")}, Prefix: "nested/v2"})
}

func TestFileBackendRejectsTraversal(t *testing.T) {
	b, err := New(Entry{Type: TypeFile, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"../escape", "/absolute", "a/../../escape", "a\\..\\escape"} {
		if err := b.Put(context.Background(), key, []byte("x")); err == nil {
			t.Fatalf("accepted %q", key)
		}
	}
}
