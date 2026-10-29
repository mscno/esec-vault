package cli

import (
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/projectfile"
)

func TestRenameMarkerKeepsCommentsAndUnknownFields(t *testing.T) {
	raw := []byte("# keep this\nproject = 'acme/store'\n\n[env.\"eu.prod\"] # guarded environment\nkey = '" + strings.Repeat("ab", 32) + "'\nguard = 'touch'\nfuture_option = 'retain me'\n")
	pf, err := projectfile.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := renameMarker(raw, pf, "eu.prod", "eu.production")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), `[env."eu.production"] # guarded environment`) || !strings.Contains(string(updated), "future_option = 'retain me'") {
		t.Fatalf("metadata lost: %s", updated)
	}
	if !isMutation("env rename <old> <new>") {
		t.Fatal("rename does not lock keyring mutations")
	}
}
