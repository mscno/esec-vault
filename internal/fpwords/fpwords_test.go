package fpwords

import (
	"strings"
	"testing"
)

func TestWords(t *testing.T) {
	a := Words(AccountWords, DomainAccount, []byte("x"))
	if len(strings.Split(a, "-")) != AccountWords {
		t.Fatalf("word count: %s", a)
	}
	if a != Words(AccountWords, DomainAccount, []byte("x")) {
		t.Fatal("not deterministic")
	}
	if a == Words(AccountWords, DomainDevice, []byte("x")) {
		t.Fatal("domains must separate fingerprints")
	}
	if Words(4, DomainDevice, []byte("ab"), []byte("c")) == Words(4, DomainDevice, []byte("a"), []byte("bc")) {
		t.Fatal("part boundaries must matter")
	}
	if !strings.HasPrefix(a, Words(4, DomainAccount, []byte("x"))) {
		t.Fatal("shorter fingerprints must be prefixes of longer ones")
	}
}
