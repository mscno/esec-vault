package caller

import (
	"os"
	"strings"
	"testing"
)

func TestChainOfThisProcess(t *testing.T) {
	chain := Chain(os.Getpid())
	if len(chain) == 0 || !strings.HasPrefix(chain[0], "caller.test") && !strings.Contains(chain[0], "caller") {
		t.Fatalf("chain: %v", chain)
	}
	if d := Describe([]string{"esec", "claude", "zsh"}); d != "zsh ▸ claude ▸ esec" {
		t.Fatalf("describe: %s", d)
	}
	if Describe(nil) != "an unknown program" {
		t.Fatal("empty chain")
	}
}
