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

// Args is the command line of a process, for the dialog to tell one
// command of a program from another.
func TestArgsOfThisProcess(t *testing.T) {
	if a := Args(os.Getpid()); !strings.Contains(a, "-test.") {
		t.Fatalf("args: %q", a)
	}
	if Args(-1) != "" {
		t.Fatal("args of no process")
	}
}
