package cli

import (
	"errors"
	"os"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/projectfile"
	"golang.org/x/term"
)

// helpArgs turns "help [command...]" into "[command...] --help", and no
// arguments at all into "--help", so both show help instead of an error.
func helpArgs(args []string) []string {
	if len(args) == 0 {
		return []string{"--help"}
	}
	if args[0] == "help" {
		if len(args) == 2 && args[1] == "all" {
			showAllHelp = true
			return []string{"--help"}
		}
		return append(append([]string{}, args[1:]...), "--help")
	}
	return args
}

// unanswered is set when a question found no terminal and no answer on
// stdin, so the error that follows can say how to answer it.
var unanswered bool

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// noteUnanswered records a question that got no answer because stdin is not
// a terminal and had nothing to read.
func noteUnanswered(err error) {
	if err != nil && !stdinIsTerminal() {
		unanswered = true
	}
}

// hints says what to do about a failed command, for errors whose message
// cannot know it.
func hints(err error, node *kong.Node) []string {
	var out []string
	if errors.Is(err, projectfile.ErrNotFound) {
		out = append(out, "no "+projectfile.ProjectFileName+" in this directory or a parent: run this in the project's repository, or create one there with: esec vault project init ORG/REPO")
	}
	if unanswered {
		if flag := confirmFlag(node); flag != "" {
			out = append(out, "this asks a question and no terminal is attached to answer it; pass "+flag+" to go ahead without asking")
		} else {
			out = append(out, "this asks a question and no terminal is attached to answer it; run it in a terminal, or pipe the answer to stdin")
		}
	}
	return out
}

// confirmFlag names the selected command's flag that skips its questions.
func confirmFlag(node *kong.Node) string {
	if node == nil {
		return ""
	}
	for _, f := range node.Flags {
		if f.Name == "yes" || f.Name == "force" {
			return "--" + f.Name
		}
	}
	return ""
}
