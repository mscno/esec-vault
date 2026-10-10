// Command esec-vault provides identity, backup, broker and team sharing for
// esec keyrings. It complements the esec CLI; all crypto primitives come from
// the esec library.
package main

import (
	"fmt"
	"runtime/debug"

	"github.com/mscno/esec-vault/internal/cli"
)

// These are set via ldflags by goreleaser for tagged releases.
var (
	version string
	commit  string
	date    string
)

func main() {
	cli.Execute(buildVersion())
}

// buildVersion prefers the release version injected at link time and falls
// back to the module version recorded by 'go install', so binaries installed
// from GitHub never report "dev". The daemon reports this string over the
// control socket, so an accurate value is what makes version comparison and
// the staleness warning meaningful.
func buildVersion() string {
	v := version
	if v == "" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
			v = info.Main.Version
		} else {
			v = "dev"
		}
	}
	if commit == "" || commit == "none" {
		commit = ""
	}
	if date == "" || date == "unknown" {
		date = ""
	}
	switch {
	case commit != "" && date != "":
		return fmt.Sprintf("%s (%s, %s)", v, commit, date)
	case commit != "":
		return fmt.Sprintf("%s (%s)", v, commit)
	default:
		return v
	}
}
