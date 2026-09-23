// Command esec-vault provides identity, backup, broker and team sharing for
// esec keyrings. It complements the esec CLI; all crypto primitives come from
// the esec library.
package main

import "github.com/mscno/esec-vault/internal/cli"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.Execute(version + " (" + commit + ", " + date + ")")
}
