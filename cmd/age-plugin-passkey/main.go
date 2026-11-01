// age-plugin-passkey delegates credential selection and verification to
// the signed Mac app's native AuthenticationServices system sheet.
package main

import (
	"os"

	"github.com/mscno/esec-vault/internal/passkeyguard"
)

func main() { os.Exit(passkeyguard.RunPlugin(os.Args[1:])) }
