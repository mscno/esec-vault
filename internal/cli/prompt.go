package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readLine reads one line from stdin, trimmed.
func readLine() (string, error) {
	// Do not read ahead: a new buffered reader per prompt loses piped answers.
	var line []byte
	var b [1]byte
	for {
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(line), "\r"), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
	}
}

// promptLine asks a question and returns the trimmed answer.
func promptLine(question string) (string, error) {
	fmt.Fprint(os.Stderr, question)
	line, err := readLine()
	return strings.TrimSpace(line), err
}

// confirm prompts the user with a y/N question on the terminal.
func confirm(question string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", question)
	answer, err := readLine()
	if err != nil {
		return false
	}
	return strings.EqualFold(answer, "y")
}

// promptSecret reads a secret without echoing it. When stdin is not a
// terminal it falls back to a plain read, so the flow still works in scripts
// and CI.
func promptSecret(label string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, label)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	fmt.Fprint(os.Stderr, label)
	return readLine()
}

// promptPassphrase asks for a passphrase twice and requires a match. An empty
// passphrase is allowed but warned about, since the recovery phrase then
// becomes the only secret.
func promptPassphrase(what string) (string, error) {
	first, err := promptSecret(fmt.Sprintf("Passphrase %s (empty for none): ", what))
	if err != nil {
		return "", err
	}
	if first == "" {
		fmt.Println("No passphrase: your 24-word recovery phrase is the only thing protecting these keys.")
		return "", nil
	}
	second, err := promptSecret("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passphrases did not match")
	}
	return first, nil
}

// promptMnemonic asks for the recovery phrase and normalises whitespace so
// pasted text with odd spacing still matches.
func promptMnemonic(label string) (string, error) {
	entered, err := promptSecret(label)
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(strings.ToLower(entered)), " "), nil
}

// confirmMnemonic asks the user to re-enter a freshly generated phrase so it
// is actually written down.
func confirmMnemonic(mnemonic string) error {
	entered, err := promptMnemonic("Confirm you have written it down (re-enter the phrase): ")
	if err != nil {
		return err
	}
	if entered != mnemonic {
		return fmt.Errorf("recovery phrase did not match")
	}
	return nil
}
