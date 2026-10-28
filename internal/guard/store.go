package guard

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	coreseal "github.com/mscno/esec/pkg/seal"
	"golang.org/x/term"

	"github.com/mscno/esec-vault/internal/notify"
)

// ErrDenied is returned when the person turned a guarded read down.
var ErrDenied = errors.New("the guarded read was denied")

// Presence asks the person before the hardware is used, and answers the
// hardware's own questions. The order matters: the dialog comes first, so
// a key that blinks with no dialog on screen is one not to touch.
type Presence struct {
	// Ask shows what a touch would allow; false denies.
	Ask func(title, text string) (bool, error)
	// Secret asks for a secret the hardware wants, such as a PIN.
	Secret func(prompt string) (string, error)
	// Note tells the person what the hardware waits for (a touch).
	Note func(message string)
}

// OpenSeal asks, then opens a seal with this machine's security keys among
// recipients (the seal's record of them). With only software stand-ins
// there is no hardware to protect and no dialog: whoever can read that file
// opens the seal without this program anyway.
func (p Presence) OpenSeal(data []byte, project, env, pub string, recipients []string, title, text string) (*coreseal.Payload, error) {
	ui := p.ui()
	ids, err := Identities(recipients, ui)
	if err != nil {
		return nil, err
	}
	if !softwareOnly(ids) {
		ok, err := p.Ask(title, text)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrDenied
		}
	}
	return Open(data, project, env, pub, ids...)
}

func softwareOnly(ids []age.Identity) bool {
	for _, id := range ids {
		if _, ok := id.(*age.X25519Identity); !ok {
			return false
		}
	}
	return len(ids) > 0
}

func (p Presence) ui() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(_, message string) error {
			p.Note(message)
			return nil
		},
		RequestValue: func(_, prompt string, _ bool) (string, error) {
			return p.Secret(prompt)
		},
		Confirm: func(_, prompt, yes, _ string) (bool, error) {
			return p.Ask("esec: security key", prompt+" ("+yes+")")
		},
		WaitTimer: func(string) {
			p.Note("touch your security key")
		},
	}
}

// DefaultPresence is the presence commands use; tests replace it.
var DefaultPresence = Desktop()

// Desktop asks in desktop dialogs, or on the terminal where there is no
// desktop. A terminal answer is weaker (a program driving the terminal can
// type it), but the hardware still needs its touch.
func Desktop() Presence {
	return Presence{
		Ask: func(title, text string) (bool, error) {
			ok, err := notify.Confirm(title, text, "Allow", 2*time.Minute)
			if !errors.Is(err, notify.ErrNoDialogs) {
				return ok, err
			}
			return ttyConfirm(title + "\n" + text)
		},
		Secret: func(prompt string) (string, error) {
			v, ok, err := notify.Secret("esec: security key", prompt, 2*time.Minute)
			if errors.Is(err, notify.ErrNoDialogs) {
				return ttySecret(prompt)
			}
			if err != nil {
				return "", err
			}
			if !ok {
				return "", ErrDenied
			}
			return v, nil
		},
		Note: func(message string) {
			fmt.Fprintln(os.Stderr, "esec: "+message)
			notify.Send("esec", message)
		},
	}
}

func ttyConfirm(text string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, errors.New("no dialog and no terminal to ask for the guarded read")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s\nAllow? [y/N] ", text)
	var answer string
	_, _ = fmt.Fscanln(tty, &answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y"), nil
}

func ttySecret(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no dialog and no terminal to ask for the security key's PIN")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s: ", prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return string(b), err
}
