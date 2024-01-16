package keyring

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// AskPass defines basic interface to retrieve passphrase.
type AskPass interface {
	GetPass() (string, error)
	NewPass() (string, error)
}

func withTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else { //nolint revive
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

// AskPassWithTerminal implements AskPass and uses tty to retrieve passphrase.
// @todo support pipe and stdin
type AskPassWithTerminal struct{}

// GetPass implements AskPass interface.
func (a AskPassWithTerminal) GetPass() (string, error) {
	return a.readPass("Enter passphrase to unlock the keyring: ")
}

// NewPass implements AskPass interface.
func (a AskPassWithTerminal) NewPass() (string, error) {
	pass1, err := a.readPass("Enter passphrase for a new keyring: ")
	if err != nil {
		return "", err
	}
	pass2, err := a.readPass("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass1 != pass2 {
		return "", errors.New("the passphrases don't match")
	}
	return pass1, nil
}

func (a AskPassWithTerminal) readPass(prompt string) (string, error) {
	var bytePassword []byte
	var err error
	err = withTerminal(func(in, out *os.File) error {
		fmt.Print(prompt)
		bytePassword, err = term.ReadPassword(int(in.Fd()))
		fmt.Println()
		return err
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

// AskPassConstFlow implements AskPass and returns constant.
type AskPassConstFlow string

// GetPass implements AskPass interface.
func (a AskPassConstFlow) GetPass() (string, error) { return string(a), nil }

// NewPass implements AskPass interface.
func (a AskPassConstFlow) NewPass() (string, error) { return string(a), nil }
