// Package executes Launchr application.
package main

import (
	"github.com/launchrctl/launchr"

	_ "github.com/launchrctl/keyring"
)

func main() {
	launchr.RunAndExit()
}
