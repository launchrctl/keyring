package test

import (
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/launchrctl/launchr"

	_ "github.com/launchrctl/keyring"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"launchr": launchr.RunAndExit,
	})
}

func TestKeyring(t *testing.T) {
	t.Parallel()
	testscript.Run(t, testscript.Params{
		Dir:      "testdata",
		Deadline: time.Now().Add(30 * time.Second),

		RequireExplicitExec: true,
		RequireUniqueNames:  true,
	})
}
