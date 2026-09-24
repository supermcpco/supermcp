package main

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// Somebody who runs this inside the released image gets "no such file or
// directory" and no idea why, because the catalogue they can see through
// the API is compiled in and the command reads a working tree.
func TestAMissingAdaptersRootSaysWhyThereIsNothingToRead(t *testing.T) {
	err := explainMissingRoot("adapters", fs.ErrNotExist)
	if err == nil {
		t.Fatal("a missing root produced no error")
	}
	for _, want := range []string{"adapters:", "compiled in", "checkout", "supermcp adapter validate path/to/adapters"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not mention %q:\n%s", want, err)
		}
	}

	// Anything else is passed through: a permission error is not a
	// missing directory, and saying so would send somebody the wrong way.
	denied := &os.PathError{Op: "open", Path: "adapters", Err: os.ErrPermission}
	if got := explainMissingRoot("adapters", denied); !errors.Is(got, os.ErrPermission) {
		t.Errorf("a permission error was rewritten as a missing directory: %v", got)
	}
}
