package main

import (
	"os"
	"testing"
)

// silenceOutput redirects stdout/stderr to /dev/null for the duration of the test.
// This is a local copy of the helper from internal/cli because we cannot import
// unexported symbols from another package. It is only for test use.
func silenceOutput() (restore func()) {
	oldOut := os.Stdout
	oldErr := os.Stderr

	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull
	os.Stderr = devNull

	return func() {
		devNull.Close()
		os.Stdout = oldOut
		os.Stderr = oldErr
	}
}

func TestMain_HelpPaths(t *testing.T) {
	restore := silenceOutput()
	defer restore()

	// No args → help
	run([]string{"blastradius"})

	// Explicit help flags
	run([]string{"blastradius", "help"})
	run([]string{"blastradius", "--help"})
	run([]string{"blastradius", "-h"})

	// Short invocation
	run([]string{"blastradius", "status"})
}

func TestMain_NormalDispatch(t *testing.T) {
	// We run each command in its own subtest + fresh silence so one bad
	// command doesn't kill coverage of the others.
	commands := []string{
		"status",
		"duplicates",
		"check-hash",
		"config",
		// Note: "unknown command" path calls osExit(1) in cli.Run.
		// We avoid it here because we don't control osExit from this package.
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			restore := silenceOutput()
			defer restore()

			args := []string{"blastradius", cmd}
			if cmd == "check-hash" {
				args = append(args, "deadbeef")
			}
			if cmd == "status" {
				args = append(args, "--json")
			}
			run(args)
		})
	}
}

func TestMain_EmptyArgs(t *testing.T) {
	restore := silenceOutput()
	defer restore()

	run([]string{})           // extremely defensive
	run([]string{"blastradius"}) // same as no subcommand
}

// TestMain_ActualMain covers the real main() entrypoint (which delegates to run).
// We only exercise help paths to avoid osExit(1) side effects from unknown commands.
func TestMain_ActualMain(t *testing.T) {
	restore := silenceOutput()
	defer restore()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"blastradius", "--help"}
	main()

	os.Args = []string{"blastradius", "help"}
	main()

	os.Args = []string{"blastradius"}
	main()
}