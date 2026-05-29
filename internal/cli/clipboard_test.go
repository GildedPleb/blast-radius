package cli

import (
	"os/exec"
	"testing"
)

func TestRunClipboard(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Override exec so pbpaste/pbcopy don't need to exist or succeed on this machine
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true") // harmless success
	}

	// These should at least execute the function bodies without crashing
	RunClipboard(nil)
	RunClipboard([]string{})
	RunClipboard([]string{"status"})
	RunClipboard([]string{"check"})
	RunClipboard([]string{"clear"})
	RunClipboard([]string{"unknown"})
}
