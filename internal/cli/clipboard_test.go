package cli

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/registry"
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

// TestRunClipboard_CheckWithSecrets exercises the new candidate-based clipboard
// checking path (instead of hashing the entire blob).
func TestRunClipboard_CheckWithSecrets(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Simulate pbpaste returning content with a known secret inside a realistic wrapper
	planted := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'export AWS_SECRET=%s\nnormal text'", planted))
		}
		return exec.Command("true")
	}

	// Use a real registry with the secret
	reg := registry.New()
	reg.Add(registry.HashValue([]byte(planted)), "testproj")

	// Override sendDaemonCommandFn to simulate daemon responses for CHECK_HASH
	sendDaemonCommandFn = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "CHECK_HASH ") {
			hex := strings.TrimPrefix(cmd, "CHECK_HASH ")
			known := reg.IsKnownHashHex(hex)
			return fmt.Sprintf(`{"status":"ok","known":%t}`, known), nil
		}
		return `{"status":"ok"}`, nil
	}

	// Run the check path — this now exercises candidate extraction + multiple CHECK_HASH calls
	RunClipboard([]string{"check"})
}

// TestRunClipboard_CheckNoCandidates exercises the new early-return path
// when the detector finds nothing interesting in the clipboard.
func TestRunClipboard_CheckNoCandidates(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("sh", "-c", `printf "just normal text here\nno secrets"`)
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"check"})
}
