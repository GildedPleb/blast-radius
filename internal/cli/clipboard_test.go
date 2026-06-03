package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
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
// checking path (instead of hashing the entire clipboard blob).
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

// TestRunClipboard_PbpasteFails hits the pbpaste error branch.
func TestRunClipboard_PbpasteFails(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("false") // will fail .Output()
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"check"})
	RunClipboard([]string{"status"})
}

// TestRunClipboard_Scrub_PbpasteFails hits the pbpaste error branch for the
// scrub/redact subcommand (exercises the logging we added for consistency
// with the check path in bug 4).
func TestRunClipboard_Scrub_PbpasteFails(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("false") // will fail .Output()
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"scrub"})
	RunClipboard([]string{"redact"})
}

// TestRunClipboard_CheckDaemonNotRunning hits the case where pbpaste succeeds
// and candidates are found, but connecting to the daemon fails.
func TestRunClipboard_CheckDaemonNotRunning(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("sh", "-c", `printf "AWS_SECRET=AKIAFAKEEXAMPLE1234567890\n"`)
		}
		return exec.Command("true")
	}

	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errForTest
	}

	RunClipboard([]string{"check"})
}

// TestRunClipboard_Clear exercises the clear subcommand path.
func TestRunClipboard_Clear(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbcopy" {
			return exec.Command("true")
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"clear"})
}

// TestRunClipboard_Unknown exercises the default/unknown subcommand help path.
func TestRunClipboard_Unknown(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunClipboard([]string{"foo"})
	RunClipboard([]string{"bar", "baz"})
}

// TestRunClipboard_CheckFullConnPath uses a real net.Pipe to exercise the
// low-level connection, AUTH (when token present), multiple CHECK_HASH writes,
// response reading, and both "known" and "not known" outcomes inside the loop.
func TestRunClipboard_CheckFullConnPath(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// pbpaste returns two plausible secrets
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("sh", "-c", `printf "DB_PASSWORD=supersecret123\nAPI_KEY=anothersecret456\nNORMAL=line\n"`)
		}
		return exec.Command("true")
	}

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	// Simulate the daemon side: consume AUTH + CHECK_HASH lines, reply with varying known status.
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		// Expect AUTH line (optional in some paths) then CHECK_HASH lines
		for i := 0; i < 5; i++ { // safety bound
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "AUTH ") {
				// consume, send nothing special
				continue
			}
			if strings.HasPrefix(line, "CHECK_HASH ") {
				resp := `{"status":"ok","known":false}`
				if i%2 == 0 {
					resp = `{"status":"ok","known":true}`
				}
				_, _ = fmt.Fprintf(serverConn, "%s\n", resp)
			}
		}
	}()

	RunClipboard([]string{"check"})
}

// TestRunClipboard_CheckWithCandidatesButAuthSkipped exercises the AUTH skip
// branch inside the low-level check path (when .auth file is unreadable).
func TestRunClipboard_CheckWithCandidatesButAuthSkipped(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return exec.Command("sh", "-c", `printf "DB_PASS=sekret\n"`)
		}
		return exec.Command("true")
	}

	// Point to a socket path whose .auth sibling does not exist
	bad := t.TempDir() + "/nosibling.sock"
	config.SocketPathFn = func() string { return bad }

	client, server := net.Pipe()
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return client, nil }

	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = server.Write([]byte(`{"status":"ok","known":false}` + "\n"))
		}
	}()

	RunClipboard([]string{"check"})
}

// TestRunClipboard_Scrub exercises the redact/scrub subcommand (story 2 primitive)
// using a real net.Pipe to drive the CHECK_HASH loop (like the check full-conn tests),
// plus a pbcopy override that captures what would be written to the pasteboard so we
// can assert the redaction actually happened (secrets replaced, non-secrets preserved,
// correct JSON report, placeholder from config).
func TestRunClipboard_Scrub(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	planted1 := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	planted2 := "ghp_1234567890abcdefABCDEF1234567890abcdef"
	nonSecret := "NORMAL=line"

	// Use a real pipe so the scrub path does the real AUTH + CHECK_HASH writes/reads
	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	// Simulate daemon: consume AUTH + two CHECK_HASH, reply known:true for both
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "AUTH ") {
				continue
			}
			if strings.HasPrefix(line, "CHECK_HASH ") {
				_, _ = fmt.Fprintf(serverConn, "%s\n", `{"status":"ok","known":true}`)
			}
		}
	}()

	// Capture what the scrub path writes to pbcopy (the redacted blob)
	var capturedStdin bytes.Buffer

	// Single definition of the realistic pbpaste provider (no dupe with earlier dead code).
	// This reduces copy-paste risk with other clipboard tests.
	pbpasteCmd := func() *exec.Cmd {
		return exec.Command("sh", "-c", fmt.Sprintf("printf 'DB_PASSWORD=%s\nAPI_TOKEN=%s\n%s\n'", planted1, planted2, nonSecret))
	}

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" {
			return pbpasteCmd()
		}
		if name == "pbcopy" {
			// Return a cmd whose Stdout we attach to our buffer. The caller will
			// set cmd.Stdin = the redacted content, then Run(). "sh -c cat" will
			// copy that Stdin to our captured buffer. Harmless and works with the
			// exact call pattern in the scrub code.
			cmd := exec.Command("sh", "-c", "cat")
			cmd.Stdout = &capturedStdin
			return cmd
		}
		return exec.Command("true")
	}

	// Provide a custom placeholder via configLoad (now under Pillar5 for clipboard)
	origConfigLoad := configLoad
	configLoad = func() (*config.Config, string, error) {
		c := &config.Config{}
		c.Pillar5.RedactPlaceholder = "[REDACTED-TEST]"
		return c, "/tmp/fake.yaml", nil
	}
	defer func() { configLoad = origConfigLoad }()

	// Run it
	RunClipboard([]string{"scrub"})

	// Assert: the written content had secrets replaced (but non-secret kept), and used our placeholder
	written := capturedStdin.String()
	if !strings.Contains(written, "[REDACTED-TEST]") {
		t.Errorf("scrub did not redact with expected placeholder; got: %q", written)
	}
	if strings.Contains(written, planted1) || strings.Contains(written, planted2) {
		t.Errorf("scrub left secret values in output: %q", written)
	}
	if !strings.Contains(written, nonSecret) {
		t.Errorf("scrub should have preserved non-secret content: %q", written)
	}

	// Also run "redact" alias (no extra asserts needed, path is same)
	RunClipboard([]string{"redact"})
}
