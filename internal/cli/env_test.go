package cli

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestRunEnvCheck(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// config error path (wrap to recover post-osExit deref caused by no-op osExit in tests)
	configLoad = func() (*config.Config, string, error) { return nil, "", errForTest }
	func() {
		defer func() { recover() }()
		RunEnvCheck("")
	}()

	// reset to good config for remaining
	resetTestOverrides(t)

	// Make exec harmless for success case
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	// unknown pillar cmd (early return before dial/exec)
	RunEnvCheck("")
	RunEnvCheck("default-env")
	RunEnvCheck("nonexistent-pillar5-command")

	// valid pillar cmd + exec success + dial fail (override dial to be instant, no 2s timeout)
	cfgWithCmd := defaultTestConfig()
	cfgWithCmd.Pillar5Commands = []config.Pillar5Command{{Name: "default-env", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfgWithCmd, "/tmp/c", nil }
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }
	RunEnvCheck("default-env")

	// exec failure path
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("false") }
	RunEnvCheck("default-env")
}

// TestRunEnvCheck_HappyPath exercises the full secret-checking loop using net.Pipe.
// This covers candidate extraction via the unified detection package (instead of
// naive whole-line hashing), the CHECK_HASH protocol over a single connection,
// AUTH handshake, response parsing, and "secrets_found" counting with realistic
// KEY=val style output from commands like printenv.
func TestRunEnvCheck_HappyPath(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Setup a command that produces realistic printenv-style output.
	// The new detection logic should correctly extract the *values* after =.
	execCommand = func(name string, arg ...string) *exec.Cmd {
		// Use printf for portable multi-line output
		return exec.Command("sh", "-c", `printf "PATH=/usr/bin\nREAL_SECRET=secret_value_one\nANOTHER=secret_value_two\nNORMAL=normal_line\n"`)
	}

	cfg := defaultTestConfig()
	cfg.Pillar5Commands = []config.Pillar5Command{{Name: "default-env", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	// Use a pipe so we can simulate the daemon's CHECK_HASH responses
	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	// Server side: read CHECK_HASH commands and reply with varying "known" results.
	// With the new candidate extraction we expect more CHECK_HASH calls (one per
	// plausible secret value extracted from the realistic output).
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		knownCount := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "CHECK_HASH ") {
				continue
			}
			// Simple simulation: treat the first two CHECK_HASH as known for coverage
			knownCount++
			resp := `{"known":false}`
			if knownCount == 1 {
				resp = `{"known":true}`
			}
			_, _ = fmt.Fprintf(serverConn, "%s\n", resp)
		}
	}()

	// This should now exercise:
	// - realistic printenv-style KEY=val output
	// - proper candidate extraction (values after =, not whole lines)
	// - multiple CHECK_HASH calls over one authenticated connection
	// - reading responses
	// - counting known matches
	// - printing the final success JSON with secrets_found
	RunEnvCheck("default-env")
}

// TestRunEnvCheck_DirectExec verifies the hard security invariant:
// Runtime hygiene commands (Pillar 4 / `pillar5_commands` in config, historical name)
// are always executed via direct argv (never through "sh -c").
// This eliminates shell injection risk from user config.
func TestRunEnvCheck_DirectExec(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	calledWith := ""
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledWith = name
		if len(arg) > 0 {
			calledWith += " " + strings.Join(arg, " ")
		}
		return exec.Command("true") // harmless
	}

	cfg := defaultTestConfig()
	cfg.Pillar5Commands = []config.Pillar5Command{
		{Name: "direct-echo", Cmd: "echo hello world"},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }

	RunEnvCheck("direct-echo")

	if !strings.HasPrefix(calledWith, "echo ") {
		t.Errorf("expected direct exec of 'echo ...', got %q (shell injection risk)", calledWith)
	}
	if strings.Contains(calledWith, "sh -c") {
		t.Error("shell was incorrectly used for a runtime hygiene command (Pillar 4)")
	}
}

// TestRunEnvCheck_NoCandidates exercises the path where the command succeeds
// but the detector extracts zero candidates (early return with secrets_found:0).
func TestRunEnvCheck_NoCandidates(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("sh", "-c", `printf "PATH=/usr/bin\nHOME=/root\nNORMAL_LINE=foo\n"`)
	}

	cfg := defaultTestConfig()
	cfg.Pillar5Commands = []config.Pillar5Command{{Name: "no-secrets", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }

	RunEnvCheck("no-secrets")
}

// TestRunEnvCheck_AuthReadFailure still proceeds with CHECK_HASH even if
// the sibling .auth file cannot be read (the daemon will reject if strict).
func TestRunEnvCheck_AuthReadFailure(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("sh", "-c", `printf "REAL_SECRET=xyz123\n"`)
	}

	cfg := defaultTestConfig()
	cfg.Pillar5Commands = []config.Pillar5Command{{Name: "auth-fail", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	// Force read of .auth to fail by pointing socket to a dir without .auth file
	badSocketDir := t.TempDir() + "/noauth.sock"
	config.SocketPathFn = func() string { return badSocketDir }

	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			// Consume whatever is written (AUTH attempt will fail read on client side but we just drain)
			buf := make([]byte, 1024)
			for {
				if _, err := s.Read(buf); err != nil {
					return
				}
			}
		}()
		return c, nil
	}

	RunEnvCheck("auth-fail")
}
