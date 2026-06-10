package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon"
)

func TestRunEnvCheck(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// config error path (osExit(1) + explicit return; no recover needed, see osExit contract in cli.go)
	configLoad = func() (*config.Config, string, error) { return nil, "", errForTest }
	RunEnvCheck("")

	// reset to good config for remaining
	resetTestOverrides(t)

	// Make exec harmless for success case
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	// unknown pillar cmd (early return before dial/exec)
	RunEnvCheck("")
	RunEnvCheck("default-env")
	RunEnvCheck("nonexistent-pillar4-command")

	// valid pillar cmd + exec success + dial fail (override dial to be instant, no 2s timeout)
	cfgWithCmd := defaultTestConfig()
	cfgWithCmd.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "default-env", Cmd: "printenv"}},
	}
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
	cfg.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "default-env", Cmd: "printenv"}},
	}
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
// The Pillar 4 env primitive (commands under `pillar4.commands`) is always
// executed via direct argv (never through "sh -c").
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
	cfg.Pillar4 = config.Pillar4Config{
		Enabled: true,
		Commands: []config.RuntimeCommand{
			{Name: "direct-echo", Cmd: "echo hello world"},
		},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }

	RunEnvCheck("direct-echo")

	if !strings.Contains(calledWith, "echo") {
		t.Errorf("expected direct exec containing 'echo' (resolved or bare), got %q (shell injection risk)", calledWith)
	}
	if strings.Contains(calledWith, "sh -c") {
		t.Error("shell was incorrectly used for the Pillar 4 env primitive")
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
	cfg.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "no-secrets", Cmd: "printenv"}},
	}
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
	cfg.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "auth-fail", Cmd: "printenv"}},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	// Force read of .auth to fail by pointing socket to a dir without .auth file
	badSocketDir := t.TempDir() + "/noauth.sock"
	daemon.SocketPathFn = func() string { return badSocketDir }

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

// TestRunEnvCheck_CommandFailsButReportsCount exercises the path where the
// configured command fails (nonzero exit) but still produces output containing
// secrets. With the fix, candidates are extracted unconditionally, CHECK_HASH
// queries are performed (if daemon reachable), and the final JSON is an error
// that *includes* "secrets_found":N so callers see the exposure even for
// "failing" introspection commands.
func TestRunEnvCheck_CommandFailsButReportsCount(t *testing.T) {
	defer resetTestOverrides(t)

	// Use a failing exec that still emits realistic printenv-style output
	// containing a secret value. CombinedOutput will return non-nil runErr.
	// Use a value that does not trigger isCommonNoise (avoids "secret"/"password" etc.
	// substrings for len<20) so the detector actually produces a plausible candidate.
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("sh", "-c", `printf "PATH=/usr/bin\nREAL=superlonghighentropyvalueABCDEF1234567890\nNORMAL=normal\n"; exit 42`)
	}

	cfg := defaultTestConfig()
	cfg.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "fail-env", Cmd: "printenv"}},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	// Successful dial + pipe server that will reply to CHECK_HASH.
	// (Same pattern as HappyPath; because we use a temp socket path from
	// resetTestOverrides, the .auth read will fail and no AUTH line is sent,
	// so the server only needs to respond to CHECK_HASH lines.)
	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

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
			knownCount++
			resp := `{"known":false}`
			if knownCount == 1 {
				// The REAL_SECRET value should be the first plausible candidate
				// extracted by the detector from the failing command's output.
				resp = `{"known":true}`
			}
			_, _ = fmt.Fprintf(serverConn, "%s\n", resp)
		}
	}()

	// Capture stdout because this test wants to assert the *exact* error JSON
	// emitted by the runErr path (status=error + secrets_found in it).
	// We intentionally do not call silenceOutput() for this test (similar to
	// the dispatch tests in cli_test.go) so the fmt.Printf from RunEnvCheck
	// goes to our pipe instead of /dev/null.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	RunEnvCheck("fail-env")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	// The error path must have been taken (runErr was non-nil) and the count
	// from the successful CHECK must be included in the JSON.
	if !strings.Contains(out, `"status":"error"`) {
		t.Errorf("expected error status in output, got: %q", out)
	}
	if !strings.Contains(out, `"command failed: exit status 42"`) {
		t.Errorf("expected command failed message in output, got: %q", out)
	}
	if !strings.Contains(out, `"secrets_found":1`) {
		t.Errorf("expected secrets_found:1 in error JSON (the REAL_SECRET should have matched), got: %q", out)
	}

	// Also exercise the dispatch-level unexpected arg handling (nit #10 fix) using
	// active test overrides. The check is early in Run() before RunEnvCheck, so it
	// emits the clear error JSON and returns without side effects.
	{
		old := os.Stdout
		r2, w2, _ := os.Pipe()
		os.Stdout = w2
		Run([]string{"env", "--foo", "bar"})
		w2.Close()
		os.Stdout = old
		var b2 bytes.Buffer
		io.Copy(&b2, r2)
		out2 := b2.String()
		if !strings.Contains(out2, "unexpected arguments for env") {
			t.Errorf("expected 'unexpected arguments for env' error JSON from dispatch, got %q", out2)
		}
	}
}

// TestRunEnvCheck_MetacharWarning covers the shell-metacharacter heuristic warning
// (the logging.Printf path when cmd.Cmd contains ;|&`$(){}[]<>).
// Behavior is unchanged (we still exec directly); this is purely a warning to the
// operator that they should point at a wrapper script for real pipes/logic.
func TestRunEnvCheck_MetacharWarning(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	cfg := defaultTestConfig()
	cfg.Pillar4 = config.Pillar4Config{
		Enabled: true,
		Commands: []config.RuntimeCommand{
			{Name: "meta-pipe", Cmd: "echo foo | bar"}, // contains |
		},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }

	RunEnvCheck("meta-pipe")
}

// TestRunEnvCheck_EmptyCommand covers the early-return path when a pillar4
// command definition has an empty (or whitespace-only) Cmd field.
// strings.Fields yields len==0, we emit the specific error JSON and return
// before any exec or daemon dial.
func TestRunEnvCheck_EmptyCommand(t *testing.T) {
	defer resetTestOverrides(t)

	// Intentionally skip silenceOutput() so we can assert the exact JSON
	// (same pattern as TestRunEnvCheck_CommandFailsButReportsCount).
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cfg := defaultTestConfig()
	cfg.Pillar4 = config.Pillar4Config{
		Enabled:  true,
		Commands: []config.RuntimeCommand{{Name: "empty-cmd", Cmd: ""}},
	}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	RunEnvCheck("empty-cmd")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, `"status":"error"`) ||
		!strings.Contains(out, `"message":"empty command (pillar4 primitive)"`) {
		t.Errorf("expected empty command error JSON, got: %q", out)
	}
}
