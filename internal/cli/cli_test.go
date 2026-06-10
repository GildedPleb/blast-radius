package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestCLI_PackageLoads(t *testing.T) {
	// Smoke test that the package and DI vars initialize
	_ = configLoad
	_ = netDialTimeout
}

func TestIsHelp(t *testing.T) {
	if !IsHelp("help") || !IsHelp("--help") || !IsHelp("-h") {
		t.Error("IsHelp should recognize help flags")
	}
	if IsHelp("status") || IsHelp("foo") {
		t.Error("IsHelp false positive")
	}
}

func TestRun_Dispatch(t *testing.T) {
	resetTestOverrides(t)
	defer resetTestOverrides(t)

	// --- Basic dispatch & error paths ---
	t.Run("unknown", func(t *testing.T) { Run([]string{"nonesuchcmd"}) })
	t.Run("empty-args", func(t *testing.T) { Run([]string{}) })
	t.Run("daemon-internal", func(t *testing.T) { Run([]string{"daemon"}) })

	t.Run("check-hash", func(t *testing.T) {
		Run([]string{"check-hash"})
		Run([]string{"check-hash", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
	})

	// --- Commands that need mocked daemon responses ---
	t.Run("status", func(t *testing.T) {
		sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","registry":{"tracked_hashes":0}}`)
		Run([]string{"status", "--json"})
		Run([]string{"status"})
	})

	t.Run("rescan", func(t *testing.T) {
		prev := sendDaemonCommandFn
		sendDaemonCommandFn = func(string) (string, error) { return "", fmt.Errorf("no daemon") }
		Run([]string{"rescan"})
		Run([]string{"rescan", "--json"})
		sendDaemonCommandFn = prev

		sendDaemonCommandFn = mockSendDaemonCommand(richDaemonResponse)
		Run([]string{"rescan"})
		Run([]string{"rescan", "--json"})
	})

	t.Run("duplicates-crumbs-status", func(t *testing.T) {
		sendDaemonCommandFn = mockSendDaemonCommand(richDaemonResponse)
		Run([]string{"duplicates"})
		Run([]string{"crumbs"})
		Run([]string{"crumbs", "--json"})
		Run([]string{"status"})
		Run([]string{"status", "--json"})
	})

	// --- Commands that were hitting ValidateReadiness early exit ---
	// We bypass validation here purely for dispatch coverage.
	t.Run("crumbs", func(t *testing.T) {
		defer bypassValidateReadiness(t)()
		Run([]string{"crumbs"})
		Run([]string{"crumbs", "--json"})
	})

	t.Run("scrub-history", func(t *testing.T) {
		defer bypassValidateReadiness(t)()
		Run([]string{"scrub-history"})
		Run([]string{"scrub_history"})
	})

	t.Run("validate-init", func(t *testing.T) {
		defer bypassValidateReadiness(t)()
		Run([]string{"validate"})
		Run([]string{"init"})
		Run([]string{"validate", "--reset"})
	})

	// --- Specific branch coverage (these are worth keeping detailed) ---
	t.Run("env", func(t *testing.T) {
		Run([]string{"env"})
		Run([]string{"env", "default-env"})
		Run([]string{"env", "nonexistent"})
		Run([]string{"env", "nonexistent-pillar"})
		Run([]string{"env", "foo", "bar"}) // unexpected args error path
		Run([]string{"env", "--json"})
		Run([]string{"env", "--json", "some-pillar"})
	})

	t.Run("env-unexpected-args", func(t *testing.T) {
		Run([]string{"env", "foo", "bar"})
	})

	t.Run("clipboard", func(t *testing.T) {
		execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }
		sendDaemonCommandFn = mockSendDaemonCommand(`{"known":false}`)
		Run([]string{"clipboard"})
		Run([]string{"clipboard", "check"})
		Run([]string{"clipboard", "clear"})
		Run([]string{"clipboard", "unknown"})
	})

	t.Run("start", func(t *testing.T) {
		tmpHome := t.TempDir()
		osUserHomeDir = func() (string, error) { return tmpHome, nil }
		osExecutable = func() (string, error) { return "/tmp/fake-br", nil }
		execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }
		getDaemonLogPathFn = func() string { return filepath.Join(tmpHome, "daemon.log") }
		Run([]string{"start"})
	})

	t.Run("start-errors", func(t *testing.T) {
		osExecutable = func() (string, error) { return "", errForTest }
		Run([]string{"start"})

		osExecutable = func() (string, error) { return "/tmp/fake-br", nil }
		getDaemonLogPathFn = func() string { return "/nonexistent/deep/dir/daemon.log" }
		Run([]string{"start"})
	})

	t.Run("crumbs-extra", func(t *testing.T) {
		sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":0}`)
		Run([]string{"crumbs"})
		Run([]string{"crumbs", "--json"})
		sendDaemonCommandFn = mockSendDaemonCommand(`not json`)
		Run([]string{"crumbs"})
	})

	// --- First-touch + ValidateReadiness error paths ---
	t.Run("first-touch-created", func(t *testing.T) {
		prev := ensureConfig
		ensureConfig = func() (string, bool, error) { return "/tmp/br-created.toml", true, nil }
		Run([]string{"status"})
		ensureConfig = prev
	})

	t.Run("validate-readiness-fails", func(t *testing.T) {
		prev := validateReadiness
		validateReadiness = func(string, *config.Config) error {
			return fmt.Errorf("readiness check failed for testing")
		}
		Run([]string{"status"})
		validateReadiness = prev
	})

	t.Run("logs-config-printhelp", func(t *testing.T) {
		Run([]string{"logs"})
		Run([]string{"config"})
		Run([]string{"config", "foo"})
		PrintHelp()
	})

	t.Run("stop-halt", func(t *testing.T) {
		defer bypassValidateReadiness(t)()
		Run([]string{"stop"})
		Run([]string{"halt"})
	})

	// --- New coverage: config load failure paths (the lerr != nil branch) ---
	t.Run("config-load-error-fatal-for-normal-commands", func(t *testing.T) {
		resetTestOverrides(t)
		defer resetTestOverrides(t)

		configLoad = func() (*config.Config, string, error) {
			return nil, "/home/user/.config/blastradius/config.yaml", errForTest
		}

		exitCalled := false
		osExit = func(code int) {
			exitCalled = true
			if code != 1 {
				t.Errorf("expected osExit(1), got %d", code)
			}
		}

		// Any normal command should hit the fatal path
		Run([]string{"status"})
		Run([]string{"crumbs"})
		Run([]string{"rescan"})

		if !exitCalled {
			t.Error("expected osExit(1) on config load error for normal commands")
		}
	})

	t.Run("config-load-error-allows-validate-reset-recovery", func(t *testing.T) {
		resetTestOverrides(t)
		defer resetTestOverrides(t)

		configLoad = func() (*config.Config, string, error) {
			return nil, "/home/user/.config/blastradius/config.yaml", errForTest
		}

		// This should NOT call osExit(1) — it should fall through to RunValidate
		// (which will print the warning and continue)
		Run([]string{"validate", "--reset"})
		Run([]string{"init", "--reset"})
	})

	t.Run("config-load-error-still-fatal-on-validate-without-reset", func(t *testing.T) {
		resetTestOverrides(t)
		defer resetTestOverrides(t)

		configLoad = func() (*config.Config, string, error) {
			return nil, "/bad/config.yaml", errForTest
		}

		exitCalled := false
		osExit = func(code int) {
			exitCalled = true
		}

		Run([]string{"validate"})    // no --reset → should fatal
		Run([]string{"init", "foo"}) // no --reset → should fatal

		if !exitCalled {
			t.Error("expected osExit on validate/init without --reset when config is unreadable")
		}
	})
}

// TestRealSendDaemonCommand exercises the unmocked path using DI hooks and net.Pipe
// for deterministic fast coverage of config err, dial err, write/read paths.
func TestRealSendDaemonCommand(t *testing.T) {
	// Synchronous call so overrides are active for the duration of the test body.
	// Using defer would apply them only after the test completes.
	resetTestOverrides(t)

	// config load error path
	configLoad = func() (*config.Config, string, error) {
		return nil, "", errForTest
	}
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected error from configLoad")
	}

	// dial timeout/error path (fast fail mock)
	configLoad = func() (*config.Config, string, error) {
		c := defaultTestConfig()
		return &c, "", nil
	}
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errForTest
	}
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected dial error")
	}

	// read error path via pipe: dial ok, write ok, but server closes without reply
	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	s.Close()
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected read error after server close")
	}

	// happy path: full roundtrip via pipe (now includes AUTH handshake)
	c, s = net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "testtoken123", nil }
	go func() {
		r := bufio.NewReader(s)
		// consume AUTH + the real command line
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = s.Write([]byte(`{"status":"ok","pong":true}` + "\n"))
		s.Close()
	}()
	resp, err := realSendDaemonCommand("PING")
	if err != nil {
		t.Fatalf("unexpected error on happy path: %v", err)
	}
	if !strings.Contains(resp, "pong") {
		t.Errorf("unexpected response: %q", resp)
	}

	// readAuthTokenForSocket error after successful dial (token file missing/unreadable)
	c, s = net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "", errForTest }
	go func() {
		// just drain whatever is written then close
		buf := make([]byte, 1024)
		for {
			if _, err := s.Read(buf); err != nil {
				return
			}
		}
	}()
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected error from readAuthTokenForSocket failure")
	}
	s.Close()

	// write failure after AUTH read succeeds
	c, s = net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "tok", nil }
	s.Close() // close immediately so first write (AUTH) fails
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected write error")
	}

	// cmd write failure *after* AUTH write succeeds (covers the second Write err block)
	c, s = net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "tok", nil }
	go func() {
		r := bufio.NewReader(s)
		// read the AUTH line (so client AUTH write succeeds)
		_, _ = r.ReadString('\n')
		// now close without reading the cmd line -> client's second Write will fail
		s.Close()
	}()
	if _, err := realSendDaemonCommand("PING"); err == nil {
		t.Error("expected cmd write error after AUTH")
	}
}

// TestRealReadAuthTokenForSocket exercises the real (non-overridden) impl directly
// to cover its success (trim) and error (ReadFile fail) paths (75% func).
func TestRealReadAuthTokenForSocket(t *testing.T) {
	defer resetTestOverrides(t)

	tmp := t.TempDir()
	sock := filepath.Join(tmp, "br.sock")
	auth := sock + ".auth"

	// success + trim
	if err := os.WriteFile(auth, []byte("  secret123  \n"), 0600); err != nil {
		t.Fatal(err)
	}
	tok, err := realReadAuthTokenForSocket(sock)
	if err != nil || tok != "secret123" {
		t.Errorf("realRead happy = %q, %v", tok, err)
	}

	// err path (no file)
	_ = os.Remove(auth)
	if _, err := realReadAuthTokenForSocket(sock); err == nil {
		t.Error("expected err for missing .auth")
	}
}
