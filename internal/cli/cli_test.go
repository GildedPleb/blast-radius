package cli

import (
	"bufio"
	"net"
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
	resetTestOverrides(t)       // apply test DI overrides (noop osExit etc) immediately
	defer resetTestOverrides(t) // ensure later tests also start from known state
	// Silence commented to avoid global stdout swap side-effects in this broad dispatch test.
	// (Other per-command tests use it safely.)
	// restore := silenceOutput()
	// defer restore()

	// Exercise dispatch branches via t.Run so we can see exactly which (if any) causes a test failure.
	t.Run("unknown", func(t *testing.T) { Run([]string{"nonesuchcmd"}) })
	t.Run("check-hash-missing", func(t *testing.T) { Run([]string{"check-hash"}) })
	t.Run("check-hash-ok", func(t *testing.T) {
		Run([]string{"check-hash", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
	})

	t.Run("status", func(t *testing.T) {
		sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","registry":{"tracked_hashes":0},"time":"2026-01-01T00:00:00Z"}`)
		Run([]string{"status", "--json"})
		Run([]string{"status"})
	})

	t.Run("duplicates-crumbs", func(t *testing.T) {
		sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok"}`)
		Run([]string{"duplicates"})
		Run([]string{"crumbs"})
		Run([]string{"crumbs", "--json"})
	})

	t.Run("scrub-stop", func(t *testing.T) {
		Run([]string{"scrub-history"})
		Run([]string{"stop"})
	})

	t.Run("printhelp", func(t *testing.T) { PrintHelp() })

	// Additional dispatch branches for coverage (use mocks to stay fast, no 2s dial timeouts, no real launches)
	t.Run("logs", func(t *testing.T) {
		Run([]string{"logs"})
	})

	t.Run("env", func(t *testing.T) {
		Run([]string{"env"})
		Run([]string{"env", "default-env"})
		Run([]string{"env", "nonexistent"})
	})

	t.Run("config", func(t *testing.T) {
		Run([]string{"config"})
		Run([]string{"config", "foo"})
	})

	t.Run("clipboard", func(t *testing.T) {
		execCommand = func(name string, arg ...string) *exec.Cmd {
			return exec.Command("true")
		}
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
		execCommand = func(name string, arg ...string) *exec.Cmd {
			return exec.Command("true")
		}
		getDaemonLogPathFn = func() string {
			return filepath.Join(tmpHome, "daemon.log")
		}
		Run([]string{"start"})
	})
}

// TestRealSendDaemonCommand exercises the unmocked path using DI hooks and net.Pipe
// for deterministic fast coverage of config err, dial err, write/read paths.
func TestRealSendDaemonCommand(t *testing.T) {
	defer resetTestOverrides(t)

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
}
