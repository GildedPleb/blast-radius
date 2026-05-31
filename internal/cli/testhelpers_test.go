package cli

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// resetTestOverrides installs safe test doubles for the CLI layer.
//
// CRITICAL FOR SANDBOXING:
//   - It ALWAYS creates a unique per-test Unix socket under t.TempDir().
//   - It resets all dangerous globals (home dir, exec, os.Exit, etc.).
//   - Never call real production functions that touch $HOME or fixed /tmp paths
//     without going through the overrides set here.
//
// Future contributors: if you add a new global or production function that
// can have side effects, make sure it is covered by this helper.
func resetTestOverrides(t testing.TB) {
	t.Helper()

	cfg := defaultTestConfig()

	// Force a unique per-test socket path (hard-coded SocketPath invariant is
	// overridden here for hermetic testing only, via the exported test seam).
	tempSocket := filepath.Join(t.TempDir(), "br.sock")
	configLoad = func() (*config.Config, string, error) {
		return &cfg, "", nil
	}
	config.SocketPathFn = func() string { return tempSocket }

	netDialTimeout = net.DialTimeout
	execCommand = exec.Command
	osReadFile = os.ReadFile
	osUserHomeDir = os.UserHomeDir
	osExecutable = os.Executable
	getDaemonLogPathFn = getDaemonLogPath
	sendDaemonCommandFn = realSendDaemonCommand
	osExit = func(code int) {}                          // silent no-op during tests
	readAuthTokenForSocket = realReadAuthTokenForSocket // reset to real (tests that need fake override it)
}

// mockSendDaemonCommand returns a sendDaemonCommandFn that always returns the given line.
func mockSendDaemonCommand(respLine string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		return respLine, nil
	}
}

// defaultTestConfig returns a minimal config for tests.
// Socket path is now a hard-coded invariant; tests override it via
// config.SocketPathFn in resetTestOverrides.
func defaultTestConfig() config.Config {
	return config.Config{}
}

// richDaemonResponse is a full response that exercises the new Pillar 1 collector_results,
// pillar1 section in status, rescan output, etc.
const richDaemonResponse = `{
	"status":"ok",
	"message":"Blast Radius daemon is running",
	"registry":{
		"tracked_hashes":142,
		"duplicate_hashes":3,
		"uptime":"1h2m3s",
		"scan_state":"completed"
	},
	"time":"2026-03-01T12:00:00Z",
	"pillar1":{
		"last_scan":"2026-03-01T11:55:00Z",
		"collector_results":{"env":142,"bitwarden":19}
	},
	"residue":{"count":2}
}`
