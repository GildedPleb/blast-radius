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
	cfg.SocketPath = filepath.Join(t.TempDir(), "br.sock")

	configLoad = func() (*config.Config, string, error) {
		return &cfg, "", nil
	}
	netDialTimeout = net.DialTimeout
	execCommand = exec.Command
	osReadFile = os.ReadFile
	osUserHomeDir = os.UserHomeDir
	osExecutable = os.Executable
	getDaemonLogPathFn = getDaemonLogPath
	sendDaemonCommandFn = realSendDaemonCommand
	osExit = func(code int) {} // silent no-op during tests
}

// mockSendDaemonCommand returns a sendDaemonCommandFn that always returns the given line.
func mockSendDaemonCommand(respLine string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		return respLine, nil
	}
}

// defaultTestConfig returns a minimal config for tests.
// Note: SocketPath is intentionally left empty here. resetTestOverrides(t)
// always overrides it with a unique path under t.TempDir() for sandboxing.
func defaultTestConfig() config.Config {
	return config.Config{}
}
