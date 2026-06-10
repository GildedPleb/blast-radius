package cli

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon"
	"github.com/GildedPleb/blast-radius/internal/logging"
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
	daemon.SocketPathFn = func() string { return tempSocket }

	netDialTimeout = net.DialTimeout
	execCommand = exec.Command
	osReadFile = os.ReadFile
	osUserHomeDir = os.UserHomeDir
	osExecutable = os.Executable
	getDaemonLogPathFn = getDaemonLogPath
	sendDaemonCommandFn = realSendDaemonCommand
	runDaemon = func() {}
	osExit = func(code int) {}                          // silent no-op during tests
	readAuthTokenForSocket = realReadAuthTokenForSocket // reset to real (tests that need fake override it)

	// Prevent first-run template creation and readiness gates from touching the
	// real filesystem or interfering with the canned configLoad in tests.
	ensureConfig = func() (string, bool, error) { return "", false, nil }

	// Safe no-op for any test that exercises RunValidate(..., "--reset")
	removeConfigFile = func() error { return nil }

	// Also force the *real* daemon package's logging path (used inside d.Run())
	// to a per-test temp location. This is required for hermeticity of any test
	// that constructs a *daemon.Daemon and calls its Run() method.
	if daemon.GetDaemonLogPathFnForTesting != nil {
		tmpLog := filepath.Join(t.TempDir(), "daemon.log")
		*daemon.GetDaemonLogPathFnForTesting = func() string { return tmpLog }
	}

	// Isolate *cli* logging (Init calls from RunEnvCheck, RunClipboard, RunStart,
	// conn batch etc.) to a per-test temp file under this test's TempDir.
	// This ensures:
	//   - Logs for this test don't pollute other tests' files or the real $HOME log.
	//   - We redirect the global log.SetOutput away from any prior Init's fd (which
	//     may point to a now-deleted TempDir from a previous test after make clean / rebuild).
	//   - Failure logs (see scripts/coverage.sh) stay bounded and relevant per test.
	cliLog := filepath.Join(t.TempDir(), "cli.log")
	getDaemonLogPathFn = func() string { return cliLog }
	_ = logging.Init(cliLog) // best-effort redirect; dir exists via TempDir
}

// mockSendDaemonCommand returns a sendDaemonCommandFn that always returns the given line.
func mockSendDaemonCommand(respLine string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		return respLine, nil
	}
}

// defaultTestConfig returns a minimal config for tests.
// It populates a few fields so that code inspecting the cfg (e.g. new RunConfig
// summary) sees sensible values rather than pure zeros, while keeping
// Pillar4.Commands empty so that "env default-env" in broad dispatch tests
// still hits the "unknown pillar4 primitive command" error path (no exec side effects).
// Socket path is now a hard-coded invariant; tests override it via
// config.SocketPathFn in resetTestOverrides.
//
// Note: Pillar4.Enabled and Pillar5.Enabled are true here so that tests exercising
// the env primitive or clipboard commands do not trip the new pillar-level enabled
// validation (they can still override the whole configLoad when they need specific
// enabled=false cases).
func defaultTestConfig() config.Config {
	return config.Config{
		Pillar3: config.Pillar3Config{
			Enabled: false,
			Mode:    "redact",
		},
		Pillar4: config.Pillar4Config{
			Enabled: true,
			// Commands deliberately left empty for certain error-path tests
		},
		Pillar5: config.Pillar5Config{
			Enabled:                 true,
			MonitorEnabled:          false,
			AlertsEnabled:           false,
			RedactTimeoutSeconds:    30,
			FullClearTimeoutSeconds: 60,
		},
		// P2.Dirs left nil/empty (surfaces=0), P1 uses GetEnvOptions which tolerates zero.
	}
}

// bypassValidateReadiness temporarily makes ValidateReadiness always pass.
// Use this only for dispatch coverage tests. Real command tests should use
// proper config or the real ValidateReadiness behavior.
func bypassValidateReadiness(t *testing.T) func() {
	t.Helper()
	prev := validateReadiness
	validateReadiness = func(string, *config.Config) error { return nil }
	return func() { validateReadiness = prev }
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
	"pillar2":{"count":2},
	"pillar5":{"clipboard":{"secret_count":0,"last_change":"2026-03-01T11:55:00Z","redacted":false,"cleared":false,"monitor_active":true}}
}`
