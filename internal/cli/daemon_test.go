package cli

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestRunDaemon(t *testing.T) {
	// Call synchronously (not via defer) so the hermetic overrides for sockets,
	// config, home, *and* daemon logging path are active during RunDaemon().
	// Using defer here would apply the resets only after the test body completes.
	resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Force a quick failure path (bad socket) via the test seam so we don't actually
	// start a listener but still execute the early parts of RunDaemon.
	// Use a path under / that cannot be mkdir'ed (prevents reaching the go discovery.RunInitial
	// launch inside d.Run, which could otherwise see a short-lived cfg and panic on nil m.cfg
	// in async goroutine after test returns).
	badPath := "/no-permission-blastradius-test-xyz123/deep/socket.sock"
	config.SocketPathFn = func() string { return badPath }

	cfg := defaultTestConfig()
	configLoad = func() (*config.Config, string, error) {
		return &cfg, "", nil
	}

	// Should hit the error path and return without hanging
	RunDaemon()
}

// TestRunDaemon_ConfigLoadError hits the early configLoad error branch in RunDaemon
// (was one of the 0-blocks for the 75% func).
func TestRunDaemon_ConfigLoadError(t *testing.T) {
	resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	configLoad = func() (*config.Config, string, error) {
		return nil, "", errForTest
	}

	// Should log, print to stderr (silenced), osExit(1) which is no-op'ed, and return.
	RunDaemon()
}
