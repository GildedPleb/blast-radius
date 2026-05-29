package cli

import (
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestRunDaemon(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Force a quick failure path (bad socket) so we don't actually start a listener
	// but still execute the early parts of RunDaemon.
	cfg := defaultTestConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "cannot-create-this", "deep", "socket.sock") // will fail in daemon.Run

	configLoad = func() (*config.Config, string, error) {
		return &cfg, "", nil
	}

	// Should hit the error path and return without hanging
	RunDaemon()
}
