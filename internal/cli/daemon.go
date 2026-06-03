package cli

import (
	"fmt"
	"os"

	"github.com/GildedPleb/blast-radius/internal/daemon"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// RunDaemon is the internal entrypoint for the background daemon process.
//
// Error paths explicitly return after osExit(1) because osExit is a test seam
// (overridden to a no-op in tests; see cli.go var block and testhelpers_test.go).
// Without the return, a no-op would fall through to code that dereferences the
// (nil) *config.Config returned by the failing configLoad, causing a panic
// instead of clean test termination. The same pattern is used in RunStart etc.
func RunDaemon() {
	_ = logging.Init(getDaemonLogPathFn())

	cfg, _, err := configLoad()
	if err != nil {
		logging.Printf("RunDaemon: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
		return
	}

	reg := registry.New()
	d := daemon.New(cfg, reg)

	if err := d.Run(); err != nil {
		logging.Printf("RunDaemon: daemon failed: %v", err)
		fmt.Fprintf(os.Stderr, "Daemon failed: %v\n", err)
		osExit(1)
		return
	}
}
