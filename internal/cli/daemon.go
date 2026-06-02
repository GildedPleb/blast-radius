package cli

import (
	"fmt"
	"os"

	"github.com/GildedPleb/blast-radius/internal/daemon"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// RunDaemon is the internal entrypoint for the background daemon process.
func RunDaemon() {
	_ = logging.Init(getDaemonLogPathFn())

	cfg, _, err := configLoad()
	if err != nil {
		logging.Printf("RunDaemon: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
	}

	reg := registry.New()
	d := daemon.New(cfg, reg)

	if err := d.Run(); err != nil {
		logging.Printf("RunDaemon: daemon failed: %v", err)
		fmt.Fprintf(os.Stderr, "Daemon failed: %v\n", err)
		osExit(1)
	}
}
