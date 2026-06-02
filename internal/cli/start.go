package cli

import (
	"fmt"
	"os"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
)

// RunStart explicitly starts the daemon in the background.
func RunStart() {
	_ = logging.Init(getDaemonLogPathFn())

	_, configPath, err := configLoad()
	if err != nil {
		logging.Printf("RunStart: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
	}

	fmt.Printf("Starting Blast Radius daemon...\n")
	fmt.Printf("Config: %s\n", configPath)
	fmt.Printf("Socket: %s\n", config.SocketPath())

	if err := startDaemonInBackground(); err != nil {
		logging.Printf("RunStart: failed to start daemon: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		osExit(1)
	}

	logging.Println("RunStart: daemon start requested")
	fmt.Println("Daemon start requested. Use 'blastradius status' to verify.")
}
