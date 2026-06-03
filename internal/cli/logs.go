package cli

import (
	"fmt"
	"os"

	"github.com/GildedPleb/blast-radius/internal/logging"
)

// RunLogs prints recent daemon log output.
func RunLogs() {
	logPath := getDaemonLogPathFn()

	data, err := osReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No daemon log file found yet.")
			fmt.Printf("Log location: %s\n", logPath)
			return
		}
		logging.Printf("RunLogs: failed to read log file: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to read log file: %v\n", err)
		osExit(1)
		return
	}

	fmt.Printf("=== Blast Radius Daemon Logs (%s) ===\n\n", logPath)
	fmt.Print(string(data))
	fmt.Println("\n=== End of log ===")
}
