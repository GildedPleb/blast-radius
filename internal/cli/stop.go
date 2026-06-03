package cli

import "fmt"

// RunStop sends a HALT command to the running daemon for graceful shutdown.
func RunStop() {
	resp, _, _ := parseDaemonResponse("HALT") // best-effort; stop is fire-and-forget-ish

	if status, ok := resp["status"].(string); ok && status == "ok" {
		fmt.Println("Blast Radius daemon shutdown initiated.")
	} else {
		fmt.Println("Shutdown command sent.")
	}
}
