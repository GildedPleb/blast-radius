package cli

import (
	"encoding/json"
	"fmt"
)

// RunStop sends a HALT command to the running daemon for graceful shutdown.
func RunStop() {
	line, err := sendDaemonCommand("HALT")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found.")
		return
	}

	var resp map[string]any
	json.Unmarshal([]byte(line), &resp)

	if status, ok := resp["status"].(string); ok && status == "ok" {
		fmt.Println("Blast Radius daemon shutdown initiated.")
	} else {
		fmt.Println("Shutdown command sent.")
	}
}
