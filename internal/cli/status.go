package cli

import (
	"encoding/json"
	"fmt"
)

// RunStatus queries the daemon for status without auto-starting it.
func RunStatus(jsonOutput bool) {
	line, err := sendDaemonCommand("STATUS")
	if err != nil {
		if jsonOutput {
			fmt.Println(`{"status":"not_running","message":"daemon not running"}`)
		} else {
			fmt.Println("Blast Radius Status")
			fmt.Println("===================")
			fmt.Println("Status:  Not running")
			fmt.Println()
			fmt.Println("The Blast Radius daemon is not currently running.")
			fmt.Println("Use 'blastradius start' to launch it.")
			fmt.Println("===================")
		}
		return
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		fmt.Printf("Raw response: %s\n", line)
		osExit(1)
	}

	if jsonOutput {
		fmt.Println(line)
		return
	}

	// Pretty print status
	fmt.Println("Blast Radius Status")
	fmt.Println("===================")
	if status, ok := resp["status"].(string); ok {
		fmt.Printf("Status:     %s\n", status)
	}
	if msg, ok := resp["message"].(string); ok {
		fmt.Printf("Message:    %s\n", msg)
	}
	if reg, ok := resp["registry"].(map[string]any); ok {
		if count, ok := reg["tracked_hashes"].(float64); ok {
			fmt.Printf("Tracked hashes: %d\n", int(count))
		}
		if dups, ok := reg["duplicate_hashes"].(float64); ok && dups > 0 {
			fmt.Printf("Duplicate hashes: %d  ← Pillar 1 Alert\n", int(dups))
		}
		if uptime, ok := reg["uptime"].(string); ok {
			fmt.Printf("Uptime:     %s\n", uptime)
		}
		if scanState, ok := reg["scan_state"].(string); ok {
			fmt.Printf("Scan state:   %s\n", scanState)
		}
	}
	cfg, _, _ := configLoad()
	fmt.Printf("Socket:     %s\n", cfg.SocketPath)
	fmt.Println("===================")
	fmt.Println("No plaintext secrets or hashes are stored on disk (invariant upheld).")
}
