package cli

import (
	"encoding/json"
	"fmt"
)

// Status JSON contract:
//
//   {"daemon": { ... full daemon STATUS or not_running sentinel ... }}
//
// This is the only top-level key. Zsh and other consumers should rely on this shape.
func RunStatus(jsonOutput bool) {
	// Collect daemon status (or not-running sentinel)
	daemonLine, daemonErr := sendDaemonCommand("STATUS")
	var daemonObj map[string]any
	if daemonErr == nil {
		_ = json.Unmarshal([]byte(daemonLine), &daemonObj)
	}

	if jsonOutput {
		out := map[string]any{
			"daemon": daemonOrNotRunning(daemonObj, daemonErr),
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return
	}

	// Human-readable output
	fmt.Println("Blast Radius Status")
	fmt.Println("===================")

	if daemonErr != nil {
		fmt.Println("Status:  Not running")
		fmt.Println()
		fmt.Println("The Blast Radius daemon is not currently running.")
		fmt.Println("Use 'blastradius start' to launch it.")
	} else {
		if status, ok := daemonObj["status"].(string); ok {
			fmt.Printf("Status:     %s\n", status)
		}
		if msg, ok := daemonObj["message"].(string); ok {
			fmt.Printf("Message:    %s\n", msg)
		}
		if reg, ok := daemonObj["registry"].(map[string]any); ok {
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
	}

	fmt.Println("===================")
	fmt.Println("No plaintext secrets or hashes are stored on disk (invariant upheld).")
}

// daemonOrNotRunning returns either the parsed daemon STATUS object or a
// minimal not_running sentinel for the unified JSON output.
func daemonOrNotRunning(obj map[string]any, err error) any {
	if err != nil || obj == nil {
		return map[string]any{
			"status":  "not_running",
			"message": "daemon not running",
		}
	}
	return obj
}
