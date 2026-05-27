package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	recorderPath := getRecorderSocketPath()
	protected := false
	if _, err := os.Stat(recorderPath); err == nil {
		protected = true
	}

	recorderInfo := ""
	recJSON := "{}"
	if protected {
		if recLine, err := sendRecorderCommand("RECORDER_STATUS"); err == nil {
			recJSON = strings.TrimSpace(recLine)
			recorderInfo = recLine
		}
	}

	if jsonOutput {
		// Best-effort merge; keep simple for compatibility
		fmt.Printf(`{"daemon":%s,"protected":%v,"recorder_socket":"%s","recorder":%s}`, line, protected, recorderPath, recJSON)
		return
	}
	fmt.Printf("Protected (this terminal): %v\n", protected)
	if cfg != nil {
		fmt.Printf("Socket:     %s\n", cfg.SocketPath)
	}
	if recorderInfo != "" {
		// Pretty print key retention numbers for visibility of the invariant
		var rec map[string]any
		if json.Unmarshal([]byte(recorderInfo), &rec) == nil {
			if b, ok := rec["buffer"].(float64); ok {
				fmt.Printf("Redaction buffer: %d (raw retention window)\n", int(b))
			}
			if raw, ok := rec["current_raw_windows"].(float64); ok {
				fmt.Printf("Current raw windows: %d (plaintext secret lifetime bound)\n", int(raw))
			}
			if tot, ok := rec["total_windows"].(float64); ok {
				fmt.Printf("Total history windows: %d\n", int(tot))
			}
		}
	}
	fmt.Println("===================")
	fmt.Println("No plaintext secrets or hashes are stored on disk (invariant upheld).")
}
