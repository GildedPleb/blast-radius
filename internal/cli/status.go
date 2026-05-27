package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Status JSON contract (stable, frozen top-level keys — see CLI_REFACTOR_DESIGN.md)
//
// When daemon is not running:
//   {"daemon":{"status":"not_running","message":"..."},"protected":false,"recorder":null,"recorder_socket":"..."}
//
// When daemon running, protection inactive:
//   {"daemon":{...full STATUS...},"protected":false,"recorder":null,"recorder_socket":"..."}
//
// When protection active:
//   {"daemon":{...},"protected":true,"recorder":{ "active":true, "buffer":N, "current_raw_windows":M, ... },"recorder_socket":"..."}
//
// Zsh and other consumers must rely only on these top-level keys. Do not change
// them without updating the design doc and this comment first.
func RunStatus(jsonOutput bool) {
	cfg, _, _ := configLoad()
	recorderPath := getRecorderSocketPath()

	// Collect daemon status (or not-running sentinel)
	daemonLine, daemonErr := sendDaemonCommand("STATUS")
	var daemonObj map[string]any
	if daemonErr == nil {
		_ = json.Unmarshal([]byte(daemonLine), &daemonObj)
	}

	// Collect per-terminal protection state (cheap stat + optional recorder query)
	protected := false
	var recorderObj map[string]any
	if _, statErr := os.Stat(recorderPath); statErr == nil {
		protected = true
		if recLine, recErr := sendRecorderCommand("RECORDER_STATUS"); recErr == nil {
			var rec map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(recLine)), &rec) == nil {
				recorderObj = rec
			}
		}
	}

	if jsonOutput {
		// Always emit the stable unified shape (never raw concatenation hacks).
		out := map[string]any{
			"daemon":          daemonOrNotRunning(daemonObj, daemonErr),
			"protected":       protected,
			"recorder":        recorderObj, // may be nil
			"recorder_socket": recorderPath,
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return
	}

	// Human-readable path (preserves previous UX + adds protection visibility)
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

	fmt.Printf("Protected (this terminal): %v\n", protected)
	if cfg != nil {
		fmt.Printf("Socket:     %s\n", cfg.SocketPath)
	}

	if recorderObj != nil {
		if b, ok := recorderObj["buffer"].(float64); ok {
			fmt.Printf("Redaction buffer: %d (raw retention window)\n", int(b))
		}
		if raw, ok := recorderObj["current_raw_windows"].(float64); ok {
			fmt.Printf("Current raw windows: %d (plaintext secret lifetime bound)\n", int(raw))
		}
		if tot, ok := recorderObj["total_windows"].(float64); ok {
			fmt.Printf("Total history windows: %d\n", int(tot))
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
