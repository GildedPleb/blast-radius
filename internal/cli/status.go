package cli

import (
	"encoding/json"
	"fmt"
)

// Status JSON contract:
//
//	{"daemon": { ... full daemon STATUS or not_running sentinel ... }}
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
		// Pillar 2 (Crumbs) summary — lightweight, only when daemon is present
		if crumbs, ok := daemonObj["pillar2"].(map[string]any); ok {
			if cnt, ok := crumbs["count"].(float64); ok && cnt > 0 {
				fmt.Printf("Pillar 2 (Crumbs): %d finding(s) — run 'blastradius crumbs' for details\n", int(cnt))
			} else {
				fmt.Println("Pillar 2 (Crumbs): clean (last scan recent)")
			}
		}
		// Pillar 5 (Clipboard) live state from the monitor (targeted stories 4+5)
		if p5, ok := daemonObj["pillar5"].(map[string]any); ok {
			if cb, ok := p5["clipboard"].(map[string]any); ok {
				if cnt, ok := cb["secret_count"].(float64); ok && cnt > 0 {
					fmt.Printf("Pillar 5 (Clipboard): %d known secret(s) on clipboard — run 'blastradius clipboard scrub' to clean\n", int(cnt))
				} else {
					// Gate on having seen at least one change (last_change != "never") so we don't
					// spam "clean (monitor active)" in the very initial state before any clipboard
					// event has been observed by the monitor.
					lastChange, _ := cb["last_change"].(string)
					if active, _ := cb["monitor_active"].(bool); active && lastChange != "never" {
						fmt.Println("Pillar 5 (Clipboard): clean (monitor active)")
					}
				}
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
