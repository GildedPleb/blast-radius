package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RunRescan triggers a manual Pillar 1 discovery refresh (on-demand rescan).
// This is the Phase 3 mechanism for keeping the registry fresh.
// Full fsnotify reactivity is permanently out of scope (security tradeoff).
func RunRescan(jsonOutput bool) {
	resp, raw, err := parseDaemonResponse("RESCAN")
	if err != nil {
		if raw != "" {
			fmt.Printf("Daemon produced bad response (protocol error?): %s\n", strings.TrimSpace(raw))
			return
		}
		fmt.Println(daemonNotRunningMsg)
		return
	}

	if jsonOutput {
		b, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(b))
		return
	}

	if status, ok := resp["status"].(string); ok && status != "ok" {
		msg := "unknown error"
		if m, ok := resp["message"].(string); ok {
			msg = m
		}
		fmt.Printf("Rescan error: %s\n", msg)
		return
	}

	fmt.Println("Blast Radius - Pillar 1 Manual Rescan")
	fmt.Println("======================================")
	fmt.Println("Discovery refresh complete.")

	if last, ok := resp["last_scan"].(string); ok && last != "" && last != "never" {
		if t, err := time.Parse(time.RFC3339, last); err == nil {
			fmt.Printf("Last scan: %s\n", t.Local().Format("2006-01-02 15:04:05"))
		}
	}

	if collectors, ok := resp["collector_results"].(map[string]any); ok && len(collectors) > 0 {
		fmt.Println("\nLogical sources contributed:")
		for name, count := range collectors {
			fmt.Printf("  • %s: %v hashes\n", name, count)
		}
	}

	if errs, ok := resp["errors"].([]any); ok && len(errs) > 0 {
		fmt.Println("\nWarnings:")
		for _, e := range errs {
			fmt.Printf("  ! %v\n", e)
		}
	}

	fmt.Println("======================================")
	fmt.Println("Use 'blastradius status' or 'blastradius duplicates' to see updated results.")
}
