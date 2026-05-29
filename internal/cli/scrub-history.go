package cli

import (
	"encoding/json"
	"fmt"
)

// RunScrubHistory triggers history file scrubbing (Pillar 3).
func RunScrubHistory() {
	fmt.Println("Requesting history scrub (this may take a moment)...")

	line, err := sendDaemonCommand("SCRUB_HISTORY")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
	}

	var resp map[string]any
	json.Unmarshal([]byte(line), &resp)

	if status, ok := resp["status"].(string); ok && status == "ok" {
		if removed, ok := resp["lines_removed"].(float64); ok && removed > 0 {
			fmt.Printf("✓ Successfully scrubbed %d sensitive line(s) from history.\n", int(removed))
			if f, ok := resp["file"].(string); ok {
				fmt.Printf("  File: %s\n", f)
			}
		} else {
			fmt.Println("✓ History scrub complete. No sensitive entries were found.")
		}
	} else {
		msg := "unknown error"
		if m, ok := resp["message"].(string); ok {
			msg = m
		}
		fmt.Printf("Scrub failed: %s\n", msg)
	}
}
