package cli

import (
	"encoding/json"
	"fmt"
	"time"
)

// RunCrumbs queries the daemon for Pillar 2 residue (crumbs) findings.
func RunCrumbs(jsonOutput bool) {
	line, err := sendDaemonCommand("CRUMBS")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		fmt.Printf("Failed to parse response: %v\nRaw: %s\n", err, line)
		return
	}

	if jsonOutput {
		// pass through (or wrap minimally)
		b, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(b))
		return
	}

	if status, ok := resp["status"].(string); ok && status != "ok" && status != "partial" {
		msg := "unknown error"
		if m, ok := resp["message"].(string); ok {
			msg = m
		}
		fmt.Printf("Crumbs error: %s\n", msg)
		return
	}

	total := 0
	if t, ok := resp["total"].(float64); ok {
		total = int(t)
	}

	fmt.Println("Blast Radius - Forgotten Secret Crumbs (Pillar 2)")
	fmt.Println("==================================================")

	if total == 0 {
		fmt.Println("No suspicious secret residue found in configured high-risk directories.")
		fmt.Println("Good — keep exports inside your vault and .env files inside project roots.")
		fmt.Println("==================================================")
		return
	}

	fmt.Printf("Found %d suspicious file(s) with potential secrets:\n\n", total)

	if findings, ok := resp["findings"].([]any); ok {
		for i, item := range findings {
			if m, ok := item.(map[string]any); ok {
				loc := m["location"]
				fmt.Printf("%d. %s\n", i+1, loc)
				fmt.Printf("   Format: %v  |  Confidence: %v\n", m["format"], m["confidence"])
				fmt.Printf("   Known registry matches: %v   Entropy hits: %v   Size: %v bytes\n", m["known_matches"], m["entropy_hits"], m["size"])
				if lm, ok := m["last_mod"].(string); ok {
					if t, err := time.Parse(time.RFC3339, lm); err == nil {
						fmt.Printf("   Last modified: %s\n", t.Local().Format("2006-01-02 15:04"))
					}
				}
				fmt.Println("   → Recommendation: Review contents and securely delete or move into a vault.")
				fmt.Println()
			}
		}
	}

	examined := 0
	if e, ok := resp["files_examined"].(float64); ok {
		examined = int(e)
	}
	fmt.Printf("Scanned %d files across configured Pillar 2 surfaces.\n", examined)
	fmt.Println("==================================================")
	fmt.Println("All detection is advisory. No files are modified automatically.")
}
