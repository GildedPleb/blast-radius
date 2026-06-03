package cli

import (
	"fmt"
	"strings"
)

// RunDuplicates queries the daemon for duplicate secret hashes across projects (Pillar 1).
func RunDuplicates() {
	resp, raw, err := parseDaemonResponse("DUPLICATES")
	if err != nil {
		if raw != "" {
			fmt.Printf("Daemon produced bad response (protocol error?): %s\n", strings.TrimSpace(raw))
			return
		}
		fmt.Println(daemonNotRunningMsg)
		return
	}

	if status, ok := resp["status"].(string); ok && status != "ok" {
		fmt.Printf("Error: %v\n", resp["message"])
		return
	}

	total := 0
	if t, ok := resp["total"].(float64); ok {
		total = int(t)
	}

	fmt.Println("Blast Radius - Duplicate Secret Detection (Pillar 1)")
	fmt.Println("====================================================")
	if total == 0 {
		fmt.Println("No duplicate secrets detected across projects. Good!")
		fmt.Println("====================================================")
		return
	}

	fmt.Printf("Found %d secret hash(es) duplicated across multiple projects:\n\n", total)

	if dups, ok := resp["duplicates"].([]any); ok {
		for i, item := range dups {
			if m, ok := item.(map[string]any); ok {
				hash := m["hash"]
				projects := m["projects"]
				fmt.Printf("%d. Hash: %s\n", i+1, hash)
				fmt.Printf("   Appears in projects:\n")
				if projList, ok := projects.([]any); ok {
					for _, p := range projList {
						fmt.Printf("     - %s\n", p)
					}
				}
				fmt.Println()
			}
		}
	}
	fmt.Println("====================================================")
	fmt.Println("Recommendation: Review these projects and rotate the shared secrets if unintended.")
}
