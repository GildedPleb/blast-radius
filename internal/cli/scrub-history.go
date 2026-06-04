package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RunScrubHistory triggers history file scrubbing (Pillar 3) with support for
// --mode, --dry-run, --json, and --file overrides.
func RunScrubHistory(tail []string) {
	jsonOutput := false
	mode := ""
	dryRun := false
	filePath := ""
	full := false

	// Very small flag parser (no external deps; matches style of other commands).
	// Supports --file PATH (two-token form, allows spaces when user quotes the PATH to shell)
	// as well as --file=PATH. The builder always emits the normalized "file=VALUE" form
	// (last) to the daemon protocol so the handler can take the tail verbatim.
	// file= is the only value that reasonably contains spaces.
	for i := 0; i < len(tail); i++ {
		t := tail[i]
		switch {
		case t == "--json":
			jsonOutput = true
		case strings.HasPrefix(t, "--mode="):
			mode = strings.TrimPrefix(t, "--mode=")
		case t == "--mode" || t == "-m":
			// value form not supported for --mode; use --mode=delete|redact
		case t == "--dry-run" || t == "-n":
			dryRun = true
		case t == "--full" || t == "--reset":
			full = true
		case strings.HasPrefix(t, "--file="):
			filePath = strings.TrimPrefix(t, "--file=")
		case t == "--file" || t == "-f":
			if i+1 < len(tail) {
				filePath = tail[i+1]
				i++ // consume value token
			}
		}
	}

	var argParts []string
	if mode != "" {
		argParts = append(argParts, "mode="+mode)
	}
	if dryRun {
		argParts = append(argParts, "dry-run")
	}
	if full {
		argParts = append(argParts, "full")
	}
	if filePath != "" {
		argParts = append(argParts, "file="+filePath)
	}
	daemonCmd := "SCRUB_HISTORY"
	if len(argParts) > 0 {
		daemonCmd += " " + strings.Join(argParts, " ")
	}

	if !jsonOutput && !dryRun {
		fmt.Println("Requesting history scrub (this may take a moment)...")
	}

	resp, raw, err := parseDaemonResponse(daemonCmd)
	if err != nil {
		if raw != "" {
			// Live daemon but bad JSON payload.
			if jsonOutput {
				fmt.Printf(`{"status":"error","message":"bad daemon response","raw":%q}`+"\n", strings.TrimSpace(raw))
			} else {
				fmt.Printf("Daemon produced bad response (protocol error?): %s\n", strings.TrimSpace(raw))
			}
			return
		}
		if jsonOutput {
			fmt.Println(`{"status":"error","message":"no running daemon"}`)
		} else {
			fmt.Println(daemonNotRunningMsg)
		}
		return
	}

	if jsonOutput {
		// Emit exactly what the daemon returned (pretty enough for CLI).
		b, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(b))
		return
	}

	status, ok := resp["status"].(string)
	if !ok || status != "ok" {
		msg := "unknown error"
		if m, ok := resp["message"].(string); ok {
			msg = m
		}
		fmt.Printf("Scrub failed: %s\n", msg)
		return
	}

	// Special-case disabled Pillar 3 (status=ok with explicit message; no counts populated).
	// This must be handled before the generic "no entries found" fallback so an
	// explicit disabled message is shown rather than a misleading success line.
	if m, ok := resp["message"].(string); ok && strings.Contains(m, "disabled") {
		fmt.Println("Pillar 3 (history hygiene) is disabled in config; no scrubbing performed.")
		return
	}

	// Human output paths
	if dry, ok := resp["dry_run"].(bool); ok && dry {
		fmt.Println("✓ Dry run complete (no changes written).")
		if m, ok := resp["mode_used"].(string); ok {
			fmt.Printf("  Mode: %s\n", m)
		}
		if f, ok := resp["file"].(string); ok && f != "" {
			fmt.Printf("  Target: %s\n", f)
		}
		if del, ok := resp["would_delete"].(float64); ok {
			if red, ok2 := resp["would_redact"].(float64); ok2 {
				fmt.Printf("  Would delete: %d entr(ies)\n", int(del))
				fmt.Printf("  Would redact: %d entr(ies)\n", int(red))
			}
		}
		if sf, ok := resp["secrets_found"].(float64); ok && sf > 0 {
			fmt.Printf("  Secrets found: %d occurrence(s)\n", int(sf))
		}
		// Safe preview examples (already redacted)
		if prev, ok := resp["preview"].(map[string]any); ok {
			if ex, ok2 := prev["example_scrubbed_lines"].([]any); ok2 && len(ex) > 0 {
				fmt.Println("  Example scrubbed lines (secrets replaced):")
				for _, e := range ex {
					if s, ok3 := e.(string); ok3 {
						fmt.Printf("    %s\n", s)
					}
				}
			}
		}
		return
	}

	// Real run output (richer JSON + human-friendly when not --json).
	// Prefer classic single-file keys ("lines_removed", "entries_redacted") when present
	// for existing callers/scripts. Fall back to the always-populated aggregate
	// "deleted"/"redacted" so multi-target redact (and delete) produce correct human
	// output instead of the lying "No sensitive entries were found." line.
	removed, hasRemoved := resp["lines_removed"].(float64)
	red, hasRed := resp["entries_redacted"].(float64)
	if !hasRed {
		if r, ok := resp["redacted"].(float64); ok {
			red = r
			hasRed = red > 0
		}
	}
	if hasRemoved && removed > 0 {
		fmt.Printf("✓ Successfully scrubbed %d sensitive line(s) from history.\n", int(removed))
		if f, ok := resp["file"].(string); ok && f != "" {
			fmt.Printf("  File: %s\n", f)
		}
		if modeUsed, ok := resp["mode_used"].(string); ok && modeUsed == "redact" {
			if sf, ok2 := resp["secrets_found"].(float64); ok2 {
				fmt.Printf("  (redact mode; %d secret occurrence(s) replaced)\n", int(sf))
			}
		}
	} else if hasRed && red > 0 {
		fmt.Printf("✓ Redacted secrets from %d history entr(ies).\n", int(red))
		if f, ok := resp["file"].(string); ok && f != "" {
			fmt.Printf("  File: %s\n", f)
		}
	} else {
		fmt.Println("✓ History scrub complete. No sensitive entries were found.")
	}
}
