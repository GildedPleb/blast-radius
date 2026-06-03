package handlers

import (
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/scrub"
)

type ScrubHistoryHandler struct{}

func (ScrubHistoryHandler) Name() string { return "SCRUB_HISTORY" }

func init() { Register(ScrubHistoryHandler{}) }

func (ScrubHistoryHandler) Handle(args string, d DaemonContext) (any, error) {
	cfg := d.Pillar3Config()
	if !cfg.Enabled {
		return map[string]any{
			"status":  "ok",
			"message": "Pillar 3 (history hygiene) is disabled in config",
			"file":    "",
		}, nil
	}

	// Coarse concurrency guard: scrub (and similar mutating ops) must not run
	// concurrently or we risk corrupting history files via temp/rename races.
	release, ok := d.BeginExclusiveOp("SCRUB_HISTORY")
	if !ok {
		return map[string]any{
			"status":  "error",
			"message": "daemon busy (another scrub or long-running operation is already in progress)",
		}, nil
	}
	defer release()

	// Parse simple args overrides: "mode=redact dry-run file=/tmp/foo_history"
	mode := cfg.Mode
	placeholder := cfg.RedactPlaceholder
	if placeholder == "" {
		placeholder = scrub.DefaultPlaceholder()
	}
	dryRun := false
	full := false // --full / --reset forces a complete pass, ignoring all receipts
	overrideFile := ""

	if args != "" {
		for _, tok := range strings.Fields(args) {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if tok == "dry-run" || tok == "--dry-run" {
				dryRun = true
				continue
			}
			if tok == "full" || tok == "--full" || tok == "--reset" || tok == "reset" {
				full = true
				continue
			}
			if strings.HasPrefix(tok, "mode=") {
				m := strings.TrimPrefix(tok, "mode=")
				if scrub.IsValidMode(m) {
					mode = m
				}
				continue
			}
			if strings.HasPrefix(tok, "file=") || strings.HasPrefix(tok, "--file=") {
				overrideFile = strings.TrimPrefix(strings.TrimPrefix(tok, "--file="), "file=")
				continue
			}
		}
	}

	// Determine the set of targets.
	var targets []string
	if overrideFile != "" {
		// --file forces exactly one. If the user explicitly asked for a
		// non-existent path we return a hard error (to match documented and
		// tested behavior for explicit --file overrides naming a missing path).
		if _, err := os.Stat(overrideFile); err != nil {
			return map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("failed to access history file for --file override: %v", err),
			}, nil
		}
		targets = []string{overrideFile}
	} else {
		// Current discovery path (LCD + rotated siblings under roots).
		// Tests override discoverHistoryTargetsFn (see seam below) to control
		// targets hermetically (history_roots/history_files + $HOME via t.Setenv).
		roots := cfg.HistoryRoots
		extras := cfg.HistoryFiles
		targets = discoverHistoryTargetsFn(roots, extras)
	}

	if len(targets) == 0 {
		return map[string]any{
			"status":  "error",
			"message": "Could not determine any history file locations (no $HISTFILE, no LCD files under home, no history_roots/history_files)",
		}, nil
	}

	// Compute the current registry fingerprint once for the whole run.
	// This is the key input to the hybrid incremental decision.
	allHashes := d.AllHashes()
	currentRegFp := scrub.ComputeRegistryFingerprint(allHashes)

	// We will accumulate per-file results.
	type fileResult struct {
		path           string
		originalLines  int
		processedLines int // lines fed to this scrub pass (suffix after marker for incremental; full for --full). Used for classic single-file "lines_since_last_scrub" compat.
		deleted        int
		redacted       int
		secrets        int
		skipped        bool
		skippedReason  string
		hadReceipt     bool
		regFpMatch     bool
		// preview holds dry-run preview data (would_* + optional example_scrubbed_lines)
		// populated only on dry-run paths so the builder is actually used.
		preview map[string]any
	}

	var results []fileResult
	totalDeleted, totalRedacted, totalSecrets := 0, 0, 0
	anyChanged := false

	for _, histFile := range targets {
		res := fileResult{path: histFile}

		data, err := os.ReadFile(histFile)
		if err != nil {
			logging.Printf("Failed to read history target %s: %v (skipping)", histFile, err)
			res.skipped = true
			res.skippedReason = "unreadable"
			results = append(results, res)
			continue
		}

		lines := strings.Split(string(data), "\n")
		res.originalLines = len(lines)

		// The decision logic, range selection, ApplyBatch, and dry-run preview
		// live in scrub so that all Pillar 3 policy (receipts, fingerprints,
		// incremental reprocessing, discovery rules) is in one package.
		proc := scrub.ProcessHistory(lines, allHashes, currentRegFp, scrub.Mode(mode), placeholder, full, dryRun)

		if proc.Skipped {
			res.skipped = true
			res.skippedReason = proc.SkippedReason
			res.hadReceipt = proc.HadReceipt
			res.regFpMatch = proc.RegFpMatch
			results = append(results, res)
			continue
		}

		kept := proc.Kept
		deleted := proc.Deleted
		redacted := proc.Redacted
		secretsFound := proc.Secrets

		res.processedLines = proc.Processed // count of lines after last marker (or full file for --full) that were fed to the scrub pass
		res.deleted = deleted
		res.redacted = redacted
		res.secrets = secretsFound
		res.hadReceipt = proc.HadReceipt
		res.regFpMatch = proc.RegFpMatch

		if dryRun {
			res.preview = proc.Preview
		}

		// Write + receipt planting for real runs on targets we decided to process.
		// We *always* plant a fresh v2 receipt with the *current* regfp when we
		// inspected a target (even if ApplyBatch found 0 matches this time). This
		// records "as of this regfp the artifact was clean (or cleaned)", which is
		// required for the incremental "skip when regfp+no-rewrite" behavior to
		// actually stick on clean artifacts after registry growth.
		writeSucceeded := true
		if !dryRun {
			needsContentWrite := (deleted > 0 || redacted > 0)
			if needsContentWrite {
				tmpFile := histFile + ".blastradius-tmp"
				cleanContent := strings.Join(kept, "\n")
				if err := os.WriteFile(tmpFile, []byte(cleanContent), 0600); err != nil {
					logging.Printf("Failed to write temp for %s: %v", histFile, err)
					// Best effort cleanup so we don't leak partial .blastradius-tmp files.
					_ = os.Remove(tmpFile)
					res.skippedReason = "write-failed"
					writeSucceeded = false
				} else if err := os.Rename(tmpFile, histFile); err != nil {
					_ = os.Remove(tmpFile)
					logging.Printf("Failed to replace %s: %v", histFile, err)
					res.skippedReason = "rename-failed"
					writeSucceeded = false
				}
			}
			if writeSucceeded {
				// Plant (or update) receipt for the post-apply kept state + current regfp.
				// For 0-change case this appends the receipt to the original content.
				lineCount, tailHash := scrub.ComputeHistoryFingerprint(kept)
				receiptLine := scrub.FormatScrubReceiptV2(lineCount, tailHash, currentRegFp)

				receiptTmp := histFile + ".blastradius-receipt-tmp"
				newContent := strings.Join(append(append([]string(nil), kept...), receiptLine), "\n")
				if werr := os.WriteFile(receiptTmp, []byte(newContent), 0600); werr == nil {
					_ = os.Rename(receiptTmp, histFile)
				} else {
					logging.Printf("Failed to write receipt temp for %s: %v (content may have been updated)", histFile, werr)
					// leave receiptTmp; not critical, next run will try again
				}
			}
		}

		// Only fold this target's counts into the aggregate totals (and anyChanged)
		// if this was a dry-run "would" or a real run that actually persisted the
		// changes/receipt. This prevents the handler from over-reporting success
		// (lines_removed etc.) when a write failed for a target that had matches.
		if dryRun || writeSucceeded {
			totalDeleted += deleted
			totalRedacted += redacted
			totalSecrets += secretsFound
			if deleted+redacted > 0 {
				anyChanged = true
			}
		}

		results = append(results, res)
	}

	// At this point we have processed (or skipped) every target.
	// Build the final aggregate response (rich for the multi-file world,
	// while keeping top-level aggregate fields for the common single-file case).

	effectiveMode := mode
	if effectiveMode == "" {
		effectiveMode = "delete"
	}

	// Simple aggregate numbers for the common case.
	changedFiles := 0
	for _, r := range results {
		if r.deleted+r.redacted > 0 {
			changedFiles++
		}
	}

	// For the (common) single-target or --file case we still emit the classic
	// top-level keys so existing scripts that only look at those continue to
	// work. For the general case we also emit the detailed "files" array.
	singleFile := ""
	if len(targets) == 1 {
		singleFile = targets[0]
	}

	resp := map[string]any{
		"status":        "ok",
		"mode_used":     effectiveMode,
		"dry_run":       dryRun,
		"full":          full,
		"targets":       len(targets),
		"files":         results, // detailed per-file info for JSON consumers
		"deleted":       totalDeleted,
		"redacted":      totalRedacted,
		"secrets":       totalSecrets,
		"changed":       anyChanged,
		"current_regfp": currentRegFp,
	}

	if singleFile != "" {
		resp["file"] = singleFile // classic single-file field
	}

	// For the single-file / --file path we also emit the classic flat keys
	// that the large existing test suite (and any external scripts) expect.
	// This keeps the surface change additive rather than breaking for the
	// common case.
	if len(results) == 1 {
		r := results[0]
		resp["original_lines"] = r.originalLines
		resp["lines_since_last_scrub"] = r.processedLines // size of the range actually scrubbed this invocation (post-marker suffix or full)
		resp["entries_deleted"] = r.deleted
		resp["entries_redacted"] = r.redacted
		resp["secrets_found"] = r.secrets
		if dryRun {
			resp["would_delete"] = r.deleted
			resp["would_redact"] = r.redacted
		}
		if !dryRun && r.deleted+r.redacted == 0 {
			resp["lines_removed"] = 0
		}
	}

	// For dry-run, ensure top-level would_* (and preview) are present even for
	// multi-target runs. This makes CLI human output and JSON consumers see
	// consistent "would" numbers and unblocks the preview builder for all cases.
	if dryRun {
		resp["would_delete"] = totalDeleted
		resp["would_redact"] = totalRedacted
		for _, r := range results {
			if r.preview != nil {
				resp["preview"] = r.preview
				break
			}
		}
	}

	if dryRun {
		resp["message"] = fmt.Sprintf("dry-run: would %s across %d artifact(s) (deleted=%d redacted=%d secrets=%d)",
			effectiveMode, len(targets), totalDeleted, totalRedacted, totalSecrets)
	} else if !anyChanged {
		resp["message"] = "No sensitive entries required changes across any discovered history artifacts"
		resp["lines_removed"] = 0
	} else {
		if effectiveMode == "delete" {
			resp["lines_removed"] = totalDeleted
			resp["message"] = fmt.Sprintf("Scrubbed %d sensitive line(s) from %d history artifact(s)", totalDeleted, changedFiles)
		} else {
			resp["message"] = fmt.Sprintf("Redacted %d secret occurrence(s) across %d entr(ies) in %d artifact(s)", totalSecrets, totalRedacted, changedFiles)
		}
	}

	logging.Printf("History scrub complete. mode=%s targets=%d deleted=%d redacted=%d secrets=%d full=%v",
		effectiveMode, len(targets), totalDeleted, totalRedacted, totalSecrets, full)

	return resp, nil
}

// discoverHistoryTargetsFn is the overridable seam for the (only) multi-target
// discovery. Tests that want to control exactly which artifacts are considered
// (for hermetic testing of history_roots, auto-rotated siblings, etc.) should
// override this. It defaults to the implementation in internal/scrub.
var discoverHistoryTargetsFn = scrub.DiscoverHistoryTargets
