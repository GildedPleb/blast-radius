package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/scrub"
	"github.com/GildedPleb/blast-radius/internal/util"
)

type ScrubHistoryHandler struct{}

func (ScrubHistoryHandler) Name() string { return "SCRUB_HISTORY" }

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
		// non-existent path we return a hard error (preserves old test
		// expectations and "I asked for this exact file" intent).
		if _, err := os.Stat(overrideFile); err != nil {
			return map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("failed to access history file for --file override: %v", err),
			}, nil
		}
		targets = []string{overrideFile}
	} else {
		// Pure new-world discovery. No legacy single-file fallback.
		// Tests must override discoverHistoryTargetsFn (or configure HistoryRoots/HistoryFiles
		// + getHistoryHome) to control what gets scrubbed.
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
		processedLines int
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

		// Decide whether to do work using the hybrid signals:
		// 1. --full forces everything.
		// 2. Otherwise consult the latest receipt we control (deterministic
		//    rewrite/restore observation) + the current regfp.
		latestReceipt := scrub.FindLatestReceipt(lines)

		doWork := full
		if !doWork {
			if scrub.ShouldReprocess(lines, latestReceipt, currentRegFp) {
				doWork = true
			}
		}

		if !doWork {
			res.skipped = true
			res.skippedReason = "receipt+regfp"
			if latestReceipt != nil {
				res.hadReceipt = true
				res.regFpMatch = (latestReceipt.RegFp == currentRegFp)
			}
			results = append(results, res)
			continue
		}

		// We are going to process (at least) some portion of this file.
		// For now (v1 of the big change) we keep the classic "from last human
		// marker or full" logic for the actual ApplyBatch range, but we have
		// already decided via the new ShouldReprocess that the file is "dirty".
		lastScrubIdx := scrub.FindLastScrubInvocation(lines)
		receiptNear := scrub.FindScrubReceiptNear(lines, lastScrubIdx)

		processStart := 0
		if lastScrubIdx >= 0 && !full {
			if receiptNear != nil && scrub.HistoryLikelyRewrittenSince(lines, receiptNear) {
				processStart = 0
			} else {
				processStart = lastScrubIdx + 1
			}
		}

		toProcess := lines[processStart:]

		// Build the known set (same as before).
		known := make(map[[32]byte]bool, len(allHashes))
		for _, h := range allHashes {
			known[h] = true
		}

		det := detection.NewDetector()

		keptSuffix, deleted, redacted, secretsFound := scrub.ApplyBatch(toProcess, known, det, scrub.Mode(mode), placeholder)

		kept := append(append([]string(nil), lines[:processStart]...), keptSuffix...)

		res.processedLines = len(toProcess)
		res.deleted = deleted
		res.redacted = redacted
		res.secrets = secretsFound
		res.hadReceipt = latestReceipt != nil
		if latestReceipt != nil {
			res.regFpMatch = (latestReceipt.RegFp == currentRegFp)
		}

		if dryRun {
			// Wire the previously-dead preview builder so --dry-run responses
			// (and CLI human output) actually include example_scrubbed_lines etc.
			res.preview = buildDryRunPreview(lines, kept, deleted, redacted, secretsFound, placeholder)
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
	// Build the final aggregate response (rich for the new multi-file world,
	// while keeping enough top-level fields for rough backward compat when
	// only one file was involved).

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
		resp["lines_since_last_scrub"] = r.processedLines
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

// buildDryRunPreview returns a small, safe summary + up to 3 example scrubbed lines
// (already containing only placeholders, never real secret material).
func buildDryRunPreview(originalLines, kept []string, deleted, redacted, secrets int, placeholder string) map[string]any {
	preview := map[string]any{
		"would_delete":  deleted,
		"would_redact":  redacted,
		"secrets_found": secrets,
	}
	// Collect a few redacted examples (lines that changed and now contain the placeholder).
	examples := []string{}
	seen := 0
	for i, orig := range originalLines {
		if seen >= 3 {
			break
		}
		if i < len(kept) && kept[i] != orig && strings.Contains(kept[i], placeholder) {
			examples = append(examples, kept[i])
			seen++
		}
	}
	if len(examples) > 0 {
		preview["example_scrubbed_lines"] = examples
	}
	return preview
}

// discoverHistoryTargetsFn is the overridable seam for the (only) multi-target
// discovery. Tests that want to control exactly which artifacts are considered
// (for hermetic testing of history_roots, auto-rotated siblings, etc.) should
// override this.
var discoverHistoryTargetsFn = discoverHistoryTargets

// getHistoryHome is a test seam for hermetic control of the HOME value used
// when discovering history files. Production code uses the real environment.
var getHistoryHome = func() string { return os.Getenv("HOME") }

// discoverHistoryTargets is the multi-target discovery for Pillar 3.
// It returns a deduplicated, existing-files-only list of history artifacts to consider.
//
// Rules:
//   - Always honor $HISTFILE if it exists.
//   - For each provided root (or $HOME if none), add the LCD live candidates under it.
//   - For every directory that contains a live candidate, also add "rotated sibling"
//     files that match common backup/rotated patterns for the known stems.
//   - Append all user explicit extras (history_files).
//   - The result is sorted (lexical) and unique for determinism (readdir order is
//     not guaranteed stable across platforms or runs).
//
// This is the only supported discovery path. There is no legacy single-file fallback.
func discoverHistoryTargets(roots []string, extras []string) []string {
	home := getHistoryHome()
	seen := map[string]bool{}
	var out []string

	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}

	// $HISTFILE always has priority if it exists.
	add(os.Getenv("HISTFILE"))

	// Determine the roots we will search.
	searchRoots := roots
	if len(searchRoots) == 0 {
		if home != "" {
			searchRoots = []string{home}
		}
	}

	// Known live stems (basenames) we care about for sibling detection.
	liveStems := []string{
		".bash_history", ".zsh_history", ".zhistory", ".history",
		".sh_history", ".mksh_history", "fish_history",
	}

	for _, r := range searchRoots {
		if r == "" {
			continue
		}
		// Expand ~ if present in a root (users may put "~/foo" in config).
		// Unified with util.ExpandPath (which also handles bare "~").
		r = util.ExpandPath(r)

		for _, stem := range liveStems {
			cand := filepath.Join(r, stem)
			add(cand)
		}

		// Now look for rotated/backup siblings in the same directory as any
		// of the candidates we just considered (or the root itself).
		// We do a cheap ReadDir + name filter instead of full glob for simplicity
		// and to avoid pulling in extra matching logic for this change.
		entries, err := os.ReadDir(r)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// Match common rotated patterns against any of our stems or generic history-ish names.
			if looksLikeRotatedHistory(name, liveStems) {
				add(filepath.Join(r, name))
			}
		}
	}

	// Explicit extras always win inclusion (even if they wouldn't be auto-discovered).
	for _, p := range extras {
		p = util.ExpandPath(p)
		add(p)
	}

	// Sort for deterministic order (readdir order is not stable across platforms/runs).
	sort.Strings(out)
	return out
}

// looksLikeRotatedHistory returns true for names that are very likely rotated
// or backup copies of shell history files. It is intentionally conservative.
func looksLikeRotatedHistory(name string, stems []string) bool {
	lower := strings.ToLower(name)
	for _, s := range stems {
		base := filepath.Base(s)
		if strings.HasPrefix(lower, base) || strings.Contains(lower, strings.TrimPrefix(base, ".")) {
			// Any name that starts with or contains a stem and has a "rotated" suffix.
			if strings.Contains(lower, ".old") || strings.Contains(lower, ".bak") ||
				strings.Contains(lower, ".backup") || strings.Contains(lower, ".orig") ||
				strings.HasSuffix(lower, "~") {
				return true
			}
			// Numeric rotated ( .1 .2 .3 ... ) or .1.gz style (we don't gunzip here).
			if matched, _ := filepath.Match(base+`.[0-9]*`, name); matched {
				return true
			}
			if matched, _ := filepath.Match("*"+base+`.[0-9]*`, name); matched {
				return true
			}
		}
	}
	// Generic history-ish rotated files even if stem not perfectly matched.
	if strings.Contains(lower, "history") || strings.Contains(lower, "zhistory") {
		if strings.Contains(lower, ".old") || strings.Contains(lower, ".bak") ||
			strings.Contains(lower, ".1") || strings.HasSuffix(lower, "~") {
			return true
		}
	}
	return false
}
