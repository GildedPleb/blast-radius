package scrub

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// history.go contains the discovery logic and higher-level processing for
// Pillar 3 (shell history hygiene).
//
// It owns LCD + rotated-sibling file discovery under history roots, the
// hybrid receipt + registry-fingerprint incremental decision, range
// selection for partial re-scrub, and dry-run preview building. The pure
// apply, receipt formatting, and ShouldReprocess primitives live in policy.go
// (same package).

// DiscoverHistoryTargets is the multi-target discovery for Pillar 3.
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
// This is the supported discovery path (LCD live files + rotated siblings under the roots).
// Called by the SCRUB_HISTORY handler (via its package-local seam for hermetic tests)
// and directly by unit tests in this package.
func DiscoverHistoryTargets(roots []string, extras []string) []string {
	home := os.Getenv("HOME")
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

	// $HISTFILE always has priority if it exists (expand ~ for consistency with roots/extras).
	add(util.ExpandPath(os.Getenv("HISTFILE")))

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
			if LooksLikeRotatedHistory(name, liveStems) {
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

// LooksLikeRotatedHistory returns true for names that are very likely rotated
// or backup copies of shell history files. It is intentionally conservative.
// LooksLikeRotatedHistory is exported so the handler tests can directly
// exercise the rotated-file predicate.
func LooksLikeRotatedHistory(name string, stems []string) bool {
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

// HistoryProcessResult is the return from processing one history artifact
// (decision + apply). The handler uses the kept content for writes/receipts
// and the counts/preview for the response. Processed is the count of lines
// actually considered in this pass (post last-scrub marker for incremental
// cases; the full slice for --full).
type HistoryProcessResult struct {
	Kept          []string
	Deleted       int
	Redacted      int
	Secrets       int
	Processed     int // number of lines fed to ApplyBatch for this run (suffix after last marker for incremental; full for --full). 0 if skipped.
	Skipped       bool
	SkippedReason string
	HadReceipt    bool
	RegFpMatch    bool
	Preview       map[string]any // only for dry-run
}

// ProcessHistory performs the full P3 policy application for one history
// file's content: receipt-based "should reprocess" decision (or --full),
// classic last-scrub marker range selection, ApplyBatch, kept assembly,
// and optional dry-run preview.
//
// It is pure with respect to the filesystem. The caller (the SCRUB_HISTORY
// handler) is responsible for the exclusive-op guard, reading the original
// file, writing the result, and planting the v2 receipt.
func ProcessHistory(lines []string, allHashes []registry.SecretHash, currentRegFp string, mode Mode, placeholder string, full, dryRun bool) HistoryProcessResult {
	res := HistoryProcessResult{}

	if len(lines) == 0 {
		return res
	}

	// Decide whether to do work using the hybrid signals:
	// 1. --full forces everything.
	// 2. Otherwise consult the latest receipt we control (deterministic
	//    rewrite/restore observation) + the current regfp.
	latestReceipt := FindLatestReceipt(lines)

	doWork := full
	if !doWork {
		if ShouldReprocess(lines, latestReceipt, currentRegFp) {
			doWork = true
		}
	}

	if !doWork {
		res.Skipped = true
		res.SkippedReason = "receipt+regfp"
		if latestReceipt != nil {
			res.HadReceipt = true
			res.RegFpMatch = (latestReceipt.RegFp == currentRegFp)
		}
		return res
	}

	// We are going to process (at least) some portion of this file.
	// We keep the classic "from last human marker or full" logic for the
	// actual ApplyBatch range, but we have already decided via ShouldReprocess
	// (receipt + regfp) that the file is "dirty".
	lastScrubIdx := FindLastScrubInvocation(lines)
	receiptNear := FindScrubReceiptNear(lines, lastScrubIdx)

	processStart := 0
	if lastScrubIdx >= 0 && !full {
		if receiptNear != nil && HistoryLikelyRewrittenSince(lines, receiptNear) {
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

	keptSuffix, deleted, redacted, secretsFound := ApplyBatch(toProcess, known, det, mode, placeholder)

	kept := append(append([]string(nil), lines[:processStart]...), keptSuffix...)

	res.Kept = kept
	res.Deleted = deleted
	res.Redacted = redacted
	res.Secrets = secretsFound
	res.Processed = len(toProcess)
	res.HadReceipt = latestReceipt != nil
	if latestReceipt != nil {
		res.RegFpMatch = (latestReceipt.RegFp == currentRegFp)
	}

	if dryRun {
		res.Preview = buildDryRunPreview(lines, kept, deleted, redacted, secretsFound, placeholder)
	}

	return res
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
