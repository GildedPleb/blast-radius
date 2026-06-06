package handlers

import (
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/scrub"
)

type ScrubHistoryHandler struct{}

func (ScrubHistoryHandler) Name() string { return "SCRUB_HISTORY" }

func init() { Register(ScrubHistoryHandler{}) }

func (ScrubHistoryHandler) Handle(args string, d DaemonContext) (any, error) {
	cfg := d.Pillar3Config()
	if !cfg.Enabled {
		return map[string]any{"status": "ok", "message": "Pillar 3 (history hygiene) is disabled in config", "file": ""}, nil
	}

	release, ok := d.BeginExclusiveOp("SCRUB_HISTORY")
	if !ok {
		return map[string]any{"status": "error", "message": "daemon busy (another scrub or long-running operation is already in progress)"}, nil
	}
	defer release()

	mode, placeholder, overrideFile, dryRun, full := parseScrubArgs(args, cfg)
	if placeholder == "" {
		placeholder = scrub.DefaultPlaceholder()
	}

	var targets []string
	if overrideFile != "" {
		if _, err := os.Stat(overrideFile); err != nil {
			return map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("failed to access history file for --file override: %v", err),
			}, nil
		}
		targets = []string{overrideFile}
	} else {
		targets = discoverHistoryTargetsFn(cfg.HistoryRoots, cfg.HistoryFiles)
	}

	if len(targets) == 0 {
		return map[string]any{
			"status":  "error",
			"message": "Could not determine any history file locations (no $HISTFILE, no LCD files under home, no history_roots/history_files)",
		}, nil
	}

	allHashes := d.AllHashes()
	currentRegFp := scrub.ComputeRegistryFingerprint(allHashes)

	var results []fileResult
	totalDeleted, totalRedacted, totalSecrets := 0, 0, 0
	anyChanged := false

	for _, histFile := range targets {
		res := processHistoryTarget(histFile, allHashes, currentRegFp, scrub.Mode(mode), placeholder, full, dryRun)
		results = append(results, res)
		if dryRun || res.writeSucceeded {
			totalDeleted += res.deleted
			totalRedacted += res.redacted
			totalSecrets += res.secrets
			if res.deleted+res.redacted > 0 {
				anyChanged = true
			}
		}
	}

	effectiveMode := mode
	if effectiveMode == "" {
		effectiveMode = "delete"
	}

	changedFiles := 0
	for _, r := range results {
		if r.deleted+r.redacted > 0 {
			changedFiles++
		}
	}

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
		"files":         results,
		"deleted":       totalDeleted,
		"redacted":      totalRedacted,
		"secrets":       totalSecrets,
		"changed":       anyChanged,
		"current_regfp": currentRegFp,
	}
	if singleFile != "" {
		resp["file"] = singleFile
	}

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
	} else if effectiveMode == "delete" {
		resp["lines_removed"] = totalDeleted
		resp["message"] = fmt.Sprintf("Scrubbed %d sensitive line(s) from %d history artifact(s)", totalDeleted, changedFiles)
	} else {
		resp["message"] = fmt.Sprintf("Redacted %d secret occurrence(s) across %d entr(ies) in %d artifact(s)", totalSecrets, totalRedacted, changedFiles)
	}

	logging.Printf("History scrub complete. mode=%s targets=%d deleted=%d redacted=%d secrets=%d full=%v",
		effectiveMode, len(targets), totalDeleted, totalRedacted, totalSecrets, full)

	return resp, nil
}

// parseScrubArgs parses the daemon args string for mode, dry-run, full/reset,
// and the file= override (preserving spaces in the path value).
func parseScrubArgs(args string, cfg config.Pillar3Config) (mode, placeholder, overrideFile string, dryRun, full bool) {
	mode = cfg.Mode
	placeholder = cfg.RedactPlaceholder

	for _, tok := range strings.Fields(args) {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "dry-run" || tok == "--dry-run":
			dryRun = true
		case tok == "full" || tok == "--full" || tok == "--reset" || tok == "reset":
			full = true
		case strings.HasPrefix(tok, "mode="):
			if m := strings.TrimPrefix(tok, "mode="); scrub.IsValidMode(m) {
				mode = m
			}
		}
	}

	// Check --file= first to avoid matching the "file=" substring inside it
	if idx := strings.Index(args, "--file="); idx != -1 {
		overrideFile = strings.TrimSpace(args[idx+7:])
	} else if idx := strings.Index(args, "file="); idx != -1 {
		overrideFile = strings.TrimSpace(args[idx+5:])
	}
	return
}

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
	preview        map[string]any
	writeSucceeded bool
}

// processHistoryTarget handles one file end-to-end: read, scrub, and (if not dry-run)
// atomically write the cleaned content plus a fresh v2 receipt.
func processHistoryTarget(
	histFile string,
	allHashes []registry.SecretHash,
	currentRegFp string,
	mode scrub.Mode,
	placeholder string,
	full, dryRun bool,
) fileResult {
	res := fileResult{path: histFile}

	data, err := os.ReadFile(histFile)
	if err != nil {
		logging.Printf("Failed to read history target %s: %v (skipping)", histFile, err)
		res.skipped = true
		res.skippedReason = "unreadable"
		return res
	}

	lines := strings.Split(string(data), "\n")
	res.originalLines = len(lines)

	proc := scrub.ProcessHistory(lines, allHashes, currentRegFp, mode, placeholder, full, dryRun)
	if proc.Skipped {
		res.skipped = true
		res.skippedReason = proc.SkippedReason
		res.hadReceipt = proc.HadReceipt
		res.regFpMatch = proc.RegFpMatch
		return res
	}

	res.processedLines = proc.Processed
	res.deleted = proc.Deleted
	res.redacted = proc.Redacted
	res.secrets = proc.Secrets
	res.hadReceipt = proc.HadReceipt
	res.regFpMatch = proc.RegFpMatch

	if dryRun {
		res.preview = proc.Preview
		res.writeSucceeded = true
		return res
	}

	// Always plant current receipt (even on 0-change) so incremental fingerprint logic works.
	lineCount, tailHash := scrub.ComputeHistoryFingerprint(proc.Kept)
	receiptLine := scrub.FormatScrubReceiptV2(lineCount, tailHash, currentRegFp)

	if err := writeFinalHistoryAtomic(histFile, proc.Kept, receiptLine); err != nil {
		logging.Printf("Failed to write final history for %s: %v", histFile, err)
		res.skippedReason = "write-failed"
		return res
	}
	res.writeSucceeded = true
	return res
}

// writeFinalHistoryAtomic performs a single atomic write of (kept + receipt).
// This replaces the previous two-phase (content then receipt) approach.
func writeFinalHistoryAtomic(path string, kept []string, receiptLine string) error {
	final := append(append([]string(nil), kept...), receiptLine)
	tmp := path + ".blastradius-tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(final, "\n")), 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var discoverHistoryTargetsFn = scrub.DiscoverHistoryTargets
