package scrub

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Mode selects the redaction strategy for history hygiene (Pillar 3).
type Mode string

const (
	// ModeDelete removes the entire history entry (line or zsh extended record).
	// This is the safe default and original behavior.
	ModeDelete Mode = "delete"

	// ModeRedact replaces every detected secret value (substring) inside the
	// command portion of the entry with the configured placeholder. The shape
	// of the command (and zsh timestamp/duration prefix when present) is preserved.
	ModeRedact Mode = "redact"
)

// zshExtendedRE matches the standard zsh EXTENDED_HISTORY prefix.
// Examples: ": 1699999999:5;curl ...", ":123:0;echo hi"
var zshExtendedRE = regexp.MustCompile(`^:\s*\d+:\d+;`)

// Entry is a parsed history line. For plain formats (bash, most shells) Prefix=="".
// For zsh with EXTENDED_HISTORY, Prefix holds the ": ts:dur;" portion and Command
// holds everything after it. Redaction is only ever applied to Command.
type Entry struct {
	Prefix  string
	Command string
	Raw     string // original full line for reference
}

// ParseEntry returns an Entry. It recognizes zsh extended format and leaves
// everything else as a plain entry (Command == Raw).
func ParseEntry(line string) Entry {
	if m := zshExtendedRE.FindString(line); m != "" {
		cmd := strings.TrimPrefix(line, m)
		return Entry{Prefix: m, Command: cmd, Raw: line}
	}
	return Entry{Prefix: "", Command: line, Raw: line}
}

// Result describes the outcome of scrubbing one history entry.
type Result struct {
	Original        string
	Final           string // for delete: "", for redact/kept: the (possibly modified) line content
	Action          string // "kept" | "redacted" | "deleted"
	SecretsRedacted int
}

// ApplyToLine is the single-entry policy. It uses the unified detector + registry
// lookup (exactly as the prior inline logic) but adds format awareness and the
// two supported modes. placeholder is only used for ModeRedact.
func ApplyToLine(raw string, known map[[32]byte]bool, det *detection.Detector, mode Mode, placeholder string) Result {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Result{Original: raw, Final: raw, Action: "kept"}
	}

	entry := ParseEntry(raw)

	// Detect using the command portion (safer + sufficient; timestamps rarely contain secrets).
	scanSrc := entry.Command
	if scanSrc == "" {
		scanSrc = raw
	}
	cands := det.ExtractCandidates([]byte(scanSrc))

	matched := make([]string, 0, len(cands))
	seen := map[string]bool{}
	for _, c := range cands {
		h := registry.HashValue([]byte(c))
		if known[h] && !seen[c] {
			seen[c] = true
			matched = append(matched, c)
		}
	}

	if len(matched) == 0 {
		return Result{Original: raw, Final: raw, Action: "kept"}
	}

	if mode == ModeDelete || mode == "" {
		return Result{
			Original:        raw,
			Final:           "",
			Action:          "deleted",
			SecretsRedacted: len(matched),
		}
	}

	// Redact: only mutate the Command portion, then reassemble prefix if present.
	scrubbed := entry.Command
	for _, sec := range matched {
		// Exact substring replacement of the literal candidate value.
		// This is safe because ExtractCandidates returns values as they appear in the text.
		scrubbed = strings.ReplaceAll(scrubbed, sec, placeholder)
	}

	final := scrubbed
	if entry.Prefix != "" {
		final = entry.Prefix + scrubbed
	}

	return Result{
		Original:        raw,
		Final:           final,
		Action:          "redacted",
		SecretsRedacted: len(matched),
	}
}

// ApplyBatch processes a slice of raw lines (as produced by strings.Split on \n)
// and returns the kept lines plus aggregate counts. It never returns secret material.
func ApplyBatch(lines []string, known map[[32]byte]bool, det *detection.Detector, mode Mode, placeholder string) (kept []string, deleted, redacted, totalSecrets int) {
	for _, l := range lines {
		r := ApplyToLine(l, known, det, mode, placeholder)
		switch r.Action {
		case "deleted":
			deleted++
			totalSecrets += r.SecretsRedacted
		case "redacted":
			if r.Final != "" {
				kept = append(kept, r.Final)
			}
			redacted++
			totalSecrets += r.SecretsRedacted
		default:
			kept = append(kept, l)
		}
	}
	return kept, deleted, redacted, totalSecrets
}

// IsValidMode reports whether m is one of the supported modes.
func IsValidMode(m string) bool {
	switch Mode(m) {
	case ModeDelete, ModeRedact:
		return true
	}
	return false
}

// DefaultPlaceholder returns the fallback when config is empty.
func DefaultPlaceholder() string { return "[REDACTED]" }

// FindLastScrubInvocation returns the index of the most recent line that
// looks like an invocation of the scrub-history command.
//
// It searches backwards and inspects the command portion (handling both
// plain history lines and zsh EXTENDED_HISTORY format).
//
// A line is considered a scrub-history invocation if its command portion
// contains the substring "scrub-history" (covers "blastradius scrub-history",
// "br scrub-history", full paths, flags, etc.).
//
// Returns -1 if no such line is found in the provided slice.
func FindLastScrubInvocation(lines []string) int {
	for i := len(lines) - 1; i >= 0; i-- {
		entry := ParseEntry(lines[i])
		cmd := strings.TrimSpace(entry.Command)
		if strings.Contains(cmd, "scrub-history") {
			return i
		}
	}
	return -1
}

// ScrubReceipt is a small machine-readable record we leave in (or near)
// history artifacts after scrubbing. v2 includes the registry fingerprint
// so we can deterministically detect when new secrets exist that were not
// present during the previous scrub of that artifact.
type ScrubReceipt struct {
	Version   int    // 1 or 2+
	LineCount int    // total lines when we finished
	TailHash  string // short hash of tail for content fingerprinting
	RegFp     string // registry fingerprint at scrub time (v2+); "" for v1
}

// scrubReceiptRE is forgiving and matches both v1 and v2 formats.
// v2 adds an optional :regfp=... field.
var scrubReceiptRE = regexp.MustCompile(`^#\s*blastradius-scrub-receipt:v(\d+):lines=(\d+):tail=([0-9a-f]+)(?::regfp=([0-9a-f]+))?`)

// FindScrubReceiptNear looks immediately after a known scrub invocation index
// for a receipt line we may have left. It returns the receipt if found (and
// parses it), otherwise nil. It now populates RegFp for v2+ receipts.
func FindScrubReceiptNear(lines []string, scrubIdx int) *ScrubReceipt {
	if scrubIdx < 0 || scrubIdx+1 >= len(lines) {
		return nil
	}

	for j := scrubIdx + 1; j < len(lines) && j <= scrubIdx+3; j++ {
		line := strings.TrimSpace(lines[j])
		if m := scrubReceiptRE.FindStringSubmatch(line); m != nil {
			var r ScrubReceipt
			fmt.Sscanf(m[1], "%d", &r.Version)
			fmt.Sscanf(m[2], "%d", &r.LineCount)
			r.TailHash = m[3]
			if len(m) > 4 {
				r.RegFp = m[4]
			}
			return &r
		}
	}
	return nil
}

// FindLatestReceipt scans the entire lines slice (from the end) and returns
// the last (highest index) well-formed blastradius scrub receipt it finds.
// This is the generalized primitive used for archival/rotated files.
// Returns nil if none present.
func FindLatestReceipt(lines []string) *ScrubReceipt {
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if m := scrubReceiptRE.FindStringSubmatch(line); m != nil {
			var r ScrubReceipt
			fmt.Sscanf(m[1], "%d", &r.Version)
			fmt.Sscanf(m[2], "%d", &r.LineCount)
			r.TailHash = m[3]
			if len(m) > 4 {
				r.RegFp = m[4]
			}
			return &r
		}
	}
	return nil
}

// ComputeHistoryFingerprint produces a simple fingerprint for the current state
// of a history file. We use line count + a hash of the tail for cheap change detection.
func ComputeHistoryFingerprint(lines []string) (lineCount int, tailHash string) {
	lineCount = len(lines)

	// Take up to the last 64 lines as the "tail" for fingerprinting
	tailStart := 0
	if len(lines) > 64 {
		tailStart = len(lines) - 64
	}
	tail := strings.Join(lines[tailStart:], "\n")

	h := sha256.Sum256([]byte(tail))
	tailHash = fmt.Sprintf("%x", h[:8]) // short 8-byte hex for readability in the file
	return lineCount, tailHash
}

// stripReceipts removes our own scrub receipt marker lines (wherever they appear)
// before computing a content fingerprint for rewrite detection. The stored receipt
// values were computed on the user content *before* we appended our marker, so we
// must ignore markers (and any number of them for rotated + live) when comparing.
func stripReceipts(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "# blastradius-scrub-receipt:") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// HistoryLikelyRewrittenSince returns true if the current lines look
// meaningfully different from what the receipt claims they were at scrub time.
// This is a heuristic, not perfect.
func HistoryLikelyRewrittenSince(currentLines []string, receipt *ScrubReceipt) bool {
	if receipt == nil {
		return true // no receipt = we have no idea, treat as potentially rewritten
	}

	effective := stripReceipts(currentLines)
	currentCount, currentTail := ComputeHistoryFingerprint(effective)

	// If line count dropped significantly, the file was almost certainly truncated/rewritten
	// (old scrubbed content may have been restored, bringing secrets back before the marker).
	if currentCount < receipt.LineCount-5 {
		return true
	}

	// If we have a stored tail hash, compare it. Mismatch (after stripping our markers)
	// is a rewrite/restore signal (for small files the tail is effectively the whole
	// content; for rotated/static files an edit that doesn't change total line count
	// can still be caught here). For live appends after a marker the effective tail
	// will differ, causing full reprocess on next doWork (safe; necessary when regfp
	// changed to catch historical secrets matching the new registry values).
	if receipt.TailHash != "" && currentTail != receipt.TailHash {
		return true
	}

	return false
}

// ShouldReprocess returns true if the current artifact state (lines + optional
// latest receipt + current registry fingerprint) indicates that we should
// perform (re)scrubbing work on it.
//
// Rules (designed to be conservative and to answer the "deterministic rewrite"
// question via our own control records):
//   - No receipt at all → reprocess (first time or marker was stripped by restore/rewrite).
//   - Receipt present but RegFp is empty or does not match currentRegFp → reprocess
//     (new secrets have appeared in the registry since we last touched this artifact).
//   - Receipt present with matching RegFp, but HistoryLikelyRewrittenSince says yes
//     on content fingerprint → reprocess.
//   - Otherwise (matching regfp + stable content) → safe to skip or limit to suffix.
func ShouldReprocess(lines []string, receipt *ScrubReceipt, currentRegFp string) bool {
	if receipt == nil {
		return true
	}
	if receipt.RegFp == "" || receipt.RegFp != currentRegFp {
		return true
	}
	if HistoryLikelyRewrittenSince(lines, receipt) {
		return true
	}
	return false
}

// ComputeRegistryFingerprint returns a short, stable, opaque identifier for a
// set of known secret hashes (from the Pillar 1 registry). It is used in
// Pillar 3 receipts so future runs can detect when the set of known secrets
// has changed and a previously-scrubbed artifact may now contain new material.
//
// The fingerprint is computed by sorting the hex representations of the hashes
// and hashing the concatenation. Only the first 16 hex chars are kept for
// brevity in the receipt line. The value itself reveals nothing about the
// underlying secret material.
func ComputeRegistryFingerprint(hashes []registry.SecretHash) string {
	if len(hashes) == 0 {
		return "0"
	}
	hexes := make([]string, 0, len(hashes))
	for _, h := range hashes {
		hexes = append(hexes, fmt.Sprintf("%x", h[:]))
	}
	// Sort for stability (map iteration order is not deterministic).
	// Simple sort is fine; no external deps.
	for i := 0; i < len(hexes); i++ {
		for j := i + 1; j < len(hexes); j++ {
			if hexes[j] < hexes[i] {
				hexes[i], hexes[j] = hexes[j], hexes[i]
			}
		}
	}
	joined := strings.Join(hexes, "")
	h := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", h[:8]) // 16 hex chars, consistent with tail hash style
}

// FormatScrubReceiptV2 returns the canonical receipt line we append after a
// successful real scrub. It includes the registry fingerprint so future runs
// (even after daemon restart) can decide whether reprocessing is required.
func FormatScrubReceiptV2(lineCount int, tailHash, regFp string) string {
	return fmt.Sprintf("# blastradius-scrub-receipt:v2:lines=%d:tail=%s:regfp=%s", lineCount, tailHash, regFp)
}
