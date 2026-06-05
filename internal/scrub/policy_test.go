package scrub

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestParseEntry_Plain(t *testing.T) {
	e := ParseEntry("export FOO=bar")
	if e.Prefix != "" || e.Command != "export FOO=bar" {
		t.Errorf("plain entry parsed wrong: %+v", e)
	}
}

func TestParseEntry_ZshExtended(t *testing.T) {
	line := ": 1699999999:5;curl -H 'Authorization: Bearer sk-123' https://api"
	e := ParseEntry(line)
	if e.Prefix != ": 1699999999:5;" {
		t.Errorf("prefix = %q, want ': 1699999999:5;'", e.Prefix)
	}
	if !strings.Contains(e.Command, "curl") {
		t.Errorf("command portion missing: %q", e.Command)
	}
}

func TestApplyToLine_Delete(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567"
	h := registry.HashValue([]byte(secret))
	known := map[[32]byte]bool{h: true}
	det := detection.NewDetector()

	line := "export AWS_SECRET=" + secret

	r := ApplyToLine(line, known, det, ModeDelete, "[REDACTED]")
	if r.Action != "deleted" {
		t.Errorf("action = %s, want deleted", r.Action)
	}
	if r.Final != "" {
		t.Error("deleted entry should have empty Final")
	}
	if r.SecretsRedacted != 1 {
		t.Errorf("secrets = %d", r.SecretsRedacted)
	}
}

func TestApplyToLine_Redact_PreservesStructure(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
	h := registry.HashValue([]byte(secret))
	known := map[[32]byte]bool{h: true}
	det := detection.NewDetector()

	// zsh extended + secret in the command portion
	line := ": 1700000000:12;curl -H \"Authorization: Bearer " + secret + "\" https://api"

	r := ApplyToLine(line, known, det, ModeRedact, "[REDACTED]")
	if r.Action != "redacted" {
		t.Fatalf("action = %s", r.Action)
	}
	if strings.Contains(r.Final, secret) {
		t.Error("real secret still present after redact")
	}
	if !strings.HasPrefix(r.Final, ": 1700000000:12;") {
		t.Errorf("zsh prefix was stripped: %q", r.Final)
	}
	if !strings.Contains(r.Final, "[REDACTED]") {
		t.Error("placeholder missing")
	}
}

func TestApplyToLine_NoMatch_Kept(t *testing.T) {
	known := map[[32]byte]bool{}
	det := detection.NewDetector()

	line := "echo hello world"

	r := ApplyToLine(line, known, det, ModeRedact, "[REDACTED]")
	if r.Action != "kept" || r.Final != line {
		t.Error("unrelated line should be kept unchanged")
	}
}

func TestApplyBatch_Mixed(t *testing.T) {
	s1 := "AKIAREALKEY1234567890EXAMPLESECRET"
	s2 := "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABC"
	h1 := registry.HashValue([]byte(s1))
	h2 := registry.HashValue([]byte(s2))
	known := map[[32]byte]bool{h1: true, h2: true}
	det := detection.NewDetector()

	lines := []string{
		"export AWS=" + s1,
		"echo clean",
		": 123:0;openai key is " + s2,
		"ls -l",
	}

	kept, deleted, redacted, secrets := ApplyBatch(lines, known, det, ModeRedact, "[REDACTED]")

	if deleted != 0 {
		t.Errorf("deleted=%d", deleted)
	}
	if redacted != 2 {
		t.Errorf("redacted=%d", redacted)
	}
	if secrets != 2 {
		t.Errorf("secrets=%d", secrets)
	}
	// For redact mode, redacted lines are still written back (modified), so we get
	// all original lines back in the "kept" slice (some with placeholders).
	if len(kept) != 4 {
		t.Errorf("kept=%d, want 4 (all lines retained after in-place redaction)", len(kept))
	}
	// The two redacted lines should contain the placeholder and keep structure
	for _, k := range kept {
		if strings.Contains(k, "AWS=") || strings.Contains(k, "openai key") {
			if !strings.Contains(k, "[REDACTED]") {
				t.Errorf("redacted line missing placeholder: %s", k)
			}
		}
	}
}

func TestIsValidMode(t *testing.T) {
	if !IsValidMode("delete") {
		t.Error("delete should be valid")
	}
	if !IsValidMode("redact") {
		t.Error("redact should be valid")
	}
	if IsValidMode("fake") {
		t.Error("fake should be invalid")
	}
	if IsValidMode("") {
		t.Error("empty should be invalid")
	}
	if IsValidMode("DELETE") { // case sensitive on purpose
		t.Error("uppercase should be invalid")
	}
}

func TestDefaultPlaceholder(t *testing.T) {
	if DefaultPlaceholder() != "[REDACTED]" {
		t.Error("DefaultPlaceholder should return [REDACTED]")
	}
}

func TestFindLastScrubInvocation(t *testing.T) {
	lines := []string{
		"ls -l",
		"export FOO=bar",
		": 1750000000:0;blastradius scrub-history --mode=redact",
		"curl https://example.com",
		"blastradius scrub-history",
		"echo done",
	}

	idx := FindLastScrubInvocation(lines)
	if idx != 4 {
		t.Errorf("expected last scrub at index 4, got %d", idx)
	}

	// No scrub command
	noScrub := []string{"ls", "cd /tmp", "echo hi"}
	if FindLastScrubInvocation(noScrub) != -1 {
		t.Error("expected -1 when no scrub-history command present")
	}

	// Zsh extended + different invocation style
	zshLines := []string{
		": 1:0;some command",
		": 2:0;br scrub-history --dry-run",
		": 3:0;normal command",
	}
	if FindLastScrubInvocation(zshLines) != 1 {
		t.Error("failed to detect 'br scrub-history' in zsh extended format")
	}
}

func TestScrubReceipt_RoundtripAndRewriteDetection(t *testing.T) {
	// Simulate the *content* right after scrub (the "kept" we would have fingerprinted
	// before appending the receipt line itself).
	contentAtScrub := []string{
		"ls -l",
		"blastradius scrub-history --mode=redact",
		"echo after",
	}
	lineCountAtScrub, tailAtScrub := ComputeHistoryFingerprint(contentAtScrub)

	// Build a realistic post-scrub lines slice that includes the planted receipt (v2 style).
	// The receipt line itself is *after* the fingerprinted content.
	receiptLine := FormatScrubReceiptV2(lineCountAtScrub, tailAtScrub, "regfp123")
	linesWithReceipt := append(append([]string(nil), contentAtScrub...), receiptLine)

	receipt := FindLatestReceipt(linesWithReceipt)
	if receipt == nil {
		t.Fatal("expected to parse receipt")
	}
	if receipt.TailHash != tailAtScrub {
		t.Fatalf("receipt tail mismatch in test setup: %s vs %s", receipt.TailHash, tailAtScrub)
	}

	// Current file is exactly the same as when we scrubbed (receipt appended but content stable)
	// → should trust (tail matches the stored one, count matches).
	if HistoryLikelyRewrittenSince(linesWithReceipt, receipt) {
		t.Error("should trust when fingerprint (tail+count) matches")
	}

	// Simulate the shell rewriting the file and re-introducing old secrets before the marker.
	// (prepend changes count and thus tail)
	rewritten := append([]string{"export AWS_SECRET=AKIAREWRITTEN12345678901234"}, linesWithReceipt...)
	if !HistoryLikelyRewrittenSince(rewritten, receipt) {
		t.Error("prepend/rewrite should be treated as likely rewritten (tail or count change)")
	}

	// Explicit: line count drop is strong rewrite signal (trunc/restore of old content).
	short := linesWithReceipt[:1]
	if !HistoryLikelyRewrittenSince(short, receipt) {
		t.Error("count drop must be treated as likely rewritten")
	}

	// Tail mismatch with stable-ish count (e.g. in-place edit on small file or rotated sibling) → rewrite.
	edited := append([]string(nil), contentAtScrub...)
	edited[0] = "export AWS_SECRET=AKIAREWRITTEN12345678901234" // same count, different content -> different tail
	editedWithReceipt := append(append([]string(nil), edited...), receiptLine)
	// Use the original receipt (whose tail was for the clean content)
	if !HistoryLikelyRewrittenSince(editedWithReceipt, receipt) {
		t.Error("tail mismatch (stable count) must be treated as likely rewritten for edited small/rotated files")
	}
}

func TestComputeRegistryFingerprint(t *testing.T) {
	h1 := registry.SecretHash{1}
	h2 := registry.SecretHash{2}
	h3 := registry.SecretHash{3}

	fp1 := ComputeRegistryFingerprint([]registry.SecretHash{h1, h2})
	fp2 := ComputeRegistryFingerprint([]registry.SecretHash{h2, h1}) // order must not matter
	if fp1 != fp2 || fp1 == "" || fp1 == "0" {
		t.Errorf("fingerprint must be stable and non-empty, got %q vs %q", fp1, fp2)
	}

	fpEmpty := ComputeRegistryFingerprint(nil)
	if fpEmpty != "0" {
		t.Error("empty set should produce '0'")
	}

	fp3 := ComputeRegistryFingerprint([]registry.SecretHash{h1, h2, h3})
	if fp3 == fp1 {
		t.Error("different sets should produce different fingerprints")
	}
}

func TestFindLatestReceipt_FindsLastEvenIfNotNearMarker(t *testing.T) {
	lines := []string{
		"old command",
		"# blastradius-scrub-receipt:v1:lines=10:tail=deadbeef",
		"blastradius scrub-history",
		"some later line",
		"# blastradius-scrub-receipt:v2:lines=42:tail=cafebabe:regfp=abc987",
		"even later append",
	}

	r := FindLatestReceipt(lines)
	if r == nil {
		t.Fatal("expected to find a receipt")
	}
	if r.Version != 2 || r.LineCount != 42 || r.RegFp != "abc987" {
		t.Errorf("got wrong latest receipt: %+v", r)
	}
}

func TestShouldReprocess(t *testing.T) {
	lines := []string{"ls", "echo hi", "# receipt here"}
	currentFp := "deadbeef1234"

	// No receipt → must reprocess
	if !ShouldReprocess(lines, nil, currentFp) {
		t.Error("nil receipt should force reprocess")
	}

	// Matching v2 regfp + stable content → safe to skip
	// Use a receipt whose TailHash matches the actual fingerprint of these lines so
	// HistoryLikelyRewrittenSince returns false (tail match + count match + reg match).
	lc, th := ComputeHistoryFingerprint(lines)
	matching := &ScrubReceipt{Version: 2, LineCount: lc, TailHash: th, RegFp: currentFp}
	if ShouldReprocess(lines, matching, currentFp) {
		t.Error("matching regfp + no rewrite signal should allow skip")
	}

	// Stale regfp (new secrets in registry) → reprocess even with receipt present
	stale := &ScrubReceipt{Version: 2, LineCount: 3, TailHash: "xx", RegFp: "oldfp"}
	if !ShouldReprocess(lines, stale, currentFp) {
		t.Error("stale regfp must force reprocess (new secrets)")
	}

	// v1 receipt (no regfp) → reprocess so we can upgrade
	v1 := &ScrubReceipt{Version: 1, LineCount: 3, TailHash: "xx"}
	if !ShouldReprocess(lines, v1, currentFp) {
		t.Error("v1 receipt should force reprocess/upgrade")
	}
}

func TestFindScrubReceiptNear(t *testing.T) {
	// Basic setup: a scrub invocation, then a receipt 1 or 2 lines later.
	base := []string{
		"ls -l",
		"blastradius scrub-history --mode=delete",
		"# blastradius-scrub-receipt:v1:lines=5:tail=abc123",
		"some other line",
	}

	// Happy: finds v1 immediately after (j = idx+1)
	scrubIdx := 1
	r := FindScrubReceiptNear(base, scrubIdx)
	if r == nil || r.Version != 1 || r.TailHash != "abc123" || r.RegFp != "" {
		t.Errorf("expected v1 receipt near, got %+v", r)
	}

	// v2 with regfp, two lines after
	linesV2 := []string{
		"cmd before",
		"blastradius scrub-history",
		"intervening noise",
		"# blastradius-scrub-receipt:v2:lines=42:tail=cafebabe:regfp=deadbeef42",
	}
	r = FindScrubReceiptNear(linesV2, 1)
	if r == nil || r.Version != 2 || r.RegFp != "deadbeef42" {
		t.Errorf("expected v2 with regfp, got %+v", r)
	}

	// Negative: scrubIdx < 0
	if FindScrubReceiptNear(base, -1) != nil {
		t.Error("negative scrubIdx must return nil")
	}

	// Negative: not enough lines after (scrubIdx+2 >= len)
	short := []string{"only", "scrub cmd here"}
	if FindScrubReceiptNear(short, 1) != nil {
		t.Error("insufficient lines after scrubIdx must return nil")
	}

	// Negative: no receipt in the +1..+3 window
	noReceipt := []string{
		"foo",
		"blastradius scrub-history",
		"unrelated1",
		"unrelated2",
		"unrelated3",
		"later receipt but outside window",
	}
	if FindScrubReceiptNear(noReceipt, 1) != nil {
		t.Error("no receipt in the 3-line window must return nil")
	}

	// Trims whitespace on candidate lines (minimal: receipt is the immediate next + last line in file)
	ws := []string{
		"scrub-invocation",
		"   # blastradius-scrub-receipt:v2:lines=10:tail=fff:regfp=999   ",
	}
	r = FindScrubReceiptNear(ws, 0)
	if r == nil || r.RegFp != "999" {
		t.Errorf("should parse trimmed receipt line even as last line, got %+v", r)
	}

	// Explicit minimal case that the old +2 guard would have incorrectly rejected
	minimal := []string{
		"blastradius scrub-history",
		"# blastradius-scrub-receipt:v2:lines=2:tail=aa:regfp=bb",
	}
	r = FindScrubReceiptNear(minimal, 0)
	if r == nil || r.RegFp != "bb" {
		t.Errorf("must find receipt when it is the immediate next line (last in file), got %+v", r)
	}
}

func TestStripReceipts_Internal(t *testing.T) {
	// stripReceipts is unexported but same-package; covers the marker stripping used by
	// HistoryLikelyRewrittenSince before fingerprinting.
	lines := []string{
		"real cmd",
		"# blastradius-scrub-receipt:v2:lines=3:tail=xx:regfp=yy",
		"another real",
		" # blastradius-scrub-receipt:v1:lines=1:tail=zz",
		"final",
	}
	stripped := stripReceipts(lines)
	if len(stripped) != 3 {
		t.Errorf("expected 3 kept, got %d: %v", len(stripped), stripped)
	}
	if strings.Contains(strings.Join(stripped, "\n"), "blastradius-scrub-receipt") {
		t.Error("receipt markers must be stripped")
	}
}

// NEW TESTS FOR MISSING COVERAGE (append to policy_test.go)

func TestApplyToLine_EmptyLine(t *testing.T) {
	known := map[[32]byte]bool{}
	det := detection.NewDetector()

	// empty raw
	r := ApplyToLine("", known, det, ModeDelete, "[REDACTED]")
	if r.Action != "kept" || r.Final != "" {
		t.Errorf("empty line should be kept as-is, got action=%s final=%q", r.Action, r.Final)
	}

	// whitespace only (TrimSpace makes it hit the early return)
	r2 := ApplyToLine("   \t\n  ", known, det, ModeRedact, "[REDACTED]")
	if r2.Action != "kept" || r2.Final != "   \t\n  " {
		t.Errorf("whitespace-only line should be kept with original raw, got %+v", r2)
	}
}

func TestApplyToLine_EmptyCommand_ZshPrefixOnly(t *testing.T) {
	known := map[[32]byte]bool{}
	det := detection.NewDetector()

	// pure zsh extended prefix with no command after ";"  --> Command == "", hits the if scanSrc == ""
	line := ": 1699999999:5;"
	r := ApplyToLine(line, known, det, ModeRedact, "[REDACTED]")
	if r.Action != "kept" {
		t.Errorf("zsh prefix-only line should be kept, got action=%s", r.Action)
	}
	if r.Final != line {
		t.Errorf("final should equal original for kept prefix-only")
	}
}

func TestComputeHistoryFingerprint_LargeTail(t *testing.T) {
	// >64 lines to hit the tailStart = len-64 branch
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d with some command here", i)
	}

	lc, tailHash := ComputeHistoryFingerprint(lines)
	if lc != 100 {
		t.Fatalf("lineCount = %d, want 100", lc)
	}
	if tailHash == "" {
		t.Error("tailHash should be non-empty")
	}

	// Verify correctness: tail should be lines[36:]
	tailLines := lines[36:]
	expectedTailStr := strings.Join(tailLines, "\n")
	h := sha256.Sum256([]byte(expectedTailStr))
	expected := fmt.Sprintf("%x", h[:8])
	if tailHash != expected {
		t.Errorf("tailHash mismatch for large input: got %s want %s", tailHash, expected)
	}
}

func TestHistoryLikelyRewrittenSince_NilReceipt(t *testing.T) {
	// Direct test of nil branch
	lines := []string{"foo", "bar"}
	if !HistoryLikelyRewrittenSince(lines, nil) {
		t.Error("nil receipt must return true (likely rewritten)")
	}
}

func TestHistoryLikelyRewrittenSince_EmptyTailHash(t *testing.T) {
	// Cover the if receipt.TailHash != "" branch being false (skip compare)
	lines := []string{"cmd1", "cmd2"}
	lc, _ := ComputeHistoryFingerprint(lines)
	receipt := &ScrubReceipt{Version: 2, LineCount: lc, TailHash: "", RegFp: "fp"}
	if HistoryLikelyRewrittenSince(lines, receipt) {
		t.Error("receipt with empty TailHash should return false (no tail compare)")
	}
}

// TestApplyBatch_DeleteMode exercises the "deleted" case in the switch (previously uncovered in batch).
func TestApplyBatch_DeleteMode(t *testing.T) {
	s1 := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567"
	h1 := registry.HashValue([]byte(s1))
	known := map[[32]byte]bool{h1: true}
	det := detection.NewDetector()

	lines := []string{
		"export AWS_SECRET=" + s1,
		"echo clean line",
		"another clean",
	}

	kept, deleted, redacted, secrets := ApplyBatch(lines, known, det, ModeDelete, "[REDACTED]")

	if deleted != 1 {
		t.Errorf("deleted=%d, want 1", deleted)
	}
	if redacted != 0 {
		t.Errorf("redacted=%d, want 0", redacted)
	}
	if secrets != 1 {
		t.Errorf("secrets=%d, want 1", secrets)
	}
	if len(kept) != 2 {
		t.Errorf("kept=%d, want 2 (the clean lines)", len(kept))
	}
	// In delete mode we drop the bad line entirely (no placeholder kept)
	for _, k := range kept {
		if strings.Contains(k, s1) || strings.Contains(k, "AWS_SECRET") {
			t.Errorf("deleted secret line should not appear in kept: %s", k)
		}
	}
}

func TestFindLatestReceipt_None(t *testing.T) {
	// Covers the no-receipt path (full scan to return nil)
	lines := []string{
		"ls -l",
		"export FOO=bar",
		"curl https://example.com",
		"echo done",
	}
	if FindLatestReceipt(lines) != nil {
		t.Error("expected nil when no blastradius-scrub-receipt line present anywhere")
	}

	// Also empty input
	if FindLatestReceipt([]string{}) != nil {
		t.Error("expected nil for empty lines")
	}
}

// === EXACT COVERAGE FOR THE TWO REMAINING LINES ===

// Covers: HistoryLikelyRewrittenSince line "if currentCount < receipt.LineCount-5 { return true }"
func TestHistoryLikelyRewrittenSince_SignificantCountDrop(t *testing.T) {
	// Receipt claims the file had 30 lines at last scrub time
	receipt := &ScrubReceipt{
		Version:   2,
		LineCount: 30,
		TailHash:  "deadbeef",
		RegFp:     "regfp123",
	}

	// Current file only has 10 lines → dropped by more than 5
	current := make([]string, 10)
	for i := range current {
		current[i] = fmt.Sprintf("some command %d", i)
	}

	if !HistoryLikelyRewrittenSince(current, receipt) {
		t.Error("must return true when currentCount (10) < receipt.LineCount-5 (25)")
	}
}

// Covers: ShouldReprocess line "if HistoryLikelyRewrittenSince(lines, receipt) { return true }"
func TestShouldReprocess_WhenHistorySaysRewritten(t *testing.T) {
	// A stable, matching receipt (RegFp matches currentRegFp and content fingerprint would match)
	originalLines := []string{"ls -l", "echo hello", "cd /tmp"}
	lc, th := ComputeHistoryFingerprint(originalLines)
	goodReceipt := &ScrubReceipt{
		Version:   2,
		LineCount: lc,
		TailHash:  th,
		RegFp:     "matchingfp1234",
	}
	currentRegFp := "matchingfp1234"

	// Now the file has clearly changed (extra line with different content → different tail)
	rewrittenLines := append([]string{"export AWS_SECRET=AKIAREWRITTEN0123456789ABCDEF"}, originalLines...)

	if !ShouldReprocess(rewrittenLines, goodReceipt, currentRegFp) {
		t.Error("ShouldReprocess must return true when HistoryLikelyRewrittenSince detects a rewrite, even though RegFp matches")
	}
}
