package scrub

import (
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
	h1 := [32]byte{1}
	h2 := [32]byte{2}
	h3 := [32]byte{3}

	fp1 := ComputeRegistryFingerprint([][32]byte{h1, h2})
	fp2 := ComputeRegistryFingerprint([][32]byte{h2, h1}) // order must not matter
	if fp1 != fp2 || fp1 == "" || fp1 == "0" {
		t.Errorf("fingerprint must be stable and non-empty, got %q vs %q", fp1, fp2)
	}

	fpEmpty := ComputeRegistryFingerprint(nil)
	if fpEmpty != "0" {
		t.Error("empty set should produce '0'")
	}

	fp3 := ComputeRegistryFingerprint([][32]byte{h1, h2, h3})
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
