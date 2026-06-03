package scrub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestLooksLikeRotatedHistory(t *testing.T) {
	stems := []string{".bash_history", ".zsh_history"}
	cases := []struct {
		name string
		want bool
	}{
		{".bash_history", false},
		{".bash_history.1", true},
		{".bash_history.old", true},
		{".bash_history.bak", true},
		{".bash_history~", true},
		{".zsh_history.2.gz", true},
		{"zsh_history.backup", true},
		{"my.history.old", true},
		{"foo.bak", false}, // no history stem
		{"other.log", false},
		{".bash_history.swp", false},
	}
	for _, c := range cases {
		if got := LooksLikeRotatedHistory(c.name, stems); got != c.want {
			t.Errorf("LooksLikeRotatedHistory(%q)=%v want %v", c.name, got, c.want)
		}
	}
}

func TestExpandPath(t *testing.T) {
	// We test via DiscoverHistoryTargets with ~ in roots, but also direct for the helper.
	// Since unexported, we exercise it through discovery with controlled HOME.
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a target under $HOME
	target := filepath.Join(home, ".bash_history")
	if err := os.WriteFile(target, []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Pass root with ~/
	got := DiscoverHistoryTargets([]string{"~/"}, nil)
	if len(got) != 1 || got[0] != target {
		t.Fatalf("Discover with ~/ root gave %v, want [%s]", got, target)
	}

	// Bare ~
	got = DiscoverHistoryTargets([]string{"~"}, nil)
	if len(got) != 1 || got[0] != target {
		t.Fatalf("Discover with ~ root gave %v, want [%s]", got, target)
	}
}

func TestDiscoverHistoryTargets_Basic(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, ".bash_history")
	rot := filepath.Join(root, ".bash_history.1")
	extra := filepath.Join(root, "my_custom")
	non := filepath.Join(root, "notes.txt")

	for _, p := range []string{live, rot, extra, non} {
		if err := os.WriteFile(p, []byte("line\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// HISTFILE takes priority
	histfile := filepath.Join(root, "from_histfile")
	if err := os.WriteFile(histfile, []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HISTFILE", histfile)

	got := DiscoverHistoryTargets([]string{root}, []string{extra})
	// Should include HISTFILE + live + rot (from ReadDir) + extra; not non
	wantContains := map[string]bool{
		histfile: true,
		live:     true,
		rot:      true,
		extra:    true,
	}
	if len(got) < 3 {
		t.Fatalf("got too few targets: %v", got)
	}
	for _, g := range got {
		if !wantContains[g] && g == non {
			t.Errorf("unexpectedly included non-history file: %s", g)
		}
	}
	// Sorted
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("not sorted: %v", got)
		}
	}
}

func TestDiscoverHistoryTargets_NoRootsUsesHOME(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	live := filepath.Join(root, ".zsh_history")
	if err := os.WriteFile(live, []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got := DiscoverHistoryTargets(nil, nil)
	if len(got) != 1 || got[0] != live {
		t.Fatalf("Discover(nil, nil) under HOME gave %v, want [%s]", got, live)
	}
}

func TestProcessHistory_SkipWhenReceiptMatches(t *testing.T) {
	contentAtScrub := []string{
		"echo hello",
		": 123:0;secret cmd",
	}
	lc, tail := ComputeHistoryFingerprint(contentAtScrub)
	receipt := FormatScrubReceiptV2(lc, tail, "deadbeef0123")
	lines := append(append([]string(nil), contentAtScrub...), receipt)

	allHashes := []registry.SecretHash{} // no secrets now
	currentRegFp := "deadbeef0123"

	res := ProcessHistory(lines, allHashes, currentRegFp, ModeDelete, "[REDACTED]", false, false)
	if !res.Skipped || res.SkippedReason != "receipt+regfp" {
		t.Fatalf("expected skip receipt+regfp, got %+v", res)
	}
}

func TestProcessHistory_FullForcesProcess(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567"
	h := registry.HashValue([]byte(secret))
	lines := []string{
		"export FOO=" + secret,
		"echo ok",
	}
	allHashes := []registry.SecretHash{h}
	currentRegFp := "somefp"

	res := ProcessHistory(lines, allHashes, currentRegFp, ModeDelete, "[REDACTED]", true, false)
	if res.Skipped {
		t.Fatal("full=true should not skip")
	}
	if res.Deleted != 1 {
		t.Errorf("deleted=%d want 1", res.Deleted)
	}
	if res.Processed != len(lines) {
		t.Errorf("processed=%d want %d (full file for --full)", res.Processed, len(lines))
	}
	if strings.Contains(strings.Join(res.Kept, "\n"), secret) {
		t.Error("secret should have been deleted from kept")
	}
	// For delete mode the resulting kept slice is shorter (removed lines are not present)
	if len(res.Kept) != 1 {
		t.Errorf("len(kept)=%d after delete (expected the non-matching line only)", len(res.Kept))
	}
}

func TestProcessHistory_RewrittenSinceLastReceipt(t *testing.T) {
	secret := "sk-1234567890abcdef1234567890abcdef"
	h := registry.HashValue([]byte(secret))
	// Simulate previous scrub left a receipt on some content, then the file was edited
	// (different tail now).
	contentAtScrub := []string{
		"old line",
		"some other",
	}
	lc, tail := ComputeHistoryFingerprint(contentAtScrub)
	receipt := FormatScrubReceiptV2(lc, tail, "oldfp")

	// Current lines are different (user added the secret after the old scrub point)
	currentLines := []string{
		"old line",
		": 999:0;curl -H 'Auth: " + secret + "'",
	}
	lines := append(append([]string(nil), currentLines...), receipt)
	allHashes := []registry.SecretHash{h}
	// Use matching regfp so that the "rewritten since" (tail mismatch) path is what triggers reprocess.
	currentRegFp := "oldfp"

	res := ProcessHistory(lines, allHashes, currentRegFp, ModeRedact, "[REDACTED]", false, false)
	if res.Skipped {
		t.Fatal("should process because history was rewritten since receipt (tail mismatch)")
	}
	if res.Redacted != 1 {
		t.Errorf("redacted=%d want 1", res.Redacted)
	}
	if res.Processed == 0 {
		t.Error("expected Processed > 0 (range was reprocessed due to rewrite)")
	}
}

func TestProcessHistory_DryRunPreview(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"
	h := registry.HashValue([]byte(secret))
	lines := []string{
		"echo before",
		"export TOKEN=" + secret,
		"echo after",
	}
	allHashes := []registry.SecretHash{h}
	currentRegFp := "fp"

	res := ProcessHistory(lines, allHashes, currentRegFp, ModeRedact, "[REDACTED]", true, true)
	if res.Skipped {
		t.Fatal("should not skip on dry full")
	}
	if res.Preview == nil {
		t.Fatal("expected preview on dryRun")
	}
	if wd, ok := res.Preview["would_redact"].(int); !ok || wd != 1 {
		t.Errorf("preview would_redact = %v want 1", res.Preview["would_redact"])
	}
	examples, _ := res.Preview["example_scrubbed_lines"].([]string)
	if len(examples) == 0 {
		t.Error("expected example_scrubbed_lines in preview")
	}
}

func TestProcessHistory_NoSecrets_Kept(t *testing.T) {
	lines := []string{"echo clean", "ls -l"}
	allHashes := []registry.SecretHash{}
	res := ProcessHistory(lines, allHashes, "fp", ModeDelete, "[REDACTED]", false, false)
	if res.Skipped {
		t.Fatal("no receipt, should process even if 0 secrets")
	}
	if res.Deleted+res.Redacted != 0 {
		t.Error("should report 0 changes")
	}
	if len(res.Kept) != 2 {
		t.Error("kept should be original")
	}
}

func TestBuildDryRunPreview(t *testing.T) {
	orig := []string{"line1", "secretline", "line3"}
	kept := []string{"line1", "[REDACTED]", "line3"}
	preview := buildDryRunPreview(orig, kept, 0, 1, 1, "[REDACTED]")
	if preview["would_redact"] != 1 {
		t.Error("would_redact")
	}
	ex, ok := preview["example_scrubbed_lines"].([]string)
	if !ok || len(ex) != 1 || !strings.Contains(ex[0], "[REDACTED]") {
		t.Errorf("example_scrubbed_lines = %v", preview["example_scrubbed_lines"])
	}
}
