package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

// withTempHistory creates a temporary file with the given content and returns
// its path. The file lives under t.TempDir so it is cleaned up automatically.
func withTempHistory(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test_history")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp history file: %v", err)
	}
	return p
}

func TestScrubHistoryHandler_NoFile(t *testing.T) {
	orig := findHistoryFileFn
	findHistoryFileFn = func() string { return "" }
	defer func() { findHistoryFileFn = orig }()

	h := ScrubHistoryHandler{}
	resp, err := h.Handle("", &fakeContext{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.(map[string]any)["status"] != "error" {
		t.Error("expected error when no history file")
	}
}

func TestScrubHistoryHandler_RealFindHistoryFile(t *testing.T) {
	// Create a real history file on disk
	histPath := withTempHistory(t, "# some zsh history\nls\ncd /\n")
	t.Setenv("HISTFILE", histPath)
	// Ensure HOME variants would also work, but HISTFILE takes precedence in realFindHistoryFile

	orig := findHistoryFileFn
	findHistoryFileFn = realFindHistoryFile
	defer func() { findHistoryFileFn = orig }()

	h := ScrubHistoryHandler{}
	resp, err := h.Handle("", &fakeContext{})
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" {
		t.Errorf("expected ok when history file exists but no matches, got %v", m)
	}
	if m["lines_removed"] != 0 {
		t.Errorf("expected 0 lines removed, got %v", m["lines_removed"])
	}
}

func TestScrubHistoryHandler_RemovesMatchingLines(t *testing.T) {
	// Real secrets (as they would actually appear in shell history)
	secret1 := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567"
	secret2 := "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"

	// The context provides the *hashes* of the real secrets (exactly like the daemon does in production)
	h1 := registry.HashValue([]byte(secret1))
	h2 := registry.HashValue([]byte(secret2))

	// Realistic history content containing the *actual secret values* in common dangerous patterns.
	// The old implementation would have completely failed to detect these.
	content := "# zsh history\n" +
		"export AWS_SECRET_ACCESS_KEY=" + secret1 + "\n" + // should be removed
		"echo hello\n" +
		"curl -H \"Authorization: Bearer " + secret2 + "\" https://api.github.com\n" + // should be removed
		"ls -la\n" +
		"some-other-command --token=" + secret1 + "\n" // should be removed

	histPath := withTempHistory(t, content)

	orig := findHistoryFileFn
	findHistoryFileFn = func() string { return histPath }
	defer func() { findHistoryFileFn = orig }()

	ctx := &fakeContext{
		hashes: [][32]byte{h1, h2},
	}

	h := ScrubHistoryHandler{}
	resp, err := h.Handle("", ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" {
		t.Fatalf("expected ok, got %v (message=%v)", m["status"], m["message"])
	}
	if m["lines_removed"] != 3 {
		t.Errorf("expected 3 lines removed, got %v", m["lines_removed"])
	}
	if m["file"] != histPath {
		t.Errorf("file in response = %v, want %s", m["file"], histPath)
	}

	// Verify the file was actually rewritten without the real secret values
	data, err := os.ReadFile(histPath)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := string(data)
	if strings.Contains(cleaned, secret1) || strings.Contains(cleaned, secret2) {
		t.Errorf("history file still contains real secret values after scrub:\n%s", cleaned)
	}
	if m["original_lines"] == nil {
		t.Error("expected original_lines to be present in success response")
	}
}

func TestScrubHistoryHandler_NoSensitiveLinesFound(t *testing.T) {
	// File exists and is readable, but none of the hashes match
	histPath := withTempHistory(t, "export FOO=bar\nls\ncd ~\n")

	orig := findHistoryFileFn
	findHistoryFileFn = func() string { return histPath }
	defer func() { findHistoryFileFn = orig }()

	// Put some unrelated hash in the context (simulates a registry that doesn't contain the secrets in this history)
	var unrelated [32]byte
	for i := range unrelated {
		unrelated[i] = 0x42
	}
	ctx := &fakeContext{hashes: [][32]byte{unrelated}}

	h := ScrubHistoryHandler{}
	resp, err := h.Handle("", ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" {
		t.Errorf("expected ok, got %v", m["status"])
	}
	if m["lines_removed"] != 0 {
		t.Errorf("expected 0 lines removed, got %v", m["lines_removed"])
	}
	if m["message"] == nil || m["message"].(string) == "" {
		t.Error("expected a message when nothing was removed")
	}
}
