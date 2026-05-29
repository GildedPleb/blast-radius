package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	secret := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567"
	sum := sha256.Sum256([]byte(secret))
	hashHex := hex.EncodeToString(sum[:])

	content := "# zsh history\n" +
		"export AWS_SECRET=" + hashHex + "\n" + // should be removed
		"echo hello\n" +
		"some-command --token=" + hashHex + " --other\n" + // should be removed
		"ls -la\n"

	histPath := withTempHistory(t, content)

	orig := findHistoryFileFn
	findHistoryFileFn = func() string { return histPath }
	defer func() { findHistoryFileFn = orig }()

	ctx := &fakeContext{
		hashes: [][32]byte{sum},
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
	if m["lines_removed"] != 2 {
		t.Errorf("expected 2 lines removed, got %v", m["lines_removed"])
	}
	if m["file"] != histPath {
		t.Errorf("file in response = %v, want %s", m["file"], histPath)
	}

	// Verify the file was actually rewritten without the sensitive lines
	data, err := os.ReadFile(histPath)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := string(data)
	if strings.Contains(cleaned, hashHex) {
		t.Errorf("history file still contains the sensitive hash after scrub:\n%s", cleaned)
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

	// Put some unrelated hash in the context
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
