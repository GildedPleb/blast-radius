package handlers

import "testing"

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

// Note: full integration test of actual scrubbing is covered by cli/scrub-history_test.go
