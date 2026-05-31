package handlers

import (
	"testing"
	"time"
)

func TestRescanHandler(t *testing.T) {
	fake := &fakeContext{
		now: time.Now(),
	}

	h := RescanHandler{}
	resp, err := h.Handle("", fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("expected map response, got %T", resp)
	}
	if m["status"] != "ok" {
		t.Errorf("expected status ok, got %v", m["status"])
	}
}
