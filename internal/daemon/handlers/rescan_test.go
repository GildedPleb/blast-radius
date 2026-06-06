package handlers

import (
	"errors"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/discovery"
)

func TestRescanHandler(t *testing.T) {
	h := RescanHandler{}

	t.Run("success_no_last_rescan_result", func(t *testing.T) {
		fake := &fakeContext{now: time.Now()}
		resp, err := h.Handle("", fake)
		if err != nil {
			t.Fatalf("unexpected Handle error: %v", err)
		}
		m := resp.(map[string]any)
		if m["status"] != "ok" {
			t.Errorf("expected status=ok, got %v", m["status"])
		}
		if _, has := m["last_scan"]; !has {
			t.Error("expected last_scan from Pillar1ScanStatus")
		}
		if _, has := m["collector_results"]; has {
			t.Error("collector_results should only appear when LastPillar1Rescan() != nil")
		}
	})

	t.Run("success_with_last_rescan_result", func(t *testing.T) {
		fake := &fakeContext{now: time.Now()}
		// Non-nil pointer is enough — handler will add "collector_results"
		// using whatever the real type of CollectorResults is.
		fake.SetLastPillar1Rescan(&discovery.RescanResult{})

		resp, _ := h.Handle("", fake)
		m := resp.(map[string]any)

		if _, has := m["collector_results"]; !has {
			t.Error("expected collector_results key when LastPillar1Rescan returned non-nil")
		}
		if _, has := m["errors"]; has {
			t.Error("should not have errors key when len(Errors) == 0")
		}
	})

	t.Run("success_with_errors_in_rescan_result", func(t *testing.T) {
		fake := &fakeContext{now: time.Now()}
		res := &discovery.RescanResult{
			Errors: []string{"fs: permission denied", "git: timeout"}, // ← change to []error{} if needed
		}
		fake.SetLastPillar1Rescan(res)

		resp, _ := h.Handle("", fake)
		m := resp.(map[string]any)

		if m["errors"] == nil {
			t.Error("expected errors key when len(res.Errors) > 0")
		}
	})

	t.Run("trigger_pillar1_rescan_error", func(t *testing.T) {
		fake := &fakeContext{now: time.Now()}
		fake.SetPillar1RescanError(errors.New("rescan already running"))

		resp, err := h.Handle("", fake)
		if err != nil {
			t.Fatalf("Handle must return err=nil even on failure, got %v", err)
		}
		m := resp.(map[string]any)
		if m["status"] != "error" {
			t.Errorf("expected status=error, got %v", m["status"])
		}
		if msg, _ := m["message"].(string); msg != "rescan already running" {
			t.Errorf("expected message, got %v", m["message"])
		}
	})
}
