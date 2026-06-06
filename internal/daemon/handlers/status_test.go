package handlers

import (
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/discovery"
)

func TestStatusHandler(t *testing.T) {
	f := &fakeContext{
		snapshot: map[string]int{"count": 3},
		now:      time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
	}
	h := StatusHandler{}
	resp, err := h.Handle("", f)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" || m["registry"] == nil {
		t.Errorf("unexpected status response: %+v", m)
	}
	// Exercise Pillar5 clipboard state (from monitor) in the handler response
	if _, ok := m["pillar5"]; !ok {
		t.Error("expected pillar5 key in status response from fakeContext")
	}
}

func TestStatusHandler1(t *testing.T) {
	h := StatusHandler{}

	t.Run("full_status_with_all_pillars", func(t *testing.T) {
		f := &fakeContext{
			snapshot: map[string]any{"projects": 3, "secrets": 12},
			now:      time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			crumbs:   map[string]any{"findings": 0, "last_scan": "2026-05-25T12:00:00Z"},
		}
		// Just a non-nil pointer is enough — handler will add the key using whatever
		// the real type of CollectorResults is.
		f.SetLastPillar1Rescan(&discovery.RescanResult{})

		resp, err := h.Handle("", f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := resp.(map[string]any)

		if m["status"] != "ok" {
			t.Errorf("expected status=ok, got %v", m["status"])
		}

		// pillar2
		if _, ok := m["pillar2"]; !ok {
			t.Error("expected pillar2")
		}

		// pillar1 + inner LastPillar1Rescan branch
		p1 := m["pillar1"].(map[string]any)
		if _, has := p1["collector_results"]; !has {
			t.Error("expected collector_results key inside pillar1")
		}

		// pillar5
		if _, ok := m["pillar5"]; !ok {
			t.Error("expected pillar5")
		}
	})

	t.Run("minimal_no_crumbs_no_last_rescan", func(t *testing.T) {
		f := &fakeContext{
			snapshot: nil,
			now:      time.Now().UTC(),
			// crumbs == nil  → CrumbsSummary returns nil → no "pillar2"
			// LastPillar1Rescan returns nil by default → no collector_results inside pillar1
		}

		resp, _ := h.Handle("", f)
		m := resp.(map[string]any)

		if _, has := m["pillar2"]; has {
			t.Error("should not have pillar2 when CrumbsSummary returned nil")
		}

		p1 := m["pillar1"].(map[string]any)
		if _, has := p1["collector_results"]; has {
			t.Error("should not have collector_results when LastPillar1Rescan returned nil")
		}
	})
}
