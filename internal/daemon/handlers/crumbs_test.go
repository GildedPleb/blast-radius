package handlers

import (
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/residue"
)

func TestCrumbsHandler(t *testing.T) {
	h := CrumbsHandler{}

	t.Run("nil_scan_result", func(t *testing.T) {
		fake := &fakeContext{}
		fake.SetCrumbsResultNil()

		resp, err := h.Handle("", fake)
		if err != nil {
			t.Fatalf("Handle should return err=nil: %v", err)
		}
		m := resp.(map[string]any)
		if m["status"] != "error" {
			t.Errorf("expected status=error, got %v", m["status"])
		}
		if m["message"] != "no scan result" {
			t.Errorf("expected message, got %v", m["message"])
		}
	})

	t.Run("success_with_findings", func(t *testing.T) {
		fake := &fakeContext{
			crumbsResult: &residue.ScanResult{
				Findings: []residue.ResidueFinding{
					{
						Location:     "Downloads/creds.json",
						Basename:     "creds.json",
						LastMod:      time.Now().UTC(),
						Format:       residue.FormatBitwardenJSON,
						Confidence:   residue.ConfHigh,
						KnownMatches: 2,
						EntropyHits:  5,
						Size:         1234,
					},
				},
				ScannedDirs:   3,
				FilesExamined: 420,
				Duration:      12 * time.Millisecond,
				Timestamp:     time.Now().UTC(),
			},
		}

		resp, err := h.Handle("", fake)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := resp.(map[string]any)

		if m["status"] != "ok" {
			t.Errorf("expected status=ok, got %v", m["status"])
		}
		if total, ok := m["total"].(int); !ok || total != 1 {
			t.Errorf("expected total=1 (int), got %T %v", m["total"], m["total"])
		}
		if findings, ok := m["findings"].([]map[string]any); !ok || len(findings) != 1 {
			t.Errorf("expected 1 finding, got %T %v", m["findings"], m["findings"])
		}
	})

	t.Run("partial_when_errors_but_no_findings", func(t *testing.T) {
		fake := &fakeContext{
			crumbsResult: &residue.ScanResult{
				Findings:  []residue.ResidueFinding{},
				Errors:    []string{"pillar2.enabled is false"},
				Timestamp: time.Now().UTC(),
			},
		}

		resp, _ := h.Handle("", fake)
		m := resp.(map[string]any)
		if m["status"] != "partial" {
			t.Errorf("expected status=partial, got %v", m["status"])
		}
	})

	t.Run("ok_when_errors_but_has_findings", func(t *testing.T) {
		// Covers the `&& len(res.Findings) == 0` short-circuit in status logic
		fake := &fakeContext{
			crumbsResult: &residue.ScanResult{
				Findings: []residue.ResidueFinding{
					{
						Location:   "secret.txt",
						Format:     residue.FormatBitwardenJSON,
						Confidence: residue.ConfHigh,
					},
				},
				Errors:    []string{"some warning during scan"},
				Timestamp: time.Now().UTC(),
			},
		}

		resp, _ := h.Handle("", fake)
		m := resp.(map[string]any)
		if m["status"] != "ok" {
			t.Errorf("expected status=ok (findings present), got %v", m["status"])
		}
	})

	t.Run("empty_findings_no_errors", func(t *testing.T) {
		fake := &fakeContext{
			crumbsResult: &residue.ScanResult{
				Findings:  []residue.ResidueFinding{},
				Errors:    nil,
				Timestamp: time.Now().UTC(),
			},
		}

		resp, _ := h.Handle("", fake)
		m := resp.(map[string]any)
		if m["status"] != "ok" {
			t.Errorf("expected status=ok, got %v", m["status"])
		}
	})

	t.Run("default_crumbs_scan_fallback", func(t *testing.T) {
		// Fresh fake with nothing set for crumbs → hits the default return
		fake := &fakeContext{}

		resp, err := h.Handle("", fake)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := resp.(map[string]any)

		if m["status"] != "ok" {
			t.Errorf("expected status=ok with default scan result, got %v", m["status"])
		}
		if total, ok := m["total"].(int); !ok || total != 0 {
			t.Errorf("expected total=0, got %T %v", m["total"], m["total"])
		}
		// findings should be empty slice (not nil)
		if findings, ok := m["findings"].([]map[string]any); !ok || len(findings) != 0 {
			t.Errorf("expected empty findings slice, got %T %v", m["findings"], m["findings"])
		}
	})
}
