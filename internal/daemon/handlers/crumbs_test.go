package handlers

import (
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/residue"
)

func TestCrumbsHandler_Basic(t *testing.T) {
	h := CrumbsHandler{}
	fake := &fakeContext{
		crumbsResult: &residue.ScanResult{
			Findings: []residue.ResidueFinding{
				{Location: "Downloads/creds.json", Format: residue.FormatBitwardenJSON, KnownMatches: 2, EntropyHits: 5, Confidence: residue.ConfHigh},
			},
			ScannedDirs:   3,
			FilesExamined: 420,
			Duration:      12 * time.Millisecond,
			Timestamp:     time.Now().UTC(),
		},
	}
	resp, err := h.Handle("", fake)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" {
		t.Errorf("status = %v", m["status"])
	}
	if int(m["total"].(int)) != 1 { // note: json numbers come as float64 in real, but direct call is int? wait, our handler uses literal
		// actually in Go direct it's int from len; in real JSON it's float64. Test the count key.
	}
	total := m["total"]
	if total != 1 && total != float64(1) {
		t.Errorf("total = %v (type %T)", total, total)
	}
}

func TestCrumbsHandler_DisabledPath(t *testing.T) {
	h := CrumbsHandler{}
	// When manager returns the disabled marker, handler should still succeed with status ok/partial
	fake := &fakeContext{
		crumbsResult: &residue.ScanResult{
			Findings: []residue.ResidueFinding{},
			Errors:   []string{"pillar2.enabled is false"},
		},
	}
	resp, err := h.Handle("", fake)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] == "error" {
		t.Error("handler should not turn disabled into hard error")
	}
}
