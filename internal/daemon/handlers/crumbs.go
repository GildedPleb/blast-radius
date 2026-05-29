package handlers

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/logging"
)

type CrumbsHandler struct{}

func (CrumbsHandler) Name() string { return "CRUMBS" }

func (CrumbsHandler) Handle(_ string, d DaemonContext) (any, error) {
	logging.Println("Handling CRUMBS request (Pillar 2)")

	res := d.RunCrumbsScan()
	if res == nil {
		return map[string]any{
			"status":  "error",
			"message": "no scan result",
		}, nil
	}

	// Convert findings to serializable form (keep structs but map for consistency with other handlers)
	findings := make([]map[string]any, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, map[string]any{
			"location":      f.Location,
			"basename":      f.Basename,
			"last_mod":      f.LastMod.Format(time.RFC3339),
			"format":        f.Format,
			"confidence":    f.Confidence,
			"known_matches": f.KnownMatches,
			"entropy_hits":  f.EntropyHits,
			"size":          f.Size,
		})
	}

	status := "ok"
	if len(res.Errors) > 0 && len(res.Findings) == 0 {
		status = "partial"
	}

	return map[string]any{
		"status":         status,
		"findings":       findings,
		"total":          len(res.Findings),
		"scanned_dirs":   res.ScannedDirs,
		"files_examined": res.FilesExamined,
		"duration_ms":    res.Duration.Milliseconds(),
		"timestamp":      res.Timestamp.Format(time.RFC3339),
		"errors":         res.Errors,
	}, nil
}

// Note: when residue_hunter.enabled=false, RunCrumbsScan still succeeds and returns
// a clean result with "disabled" marker inside the manager (no error, no scan performed).
// The handler surfaces it via the normal response shape.
