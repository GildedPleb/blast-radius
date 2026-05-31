package residue

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// test hook to control UserHomeDir for fast coverage of len(targets)==0 without walking real home.
var userHomeDir = os.UserHomeDir

// Manager owns the residue (crumbs) scanning logic and last result cache.
// Scans are on-demand only (no background goroutine per v1 plan decision).
type Manager struct {
	cfg      *config.Config
	reg      *registry.Registry
	last     *ScanResult
	lastScan time.Time
}

// NewManager creates a residue manager.
func NewManager(cfg *config.Config, reg *registry.Registry) *Manager {
	return &Manager{
		cfg: cfg,
		reg: reg,
	}
}

// RunScan performs a fresh scan of all configured target_dirs (if enabled).
// Returns a result even when disabled (empty findings + status info).
// Errors are collected per-dir/file and never abort the whole scan.
func (m *Manager) RunScan() *ScanResult {
	start := time.Now()
	res := &ScanResult{
		Findings:  []ResidueFinding{},
		Timestamp: start.UTC(),
		Errors:    []string{},
	}

	if m.cfg == nil || !m.cfg.ResidueHunter.Enabled {
		res.Duration = time.Since(start)
		res.Errors = append(res.Errors, "residue_hunter.enabled is false")
		m.last = res
		m.lastScan = start
		return res
	}

	targets := m.cfg.ResidueHunter.TargetDirs
	if len(targets) == 0 {
		// sensible defaults even if user left the list empty
		home, _ := userHomeDir()
		targets = []string{
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
		}
	}

	ignoreFiles := m.cfg.IgnoreFiles
	if len(ignoreFiles) == 0 {
		ignoreFiles = []string{".gitignore", ".blastradiusignore"}
	}

	skipDirs := make(map[string]bool)
	for _, d := range m.cfg.SkipDirs {
		skipDirs[d] = true
	}
	// always add a few more for residue surface safety/performance
	for _, extra := range []string{"node_modules", ".git", "Library", "Applications"} {
		skipDirs[extra] = true
	}

	scanned := 0
	examined := 0

	for _, raw := range targets {
		expanded := expandPath(raw)
		abs, err := filepath.Abs(expanded)
		if err != nil {
			res.Errors = append(res.Errors, "bad target: "+raw)
			continue
		}

		// per-root ignore matcher (reuses discovery logic exactly)
		ign := discovery.NewIgnoreMatcher(abs, ignoreFiles)

		err = filepath.WalkDir(abs, func(path string, de os.DirEntry, err error) error {
			if err != nil {
				res.Errors = append(res.Errors, path+": "+err.Error())
				return nil
			}
			if de.IsDir() {
				base := filepath.Base(path)
				if skipDirs[base] {
					return filepath.SkipDir
				}
				if ign.ShouldIgnore(path) {
					return filepath.SkipDir
				}
				scanned++
				return nil
			}

			// regular file
			if ign.ShouldIgnore(path) {
				return nil
			}
			examined++

			finding, scanErr := ScanFile(path, m.cfg.ResidueHunter, m.reg)
			if scanErr != nil {
				// per-file errors are soft
				res.Errors = append(res.Errors, path+": "+scanErr.Error())
				return nil
			}
			if finding != nil {
				res.Findings = append(res.Findings, *finding)
			}
			return nil
		})
		if err != nil {
			res.Errors = append(res.Errors, "walk "+abs+": "+err.Error())
		}
	}

	res.ScannedDirs = scanned
	res.FilesExamined = examined
	res.Duration = time.Since(start)

	m.last = res
	m.lastScan = start
	logging.Printf("Crumbs scan complete: %d findings, %d dirs, %d files, %v", len(res.Findings), scanned, examined, res.Duration)
	return res
}

// GetLastResult returns the most recent scan (or nil). Does not trigger a new scan.
func (m *Manager) GetLastResult() *ScanResult {
	return m.last
}

// CrumbsSummary returns a tiny map for status embedding (count + recency only).
// Full findings list is only exposed via the dedicated CRUMBS command.
func (m *Manager) CrumbsSummary() map[string]any {
	if m.last == nil {
		return map[string]any{
			"status": "never_scanned",
			"count":  0,
		}
	}
	age := time.Since(m.lastScan).Round(time.Second)
	return map[string]any{
		"status":    "ok",
		"count":     len(m.last.Findings),
		"last_scan": m.last.Timestamp.Format(time.RFC3339),
		"age":       age.String(),
		"examined":  m.last.FilesExamined,
		"scanned":   m.last.ScannedDirs,
		"sample":    firstFewLocations(m.last.Findings, 3),
	}
}

func firstFewLocations(findings []ResidueFinding, n int) []string {
	out := make([]string, 0, n)
	for i, f := range findings {
		if i >= n {
			break
		}
		out = append(out, f.Location)
	}
	return out
}

// expandPath duplicates the tiny helper from discovery/manager.go (KISS per plan —
// no new internal/util package until 3+ call sites exist).
func expandPath(path string) string {
	if path == "~" || path == "~/" {
		if h := os.Getenv("HOME"); h != "" {
			return h
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if h := os.Getenv("HOME"); h != "" {
			return filepath.Join(h, path[2:])
		}
	}
	return path
}
