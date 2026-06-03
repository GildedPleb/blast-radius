package residue

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/policy"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// test hook to control UserHomeDir for fast coverage of len(targets)==0 without walking real home.
var userHomeDir = os.UserHomeDir

// test hook for filepath.Abs (used in effectiveP2Surfaces) to cover the error-continue path.
var filepathAbs = filepath.Abs

// Manager owns the residue (crumbs) scanning logic and last result cache.
// Scans are on-demand only.
//
// last/lastScan are published under lastMu after each scan (compute-then-publish
// to keep readers non-blocking during long walks). Concurrent RunScan calls are
// allowed (each performs full work; last writer wins for the published snapshot).
//
// Configuration: cfg.Pillar2 (enabled + dirs[] with per-dir files[]). Skip/ignore
// lists are read from cfg.GetEnvOptions() (the Pillar 1 hygiene lists).
type Manager struct {
	cfg      *config.Config
	reg      *registry.Registry
	last     *ScanResult
	lastScan time.Time
	lastMu   sync.RWMutex // protects last + lastScan for concurrent STATUS/CRUMBS + bg writers
}

// NewManager creates a residue manager.
func NewManager(cfg *config.Config, reg *registry.Registry) *Manager {
	return &Manager{
		cfg: cfg,
		reg: reg,
	}
}

// RunScan performs a fresh scan of all configured dirs[] surfaces (if enabled).
// Returns a result even when disabled (empty findings + status info).
// Errors are collected per-dir/file and never abort the whole scan.
func (m *Manager) RunScan() *ScanResult {
	start := time.Now()
	res := &ScanResult{
		Findings:  []ResidueFinding{},
		Timestamp: start.UTC(),
		Errors:    []string{},
	}

	if m.cfg == nil || !m.cfg.Pillar2.Enabled {
		res.Duration = time.Since(start)
		res.Errors = append(res.Errors, "pillar2.enabled is false")
		m.lastMu.Lock()
		m.last = res
		m.lastScan = start
		m.lastMu.Unlock()
		return res
	}

	// Reuse the single source of truth for scan hygiene (skip/ignore lists) from
	// cfg.GetEnvOptions() (the Pillar 1 env source options; the authority for
	// what to skip/ignore during P2 crumb hunts).
	envOpts := m.cfg.GetEnvOptions()
	ignoreFiles := envOpts.IgnoreFiles
	if len(ignoreFiles) == 0 {
		ignoreFiles = []string{".gitignore", ".blastradiusignore"}
	}

	skipDirs := make(map[string]bool)
	for _, d := range envOpts.SkipDirs {
		skipDirs[d] = true
	}
	// always add a few more for residue surface safety/performance
	for _, extra := range []string{"node_modules", ".git", "Library", "Applications"} {
		skipDirs[extra] = true
	}

	scanned := 0
	examined := 0

	// Build effective P2 surfaces (dirs[] + per-dir files[]).
	// Each surface carries its own files[] patterns so different locations can have different rules.
	surfaces := effectiveP2Surfaces(m.cfg.Pillar2)

	// The Classifier is the single source of truth for "P1 authority wins".
	// It is consulted on every file before we spend time on detection.
	// This is what makes the three supported P2 interactions (and "P1 overrides P2") work.
	classifier := policy.New(m.cfg)

	for _, surf := range surfaces {
		abs := surf.absDir

		// per-root ignore matcher (reuses discovery logic exactly)
		ign := discovery.NewIgnoreMatcher(abs, ignoreFiles)

		walkErr := filepath.WalkDir(abs, func(path string, de os.DirEntry, err error) error {
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

			// === P1 authority + P2 surface gate (single source of truth) ===
			// The Classifier already performed the full decision:
			// - Is this path claimed by an active P1 env source?
			// - Is this path under a configured P2 surface?
			// - Does it match that surface's files[] patterns (including broad **/*)?
			// If ShouldTreatFileAsCrumb returns false, we must skip it.
			if treat, _ := classifier.ShouldTreatFileAsCrumb(path); !treat {
				return nil
			}

			examined++

			finding, scanErr := ScanFile(path, m.reg)
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
		if walkErr != nil {
			res.Errors = append(res.Errors, "walk "+abs+": "+walkErr.Error())
		}
	}

	res.ScannedDirs = scanned
	res.FilesExamined = examined
	res.Duration = time.Since(start)

	m.lastMu.Lock()
	m.last = res
	m.lastScan = start
	m.lastMu.Unlock()
	logging.Printf("Crumbs scan complete: %d findings, %d dirs, %d files, %v", len(res.Findings), scanned, examined, res.Duration)
	return res
}

// Note: Only the dirs[] + files[] shape is supported.

// GetLastResult returns the most recent scan (or nil). Does not trigger a new scan.
func (m *Manager) GetLastResult() *ScanResult {
	m.lastMu.RLock()
	defer m.lastMu.RUnlock()
	return m.last
}

// CrumbsSummary returns a tiny map for status embedding (count + recency only).
// Full findings list is only exposed via the dedicated CRUMBS command.
func (m *Manager) CrumbsSummary() map[string]any {
	m.lastMu.RLock()
	defer m.lastMu.RUnlock()
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

// p2Surface is an internal helper representing one configured hunting surface
// (from the dirs[] shape).
type p2Surface struct {
	absDir string
	files  []string // per-dir file patterns (empty = broad "everything under this dir")
}

// effectiveP2Surfaces returns the list of directories + their file patterns
// that Pillar 2 should consider. Only the dirs[] shape is supported
// (only the dirs[] shape is supported).
//
// Entries with the same canonical absDir are deduplicated. Their files[]
// patterns are merged (union) so that overlapping user configuration
// does not cause duplicate walks or duplicate findings.
func effectiveP2Surfaces(p2 config.Pillar2Config) []p2Surface {
	type set map[string]struct{}
	byDir := make(map[string]set) // absDir -> set of patterns
	order := make([]string, 0)    // first-seen order for determinism

	for _, d := range p2.Dirs {
		if d.Path == "" {
			continue
		}
		abs, err := filepathAbs(util.ExpandPath(d.Path))
		if err != nil {
			continue
		}
		if _, seen := byDir[abs]; !seen {
			order = append(order, abs)
			byDir[abs] = make(set)
		}
		for _, pat := range d.Files {
			byDir[abs][pat] = struct{}{}
		}
	}

	out := make([]p2Surface, 0, len(order))
	for _, abs := range order {
		files := make([]string, 0, len(byDir[abs]))
		for pat := range byDir[abs] {
			files = append(files, pat)
		}
		// Sort for deterministic output (nice for tests and logs)
		sort.Strings(files)
		out = append(out, p2Surface{absDir: abs, files: files})
	}
	return out
}
