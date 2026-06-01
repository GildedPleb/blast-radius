package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/sources"
)

// Manager coordinates discovery.
// It owns the mapping from opaque ProjectID → display name.
type Manager struct {
	scanner  *Scanner
	registry *registry.Registry
	cfg      *config.Config

	// projectMeta maps opaque ProjectID -> human friendly display name.
	// This is the only place that knows the real filesystem location.
	projectMeta map[registry.ProjectID]string

	lastScan time.Time // time of most recent initial scan or manual rescan

	// collectors holds the active logical sources for Pillar 1 (env, bitwarden, etc.).
	// This is the foundation of the "logical layer".
	collectors []sources.Collector

	lastRescan *RescanResult // most recent manual rescan result (for rich output)
}

// NewManager creates a DiscoveryManager.
func NewManager(cfg *config.Config, reg *registry.Registry) *Manager {
	m := &Manager{
		registry:    reg,
		cfg:         cfg,
		projectMeta: make(map[registry.ProjectID]string),
	}

	scanner := NewScanner(cfg, reg)
	scanner.onProjectDiscovered = m.registerProject
	m.scanner = scanner

	// Initialize logical layer collectors (Phase 4).
	// We start with EnvCollector. Bitwarden will be added when its implementation matures.
	if env := sources.NewEnvCollector(cfg); env.Enabled() {
		// Provide a real scan function for the logical layer.
		env.SetScanFunc(func() ([]registry.SecretHash, error) {
			roots := m.cfg.GetEnvOptions().ProjectRoots
			if len(roots) == 0 {
				roots = []string{"~"}
			}
			return m.scanner.CollectEnvHashes(roots)
		})
		m.collectors = append(m.collectors, env)

		// Register a nice display name for the logical source
		envID := logicalProjectID("env")
		m.projectMeta[envID] = "Environment Files"
	}

	// Bitwarden collector (skeleton from previous push)
	if bw := sources.NewBitwardenCollector(cfg); bw.Enabled() {
		m.collectors = append(m.collectors, bw)
		bwID := logicalProjectID("bitwarden")
		m.projectMeta[bwID] = "Bitwarden"
	}

	return m
}

// RunInitialDiscovery performs the first scan on configured roots.
func (m *Manager) RunInitialDiscovery() {
	// Respect the logical layer: if the "env" source is explicitly disabled,
	// skip .env* discovery entirely. This is the Phase 1 foundation for
	// treating .env scanning as one activatable Pillar 1 source among others.
	envSrc := m.cfg.Pillar1.Sources["env"]
	if !envSrc.Enabled {
		logging.Printf("Pillar 1 env source is disabled; skipping .env* discovery")
		m.registry.SetScanState(registry.ScanStateCompleted)
		return
	}

	logging.Printf("Scan state changed: %s", registry.ScanStateInProgress)
	m.registry.SetScanState(registry.ScanStateInProgress)

	envOpts := m.cfg.GetEnvOptions()
	roots := envOpts.ProjectRoots
	if len(roots) == 0 {
		roots = []string{"~"}
	}

	var hadError bool
	for _, root := range roots {
		expanded := expandPath(root)
		logging.Printf("Scanning for Pillar 1 env file patterns in: %s", expanded)
		if err := m.scanner.ScanDirectory(expanded); err != nil {
			logging.Printf("Error during scan of %s: %v", expanded, err)
			hadError = true
		}
	}

	if hadError {
		logging.Printf("Scan state changed: %s", registry.ScanStateFailed)
		m.registry.SetScanState(registry.ScanStateFailed)
	} else {
		logging.Printf("Scan state changed: %s", registry.ScanStateCompleted)
		m.registry.SetScanState(registry.ScanStateCompleted)
		m.lastScan = time.Now()
	}
}

// expandPath expands ~ and ~/... to the user's home directory.
func expandPath(path string) string {
	if path == "~" || path == "~/" {
		if h := os.Getenv("HOME"); h != "" {
			return h
		}
		return path
	}

	// Handle ~/something
	if strings.HasPrefix(path, "~/") {
		if h := os.Getenv("HOME"); h != "" {
			return filepath.Join(h, path[2:])
		}
	}

	return path
}

// Note: makeOpaqueProjectID is defined in scanner.go (same package)

// registerProject associates an opaque ID with a display name inside the manager.
func (m *Manager) registerProject(id registry.ProjectID, displayName string) {
	m.projectMeta[id] = displayName
}

// GetProjectDisplayName returns a privacy-friendly name for a project.
// Falls back to a truncated form if not found.
func (m *Manager) GetProjectDisplayName(id registry.ProjectID) string {
	if name, ok := m.projectMeta[id]; ok && name != "" {
		return name
	}
	// Fallback (should rarely happen)
	return registry.ProjectDisplayName(id)
}

// Note: We deliberately chose high-quality on-demand rescan (Phase 3) instead of
// persistent file watching. Full fsnotify reactivity is permanently out of scope
// for security reasons (attack surface + complexity outweigh the benefits).
// Manual `rescan` (plus startup discovery) is the supported mechanism.

// logicalProjectID creates a stable opaque ProjectID for a logical source
// (e.g. "env", "bitwarden"). This allows collectors to contribute hashes
// that participate in duplicates, status, etc.
func logicalProjectID(sourceName string) registry.ProjectID {
	h := sha256.Sum256([]byte("logical:" + sourceName))
	return registry.ProjectID(hex.EncodeToString(h[:8]))
}

type RescanResult struct {
	BeforeHashes int
	AfterHashes  int
	Duration     time.Duration
	RootsScanned []string
	Errors       []string
	Timestamp    time.Time

	// CollectorResults tracks what each logical source contributed during this rescan.
	CollectorResults map[string]int // source name -> number of hashes added
}

// LastScan returns the time of the most recent discovery scan (initial or rescan).
func (m *Manager) LastScan() time.Time {
	return m.lastScan
}

// LastRescanResult returns the most recent manual rescan result, if any.
func (m *Manager) LastRescanResult() *RescanResult {
	return m.lastRescan
}

// Rescan performs a fresh discovery pass over the configured project roots.
// It is safe to call while the daemon is running and is the primary mechanism
// (Phase 3) for keeping the Pillar 1 registry up to date without a restart.
func (m *Manager) Rescan() *RescanResult {
	start := time.Now()
	before := m.registry.Count()

	result := &RescanResult{
		BeforeHashes:     before,
		Timestamp:        start.UTC(),
		Errors:           []string{},
		CollectorResults: make(map[string]int),
	}

	logging.Printf("Manual rescan started (Pillar 1)")

	// Full clear first. This solves the long-standing pruning hole:
	// secrets that came from a source that is now disabled (or from .env files
	// that were deleted) are removed instead of lingering forever.
	m.registry.Clear()
	result.CollectorResults = make(map[string]int)

	// Re-collect from every currently enabled collector.
	for _, c := range m.collectors {
		if !c.Enabled() {
			continue
		}

		if err := c.Validate(); err != nil {
			result.Errors = append(result.Errors, c.Name()+": "+err.Error())
			logging.Printf("Collector %s validation failed: %v", c.Name(), err)
			continue
		}

		hashes, err := c.Collect()
		if err != nil {
			result.Errors = append(result.Errors, c.Name()+": collect error: "+err.Error())
			continue
		}

		projectID := logicalProjectID(c.Name())
		for _, h := range hashes {
			m.registry.Add(h, projectID)
		}

		result.CollectorResults[c.Name()] = len(hashes)
		logging.Printf("Collector %s contributed %d hashes", c.Name(), len(hashes))
	}

	after := m.registry.Count()
	result.AfterHashes = after
	result.Duration = time.Since(start)

	envOpts := m.cfg.GetEnvOptions()
	result.RootsScanned = envOpts.ProjectRoots
	if len(result.RootsScanned) == 0 {
		result.RootsScanned = []string{"~"}
	}

	m.lastScan = start
	m.lastRescan = result

	logging.Printf("Manual rescan complete: %d -> %d hashes in %v (registry was cleared first)", before, after, result.Duration)
	return result
}
