package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	projectMeta   map[registry.ProjectID]string
	projectMetaMu sync.RWMutex // protects projectMeta (bg RunInitialDiscovery + concurrent STATUS/RESCAN queries)

	lastScan time.Time // time of most recent initial scan or manual rescan

	// collectors holds the active logical sources for Pillar 1 (env, bitwarden, etc.).
	// This is the foundation of the "logical layer".
	collectors []sources.Collector

	lastRescan *RescanResult // most recent manual rescan result (for rich output)

	lastMu sync.RWMutex // protects lastScan + lastRescan (bg initial discovery + concurrent STATUS/RESCAN handlers)
}

// NewManager creates a DiscoveryManager.
func NewManager(cfg *config.Config, reg *registry.Registry) *Manager {
	if reg == nil {
		// Defensive: registry is required for all scan/rescan paths (Add, Clear,
		// Count, SetScanState etc). Callers (daemon.New) always pass a fresh one,
		// but tests or alternate wiring may pass nil; allocate so methods remain
		// safe and the manager is always usable.
		reg = registry.New()
	}

	m := &Manager{
		registry:    reg,
		cfg:         cfg,
		projectMeta: make(map[registry.ProjectID]string),
	}

	scanner := NewScanner(cfg, reg)
	scanner.onProjectDiscovered = m.registerProject
	m.scanner = scanner

	// Initialize logical layer collectors.
	// We wire the env source (primary) and the hard-coded bitwarden source when enabled.
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
		m.projectMetaMu.Lock()
		m.projectMeta[envID] = "Environment Files"
		m.projectMetaMu.Unlock()
	}

	// Bitwarden collector (hard-coded, owned by the project)
	if bw := sources.NewBitwardenCollector(cfg); bw.Enabled() {
		m.collectors = append(m.collectors, bw)
		bwID := logicalProjectID("bitwarden")
		m.projectMetaMu.Lock()
		m.projectMeta[bwID] = "Bitwarden"
		m.projectMetaMu.Unlock()
	}

	return m
}

// RunInitialDiscovery performs the first scan on configured roots.
func (m *Manager) RunInitialDiscovery() {
	if m.cfg == nil {
		if m.registry != nil {
			m.registry.SetScanState(registry.ScanStateCompleted)
		}
		return
	}
	if m.registry == nil {
		// Should not happen (NewManager defensively allocates), but keep
		// the manager methods robust against nil registry.
		return
	}
	// Respect the logical layer: if the "env" source is explicitly disabled,
	// skip .env* discovery entirely. This is the foundation for
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
		m.lastMu.Lock()
		m.lastScan = time.Now()
		m.lastMu.Unlock()
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
	m.projectMetaMu.Lock()
	m.projectMeta[id] = displayName
	m.projectMetaMu.Unlock()
}

// GetProjectDisplayName returns a privacy-friendly name for a project.
// Falls back to a truncated form if not found.
func (m *Manager) GetProjectDisplayName(id registry.ProjectID) string {
	m.projectMetaMu.RLock()
	defer m.projectMetaMu.RUnlock()
	if name, ok := m.projectMeta[id]; ok && name != "" {
		return name
	}
	// Fallback (should rarely happen)
	return registry.ProjectDisplayName(id)
}

// Note: We deliberately chose high-quality on-demand rescan instead of
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
	m.lastMu.RLock()
	defer m.lastMu.RUnlock()
	return m.lastScan
}

// LastRescanResult returns the most recent manual rescan result, if any.
func (m *Manager) LastRescanResult() *RescanResult {
	m.lastMu.RLock()
	defer m.lastMu.RUnlock()
	return m.lastRescan
}

// Rescan performs a fresh discovery pass over the configured project roots.
// It is safe to call while the daemon is running and is the primary mechanism
// for keeping the Pillar 1 registry up to date without a restart.
func (m *Manager) Rescan() *RescanResult {
	if m.registry == nil {
		// Defensive: NewManager guarantees a registry, but tolerate nil input
		// for robustness (e.g. direct construction in tests or alternate DI).
		return &RescanResult{
			Timestamp:        time.Now().UTC(),
			Errors:           []string{"registry not initialized"},
			CollectorResults: make(map[string]int),
		}
	}
	if m.cfg == nil {
		// Can happen in degenerate test setups; still return a usable result
		// without dereferencing cfg for GetEnvOptions or collector wiring.
		return &RescanResult{
			Timestamp:        time.Now().UTC(),
			Errors:           []string{"configuration not loaded"},
			CollectorResults: make(map[string]int),
		}
	}

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

	m.lastMu.Lock()
	m.lastScan = start
	m.lastRescan = result
	m.lastMu.Unlock()

	logging.Printf("Manual rescan complete: %d -> %d hashes in %v (registry was cleared first)", before, after, result.Duration)
	return result
}
