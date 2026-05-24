package discovery

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Manager coordinates discovery and (future) watching.
// It owns the mapping from opaque ProjectID → display name.
type Manager struct {
	scanner  *Scanner
	registry *registry.Registry
	cfg      *config.Config

	// projectMeta maps opaque ProjectID -> human friendly display name.
	// This is the only place that knows the real filesystem location.
	projectMeta map[registry.ProjectID]string
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
	return m
}

// RunInitialDiscovery performs the first scan on configured roots.
func (m *Manager) RunInitialDiscovery() {
	logging.Printf("Scan state changed: %s", registry.ScanStateInProgress)
	m.registry.SetScanState(registry.ScanStateInProgress)

	roots := m.cfg.ProjectRoots
	if len(roots) == 0 {
		roots = []string{"~"}
	}

	var hadError bool
	for _, root := range roots {
		expanded := expandPath(root)
		logging.Printf("Scanning for .env* files in: %s", expanded)
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

// Note: Full fsnotify-based watching will be added when dependency is available.
// For Phase 1 we perform solid initial discovery on daemon startup.
