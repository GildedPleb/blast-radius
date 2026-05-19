package discovery

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Manager coordinates discovery and (future) watching.
type Manager struct {
	scanner  *Scanner
	registry *registry.Registry
	cfg      *config.Config
}

// NewManager creates a DiscoveryManager.
func NewManager(cfg *config.Config, reg *registry.Registry) *Manager {
	return &Manager{
		scanner:  NewScanner(cfg, reg),
		registry: reg,
		cfg:      cfg,
	}
}

// RunInitialDiscovery performs the first scan on configured roots.
func (m *Manager) RunInitialDiscovery() {
	log.Printf("Scan state changed: %s", registry.ScanStateInProgress)
	m.registry.SetScanState(registry.ScanStateInProgress)

	roots := m.cfg.ProjectRoots
	if len(roots) == 0 {
		roots = []string{"~"}
	}

	var hadError bool
	for _, root := range roots {
		expanded := expandPath(root)
		log.Printf("Scanning for .env* files in: %s", expanded)
		if err := m.scanner.ScanDirectory(expanded); err != nil {
			log.Printf("Error during scan of %s: %v", expanded, err)
			hadError = true
		}
	}

	if hadError {
		log.Printf("Scan state changed: %s", registry.ScanStateFailed)
		m.registry.SetScanState(registry.ScanStateFailed)
	} else {
		log.Printf("Scan state changed: %s", registry.ScanStateCompleted)
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

// Note: Full fsnotify-based watching will be added when dependency is available.
// For Phase 1 we perform solid initial discovery on daemon startup.
