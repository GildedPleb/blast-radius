package daemon

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// DaemonContext is the narrow interface exposed to command handlers.
type DaemonContext interface {
	RegistrySnapshot() any
	FindDuplicates() map[[32]byte][]string
	GetProjectDisplayName(string) string
	IsKnownHashHex(string) bool
	AllHashes() [][32]byte
	Now() time.Time
	TriggerShutdown()

	// CrumbsSummary returns lightweight Pillar 2 status (count, recency, sample). Used by STATUS.
	CrumbsSummary() map[string]any
	// RunCrumbsScan forces a fresh scan and returns the full result (used by CRUMBS handler).
	RunCrumbsScan() *residue.ScanResult

	// TriggerPillar1Rescan runs a fresh discovery pass (manual rescan).
	// Phase 3 deliverable — no file watching.
	TriggerPillar1Rescan() error
	// Pillar1ScanStatus returns lightweight info about the last Pillar 1 scan.
	Pillar1ScanStatus() map[string]any
	// LastPillar1Rescan returns the full result of the most recent manual rescan (for rich output).
	LastPillar1Rescan() *discovery.RescanResult
}
