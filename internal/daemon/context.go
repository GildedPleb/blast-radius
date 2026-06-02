package daemon

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
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
	// Appears in the JSON response under the "pillar2" key (symmetric with "pillar1").
	CrumbsSummary() map[string]any
	// RunCrumbsScan forces a fresh scan and returns the full result (used by CRUMBS handler).
	RunCrumbsScan() *residue.ScanResult

	// TriggerPillar1Rescan runs a fresh discovery pass (manual rescan).
	// Phase 3 deliverable. Full fsnotify reactivity is permanently out of scope.
	TriggerPillar1Rescan() error
	// Pillar1ScanStatus returns lightweight info about the last Pillar 1 scan.
	Pillar1ScanStatus() map[string]any
	// LastPillar1Rescan returns the full result of the most recent manual rescan (for rich output).
	LastPillar1Rescan() *discovery.RescanResult

	// Pillar3Config returns the user (or default) settings for History Hygiene.
	// Used by the SCRUB_HISTORY handler to decide delete vs redact + placeholder.
	Pillar3Config() config.Pillar3Config

	// BeginExclusiveOp attempts to start a potentially long-running mutating operation
	// (e.g. SCRUB_HISTORY which can touch many history files). Returns a release func
	// (call via defer) and ok=false if the daemon is already busy with another such op.
	// This is a coarse-grained guard against concurrent history mutation (temp file
	// name collisions, partial writes, truncated histories, etc.).
	BeginExclusiveOp(name string) (release func(), ok bool)
}
