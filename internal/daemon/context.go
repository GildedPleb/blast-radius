package daemon

import (
	"time"

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
}
