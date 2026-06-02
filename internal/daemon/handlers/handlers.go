package handlers

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// DaemonContext is satisfied by *daemon.Daemon (see internal/daemon/context.go)
type DaemonContext interface {
	RegistrySnapshot() any
	FindDuplicates() map[[32]byte][]string
	GetProjectDisplayName(string) string
	IsKnownHashHex(string) bool
	AllHashes() [][32]byte
	Now() time.Time
	TriggerShutdown()

	// CrumbsSummary + RunCrumbsScan for Pillar 2 (status JSON key is "pillar2")
	CrumbsSummary() map[string]any
	RunCrumbsScan() *residue.ScanResult

	// TriggerPillar1Rescan + Pillar1ScanStatus for Phase 3 manual rescan.
	// (Full fsnotify reactivity is permanently out of scope for security reasons.)
	TriggerPillar1Rescan() error
	Pillar1ScanStatus() map[string]any
	// LastPillar1Rescan for rich per-source output in rescan command.
	LastPillar1Rescan() *discovery.RescanResult

	// Pillar3Config returns History Hygiene settings (mode, placeholder, etc.).
	Pillar3Config() config.Pillar3Config

	// BeginExclusiveOp attempts to start a potentially long-running mutating operation
	// (e.g. SCRUB_HISTORY which can touch many history files). Returns a release func
	// (call via defer) and ok=false if the daemon is already busy with another such op.
	// This is a coarse-grained guard against concurrent history mutation (temp file
	// name collisions, partial writes, truncated histories, etc.).
	BeginExclusiveOp(name string) (release func(), ok bool)
}

// CommandHandler is the interface implemented by every daemon command.
type CommandHandler interface {
	Name() string
	Handle(args string, d DaemonContext) (any, error)
}
