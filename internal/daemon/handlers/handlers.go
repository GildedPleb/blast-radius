package handlers

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// DaemonContext is the narrow interface exposed to command handlers.
// The canonical definition lives here (handlers package) to avoid import
// cycles with the daemon package (which imports handlers for dispatch).
// daemon/context.go contains a thin alias for ergonomic references from
// the daemon package.
type DaemonContext interface {
	RegistrySnapshot() any
	FindDuplicates() map[registry.SecretHash][]registry.ProjectID
	GetProjectDisplayName(registry.ProjectID) string
	IsKnownHashHex(string) bool
	AllHashes() []registry.SecretHash
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

	// Pillar5ClipboardStatus (see context.go for docs).
	Pillar5ClipboardStatus() map[string]any
}

// CommandHandler is the interface implemented by every daemon command.
type CommandHandler interface {
	Name() string
	Handle(args string, d DaemonContext) (any, error)
}

// --- Declarative command handler registry (removes the imperative switch in daemon.go) ---

var commandHandlers = map[string]CommandHandler{}

// Register makes a handler available for dispatch by name.
// Called via init() from each handler implementation file.
func Register(h CommandHandler) {
	if h == nil {
		return
	}
	if name := h.Name(); name != "" {
		commandHandlers[name] = h
	}
}

// GetHandler returns the handler for cmd, or UnknownHandler for unrecognized.
// HALT/STOP are aliases handled here for the caller (daemon special-cases the
// response write + early return after HALT/STOP).
func GetHandler(cmd string) CommandHandler {
	if h, ok := commandHandlers[cmd]; ok {
		return h
	}
	// Aliases for halt
	if cmd == "STOP" {
		if h, ok := commandHandlers["HALT"]; ok {
			return h
		}
	}
	return UnknownHandler{cmd: cmd}
}
