package handlers

import (
	"time"

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

	// CrumbsSummary + RunCrumbsScan for Pillar 2 (see daemon/context.go for docs)
	CrumbsSummary() map[string]any
	RunCrumbsScan() *residue.ScanResult
}

// CommandHandler is the interface implemented by every daemon command.
type CommandHandler interface {
	Name() string
	Handle(args string, d DaemonContext) (any, error)
}
