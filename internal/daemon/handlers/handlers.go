package handlers

import "time"

// DaemonContext is satisfied by *daemon.Daemon (see internal/daemon/context.go)
type DaemonContext interface {
	RegistrySnapshot() any
	FindDuplicates() map[[32]byte][]string
	GetProjectDisplayName(string) string
	IsKnownHashHex(string) bool
	AllHashes() [][32]byte
	Now() time.Time
	TriggerShutdown()
}

// CommandHandler is the interface implemented by every daemon command.
type CommandHandler interface {
	Name() string
	Handle(args string, d DaemonContext) (any, error)
}
