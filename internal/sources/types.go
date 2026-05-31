package sources

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Collector is the interface for a logical source of legitimate secrets
// in Pillar 1 (the "where they should be" layer).
//
// All implementations are owned by the project. No user-supplied command
// execution is allowed for collectors.
//
// Collectors are expected to implement a clear prerequisite/validation flow
// before doing heavy IO or collection work (e.g. "is the binary present?",
// "can we authenticate?", "is required config present?").
type Collector interface {
	// Name returns a stable identifier for the source (e.g. "env", "bitwarden").
	Name() string

	// Enabled reports whether this collector should run given the current config.
	Enabled() bool

	// Validate performs lightweight prerequisite / IO checks for this source.
	// Examples:
	//   - For "env": are project roots configured?
	//   - For "bitwarden": is the `bw` binary available? Do we have a usable session?
	//
	// Validate should be relatively cheap and must not perform full secret collection.
	// It returns nil if the collector believes it is ready to Collect().
	Validate() error

	// Collect runs the source and returns the secret hashes discovered.
	// Callers are responsible for registering the hashes in the central registry.
	Collect() ([]registry.SecretHash, error)
}

// ScanStats captures lightweight results from running collectors.
// Used for status, rescan output, and logging.
type ScanStats struct {
	Source    string
	Hashes    int
	Duration  time.Duration
	Error     string // non-fatal error message if any
	Timestamp time.Time
}
