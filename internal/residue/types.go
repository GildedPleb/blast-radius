package residue

import "time"

// ResidueFinding describes a single suspicious file found during a crumbs scan.
// All paths are privacy-safe (never full absolute home paths in output).
type ResidueFinding struct {
	Location     string    `json:"location"`
	Basename     string    `json:"basename"`
	LastMod      time.Time `json:"last_mod"`
	Format       string    `json:"format"`
	Confidence   string    `json:"confidence"`
	KnownMatches int       `json:"known_matches"`
	EntropyHits  int       `json:"entropy_hits"`
	Size         int64     `json:"size"`
}

// ScanResult is the complete output of a residue (crumbs) scan.
type ScanResult struct {
	Findings      []ResidueFinding `json:"findings"`
	ScannedDirs   int              `json:"scanned_dirs"`
	FilesExamined int              `json:"files_examined"`
	Duration      time.Duration    `json:"duration"`
	Timestamp     time.Time        `json:"timestamp"`
	Errors        []string         `json:"errors,omitempty"`
}

// Format constants (fixed set, always evaluated when feature enabled).
const (
	FormatBitwardenJSON  = "bitwarden_json"
	FormatBitwardenCSV   = "bitwarden_csv"
	FormatDashlane       = "dashlane"
	FormatOnePassword    = "onepassword_1pif"
	FormatGenericHighEnt = "generic_high_entropy"
	FormatSuspiciousName = "suspicious_filename"
)

// Confidence levels.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Default safety limits (hard-coded per v1 plan — no config surface for these).
const (
	maxFileSizeBytes = 10 * 1024 * 1024 // 10 MiB
	minSecretLen     = 8
	highEntropyMin   = 4.0 // bits/char threshold for "interesting"
)

// minHighEntropyHitsForGeneric is the hard-coded default for v1 (no config knob).
const minHighEntropyHitsForGeneric = 3
