package registry

import (
	"crypto/sha256"
	"sync"
	"time"
)

// SecretHash represents a SHA-256 hash of a secret value.
// Plaintext is NEVER stored.
type SecretHash [32]byte

// ProjectID is a stable identifier for a project (typically a canonical directory path).
type ProjectID string

// Entry holds minimal metadata for a discovered secret hash.
type Entry struct {
	Projects   map[ProjectID]struct{}
	LastSeen   time.Time
	// No file paths, no plaintext, minimal by design.
}

// ScanState represents the current state of the discovery scan.
type ScanState string

const (
	ScanStateNotStarted ScanState = "not_started"
	ScanStateInProgress ScanState = "in_progress"
	ScanStateCompleted  ScanState = "completed"
	ScanStateFailed     ScanState = "failed"
)

// Registry is the in-memory source of truth for known secret hashes.
// It is never persisted to disk.
type Registry struct {
	mu        sync.RWMutex
	entries   map[SecretHash]Entry
	started   time.Time
	scanState ScanState
}

// New creates a new empty Registry.
func New() *Registry {
	return &Registry{
		entries:   make(map[SecretHash]Entry),
		started:   time.Now(),
		scanState: ScanStateNotStarted,
	}
}

// HashValue computes the SHA-256 hash of a secret value.
// This is the ONLY way secrets should enter the system.
func HashValue(value []byte) SecretHash {
	return sha256.Sum256(value)
}

// Add associates a hash with a project. Idempotent.
func (r *Registry) Add(hash SecretHash, project ProjectID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[hash]
	if !ok {
		entry = Entry{
			Projects: make(map[ProjectID]struct{}),
		}
	}
	entry.Projects[project] = struct{}{}
	entry.LastSeen = time.Now()
	r.entries[hash] = entry
}

// Remove disassociates a hash from a project. Cleans up if no projects remain.
func (r *Registry) Remove(hash SecretHash, project ProjectID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[hash]
	if !ok {
		return
	}
	delete(entry.Projects, project)
	if len(entry.Projects) == 0 {
		delete(r.entries, hash)
	} else {
		r.entries[hash] = entry
	}
}

// Has checks whether a hash is known.
func (r *Registry) Has(hash SecretHash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[hash]
	return ok
}

// GetProjectsForHash returns the set of projects associated with a hash.
func (r *Registry) GetProjectsForHash(hash SecretHash) []ProjectID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[hash]
	if !ok {
		return nil
	}
	projects := make([]ProjectID, 0, len(entry.Projects))
	for p := range entry.Projects {
		projects = append(projects, p)
	}
	return projects
}

// Count returns the number of unique secret hashes tracked.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// Uptime returns how long the registry has been active.
func (r *Registry) Uptime() time.Duration {
	return time.Since(r.started)
}

// Snapshot returns a safe copy of current state for status reporting.
// Never includes any secret material.
func (r *Registry) Snapshot() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]any{
		"tracked_hashes": len(r.entries),
		"uptime":         r.Uptime().String(),
		"scan_state":     string(r.scanState),
	}
}

// SetScanState updates the current discovery scan state.
func (r *Registry) SetScanState(state ScanState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanState = state
}

// GetScanState returns the current scan state.
func (r *Registry) GetScanState() ScanState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scanState
}