package handlers

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// fakeContext is a minimal implementation of DaemonContext for handler tests.
type fakeContext struct {
	snapshot       any
	dups           map[registry.SecretHash][]registry.ProjectID
	displayNames   map[registry.ProjectID]string
	knownHashes    map[string]bool
	hashes         []registry.SecretHash
	now            time.Time
	shutdown       bool
	crumbs         map[string]any
	crumbsResult   *residue.ScanResult // used for Pillar 2 (crumbs) handler tests
	crumbsForceNil bool

	// pillar3 allows tests to inject a specific Pillar3Config (for testing
	// disabled, custom placeholder, HistoryFiles, etc.).
	// Use SetPillar3Config in tests to set a non-default value.
	pillar3       config.Pillar3Config
	hasPillar3Cfg bool

	busy bool // when true, BeginExclusiveOp returns ok=false to simulate concurrent long-running op

	lastPillar1Rescan *discovery.RescanResult
	pillar1RescanErr  error
}

func (f *fakeContext) RegistrySnapshot() any { return f.snapshot }
func (f *fakeContext) FindDuplicates() map[registry.SecretHash][]registry.ProjectID {
	return f.dups
}
func (f *fakeContext) GetProjectDisplayName(p registry.ProjectID) string {
	return f.displayNames[p]
}
func (f *fakeContext) IsKnownHashHex(h string) bool { return f.knownHashes[h] }
func (f *fakeContext) AllHashes() []registry.SecretHash {
	return f.hashes
}
func (f *fakeContext) Now() time.Time   { return f.now }
func (f *fakeContext) TriggerShutdown() { f.shutdown = true }

func (f *fakeContext) CrumbsSummary() map[string]any { return f.crumbs }
func (f *fakeContext) RunCrumbsScan() *residue.ScanResult {
	if f.crumbsForceNil {
		return nil
	}
	if f.crumbsResult != nil {
		return f.crumbsResult
	}
	return &residue.ScanResult{Timestamp: time.Now().UTC()}
}

func (f *fakeContext) TriggerPillar1Rescan() error { return f.pillar1RescanErr }
func (f *fakeContext) Pillar1ScanStatus() map[string]any {
	return map[string]any{"status": "ok", "last_scan": f.now.UTC().Format(time.RFC3339)}
}
func (f *fakeContext) LastPillar1Rescan() *discovery.RescanResult {
	return f.lastPillar1Rescan
}

func (f *fakeContext) SetPillar1RescanError(err error) {
	f.pillar1RescanErr = err
}

func (f *fakeContext) SetLastPillar1Rescan(r *discovery.RescanResult) {
	f.lastPillar1Rescan = r
}

func (f *fakeContext) SetCrumbsResultNil() {
	f.crumbsForceNil = true
}

// Pillar3Config returns the injected config if set via SetPillar3Config, otherwise a safe default.
func (f *fakeContext) Pillar3Config() config.Pillar3Config {
	if f.hasPillar3Cfg {
		return f.pillar3
	}
	return config.Pillar3Config{
		Enabled:           true,
		Mode:              "delete",
		RedactPlaceholder: "[REDACTED]",
		HistoryFiles:      nil,
	}
}

// BeginExclusiveOp returns a no-op release func and ok=true unless SetBusy(true)
// was called on this context (used to exercise the "daemon busy" error path in
// long-running handlers like scrub).
func (f *fakeContext) BeginExclusiveOp(name string) (func(), bool) {
	if f.busy {
		return func() {}, false
	}
	return func() {}, true
}

func (f *fakeContext) Pillar5ClipboardStatus() map[string]any {
	return map[string]any{
		"secret_count":   0,
		"last_change":    f.now.UTC().Format(time.RFC3339),
		"redacted":       false,
		"cleared":        false,
		"monitor_active": false,
	}
}

// SetPillar3Config is a helper for tests to inject a custom Pillar3Config.
func (f *fakeContext) SetPillar3Config(c config.Pillar3Config) {
	f.pillar3 = c
	f.hasPillar3Cfg = true
}

// SetBusy forces the next BeginExclusiveOp call to return ok=false. Call with false
// to reset. This lets handler tests cover the concurrent-op / daemon-busy error branch.
func (f *fakeContext) SetBusy(b bool) {
	f.busy = b
}
