package handlers

import (
	"time"

	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// fakeContext is a minimal implementation of DaemonContext for handler tests.
type fakeContext struct {
	snapshot     any
	dups         map[[32]byte][]string
	displayNames map[string]string
	knownHashes  map[string]bool
	hashes       [][32]byte
	now          time.Time
	shutdown     bool
	crumbs       map[string]any
	crumbsResult *residue.ScanResult // used for Pillar 2 (crumbs) handler tests
}

func (f *fakeContext) RegistrySnapshot() any                 { return f.snapshot }
func (f *fakeContext) FindDuplicates() map[[32]byte][]string { return f.dups }
func (f *fakeContext) GetProjectDisplayName(p string) string { return f.displayNames[p] }
func (f *fakeContext) IsKnownHashHex(h string) bool          { return f.knownHashes[h] }
func (f *fakeContext) AllHashes() [][32]byte                 { return f.hashes }
func (f *fakeContext) Now() time.Time                        { return f.now }
func (f *fakeContext) TriggerShutdown()                      { f.shutdown = true }

func (f *fakeContext) CrumbsSummary() map[string]any { return f.crumbs }
func (f *fakeContext) RunCrumbsScan() *residue.ScanResult {
	if f.crumbsResult != nil {
		return f.crumbsResult
	}
	return &residue.ScanResult{Timestamp: time.Now().UTC()}
}

func (f *fakeContext) TriggerPillar1Rescan() error { return nil }
func (f *fakeContext) Pillar1ScanStatus() map[string]any {
	return map[string]any{"status": "ok", "last_scan": f.now.UTC().Format(time.RFC3339)}
}
func (f *fakeContext) LastPillar1Rescan() *discovery.RescanResult {
	return nil // tests can override if needed
}
