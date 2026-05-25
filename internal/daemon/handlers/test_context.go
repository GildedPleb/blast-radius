package handlers

import "time"

// fakeContext is a minimal implementation of DaemonContext for handler tests.
type fakeContext struct {
	snapshot     any
	dups         map[[32]byte][]string
	displayNames map[string]string
	knownHashes  map[string]bool
	hashes       [][32]byte
	now          time.Time
	shutdown     bool
}

func (f *fakeContext) RegistrySnapshot() any                  { return f.snapshot }
func (f *fakeContext) FindDuplicates() map[[32]byte][]string  { return f.dups }
func (f *fakeContext) GetProjectDisplayName(p string) string  { return f.displayNames[p] }
func (f *fakeContext) IsKnownHashHex(h string) bool           { return f.knownHashes[h] }
func (f *fakeContext) AllHashes() [][32]byte                  { return f.hashes }
func (f *fakeContext) Now() time.Time                         { return f.now }
func (f *fakeContext) TriggerShutdown()                       { f.shutdown = true }
