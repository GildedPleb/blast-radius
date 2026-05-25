package handlers

import "io"

// fakeContext is a recording implementation of RecorderContext for handler tests.
type fakeContext struct {
	startNewWindowCalls []string
	flushData           []byte
	flushErr            error
	lastHasSecret       bool
	stopCalled          bool
	shutdownCalled      bool
	replayMode          string
	replayCustom        string
	replayPreserve      bool
	replayWriter        io.Writer
	resetCalled         bool
}

func (f *fakeContext) StartNewWindowWithCommand(s string) {
	f.startNewWindowCalls = append(f.startNewWindowCalls, s)
}

func (f *fakeContext) FlushCurrentWindow() ([]byte, error) {
	return f.flushData, f.flushErr
}

func (f *fakeContext) LastWindowHasSecret() bool {
	return f.lastHasSecret
}

func (f *fakeContext) Stop() error {
	f.stopCalled = true
	return nil
}

func (f *fakeContext) TriggerShutdown() {
	f.shutdownCalled = true
}

func (f *fakeContext) ReplayRedacted(w io.Writer, mode, custom string, preserve bool) {
	f.replayMode = mode
	f.replayCustom = custom
	f.replayPreserve = preserve
	f.replayWriter = w
	if w != nil {
		w.Write([]byte("REDACTED_LINE\n"))
	}
}

func (f *fakeContext) ResetHistory() {
	f.resetCalled = true
}
