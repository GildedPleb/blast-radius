package recorder

import (
	"bytes"
	"sync"
	"time"
)

// RecordingWindow holds the live capture buffer for the current command.
type RecordingWindow struct {
	StartTime time.Time
	Buffer    *bytes.Buffer
	mu        sync.Mutex
}

// SecretSpan records a known secret location inside a line (hash + offset + length).
type SecretSpan struct {
	Hash   string
	Start  int
	Length int
}

// Line holds one line of captured output plus any detected secrets.
type Line struct {
	Raw     []byte
	Secrets []SecretSpan
}

// Window is the persisted, type-safe unit owned by the Go Recorder.
type Window struct {
	StartTime time.Time
	Command   string
	Lines     []Line
	HasSecret bool // true if command or any line matched mightContainSecret
}
