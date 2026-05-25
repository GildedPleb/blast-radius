package cli

import "testing"

func TestRunRecorder(t *testing.T) {
	// lightweight - just ensure it doesn't hang or panic on bad input
	RunRecorder(nil)
}
