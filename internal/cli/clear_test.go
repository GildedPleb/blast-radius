package cli

import "testing"

func TestRunClear(t *testing.T) {
	restore := silenceOutput()
	defer restore()
	RunClear()
}
