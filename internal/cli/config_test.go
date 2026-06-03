package cli

import "testing"

func TestRunConfig(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Exercises the no-arg (show) path and the unknown-subcommand path.
	RunConfig(nil)
	RunConfig([]string{"unknown"})
}
