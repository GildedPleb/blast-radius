package cli

import "testing"

func TestRunConfig(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunConfig(nil)
	RunConfig([]string{"unknown"})
}
