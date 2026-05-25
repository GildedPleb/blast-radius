package cli

import "testing"

func TestRunConfig(t *testing.T) {
	defer resetTestOverrides()
	restore := silenceOutput()
	defer restore()

	RunConfig(nil)
	RunConfig([]string{"redaction"})
	RunConfig([]string{"unknown"})
}
