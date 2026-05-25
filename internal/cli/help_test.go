package cli

import "testing"

func TestPrintHelp(t *testing.T) {
	restore := silenceOutput()
	defer restore()
	PrintHelp()
}
