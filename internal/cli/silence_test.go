package cli

import (
	"os"
)

// silenceOutput redirects stdout/stderr to /dev/null for the duration of the test.
// Call defer restore() after using it.
func silenceOutput() (restore func()) {
	oldOut := os.Stdout
	oldErr := os.Stderr

	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull
	os.Stderr = devNull

	return func() {
		devNull.Close()
		os.Stdout = oldOut
		os.Stderr = oldErr
	}
}
