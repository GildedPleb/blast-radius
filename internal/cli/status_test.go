package cli

import (
	"testing"
)

func TestRunStatus(t *testing.T) {
	defer resetTestOverrides()
	restore := silenceOutput()
	defer restore()

	RunStatus(false)
	RunStatus(true)

	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","registry":{"tracked_hashes":42}}`)
	RunStatus(false)
	RunStatus(true)
}
