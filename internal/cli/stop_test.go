package cli

import "testing"

func TestRunStop(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunStop()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok"}`)
	RunStop()
}
