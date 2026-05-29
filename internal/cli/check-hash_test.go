package cli

import "testing"

func TestRunCheckHash(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunCheckHash("deadbeef")
	sendDaemonCommandFn = mockSendDaemonCommand(`{"known":true}`)
	RunCheckHash("cafebabe")
}
