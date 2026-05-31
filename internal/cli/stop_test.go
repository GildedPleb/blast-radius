package cli

import "testing"

func TestRunStop(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunStop()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok"}`)
	RunStop()

	// error from daemon
	sendDaemonCommandFn = mockSendDaemonCommand(`not json`)
	RunStop()

	sendDaemonCommandFn = func(string) (string, error) { return "", errForTest }
	RunStop()
}
