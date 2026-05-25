package cli

import "testing"

func TestRunScrubHistory(t *testing.T) {
	defer resetTestOverrides()
	restore := silenceOutput()
	defer restore()

	RunScrubHistory()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":3,"file":"/tmp/hist"}`)
	RunScrubHistory()
}
