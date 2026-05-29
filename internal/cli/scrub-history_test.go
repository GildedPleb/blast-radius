package cli

import "testing"

func TestRunScrubHistory(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// no daemon
	RunScrubHistory()

	// success with removals
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":3,"file":"/tmp/hist"}`)
	RunScrubHistory()

	// success with zero removals (different message path)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":0}`)
	RunScrubHistory()

	// error response with message
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"daemon busy"}`)
	RunScrubHistory()

	// malformed JSON (exercises ignored unmarshal error path)
	sendDaemonCommandFn = mockSendDaemonCommand(`not valid json at all`)
	RunScrubHistory()
}
