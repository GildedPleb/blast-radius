package cli

import "testing"

func TestRunDuplicates(t *testing.T) {
	defer resetTestOverrides()
	restore := silenceOutput()
	defer restore()

	RunDuplicates()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":0}`)
	RunDuplicates()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":2,"duplicates":[{"hash":"abc","projects":["p1","p2"]}]}`)
	RunDuplicates()
}
