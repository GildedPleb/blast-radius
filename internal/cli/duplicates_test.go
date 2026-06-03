package cli

import "testing"

func TestRunDuplicates(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunDuplicates()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":0}`)
	RunDuplicates()
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":2,"duplicates":[{"hash":"abc","projects":["p1","p2"]}]}`)
	RunDuplicates()

	// err from send (no daemon path)
	sendDaemonCommandFn = func(string) (string, error) { return "", errForTest }
	RunDuplicates()

	// bad json
	sendDaemonCommandFn = mockSendDaemonCommand(`not json`)
	RunDuplicates()

	// status != ok
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"boom"}`)
	RunDuplicates()

	// missing total / bad duplicates shape (exercises the if-ok guards)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":"nope","duplicates":"bad"}`)
	RunDuplicates()
}
