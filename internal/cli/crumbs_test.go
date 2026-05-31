package cli

import "testing"

func TestRunCrumbs(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// first call will hit "no daemon" path
	RunCrumbs(false)

	// second with mock response
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":1,"findings":[{"location":"Downloads/test.json","format":"bitwarden_json","known_matches":3,"entropy_hits":7,"confidence":"high","size":1234,"last_mod":"2026-01-01T00:00:00Z","basename":"test.json"}],"files_examined":42}`)
	RunCrumbs(false)
	RunCrumbs(true) // json path
}

// TestRunCrumbs_NoFindings exercises the total==0 happy human path.
func TestRunCrumbs_NoFindings(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","total":0,"files_examined":123}`)
	RunCrumbs(false)
	RunCrumbs(true)
}

// TestRunCrumbs_ErrorStatus exercises non-ok status with message.
func TestRunCrumbs_ErrorStatus(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"scan failed"}`)
	RunCrumbs(false)
}

// TestRunCrumbs_ParseError exercises bad JSON response.
func TestRunCrumbs_ParseError(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	sendDaemonCommandFn = mockSendDaemonCommand(`not even json`)
	RunCrumbs(false)
}

// TestRunCrumbs_RichFindings exercises all the human formatting branches
// including last_mod parsing, multiple findings, etc.
func TestRunCrumbs_RichFindings(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	sendDaemonCommandFn = mockSendDaemonCommand(`{
		"status":"partial",
		"total":2,
		"findings":[
			{"location":"/tmp/secret1.env","format":"env","known_matches":1,"entropy_hits":5,"confidence":"medium","size":42,"last_mod":"2026-02-02T12:00:00Z"},
			{"location":"/tmp/secret2.json","format":"json","known_matches":0,"entropy_hits":9,"confidence":"high","size":999}
		],
		"files_examined":77
	}`)
	RunCrumbs(false)
	RunCrumbs(true)
}
