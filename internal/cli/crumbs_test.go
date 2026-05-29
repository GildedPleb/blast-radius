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
