package cli

import "testing"

func TestRunRescan(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// No daemon path
	RunRescan(false)
	RunRescan(true)

	// Bad JSON
	sendDaemonCommandFn = mockSendDaemonCommand(`not valid json at all`)
	RunRescan(false)
	RunRescan(true)

	// Non-ok status with message
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"something went wrong"}`)
	RunRescan(false)
	RunRescan(true)

	// Happy path with full Pillar 1 data (exercises last_scan formatting + collector_results + errors)
	sendDaemonCommandFn = mockSendDaemonCommand(`{
		"status":"ok",
		"last_scan":"2026-03-01T11:55:00Z",
		"collector_results":{"env":142,"bitwarden":19},
		"errors":["one warning","another"]
	}`)
	RunRescan(false)
	RunRescan(true)

	// Happy path, minimal data (no last_scan, no collectors, no errors)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok"}`)
	RunRescan(false)
	RunRescan(true)
}
