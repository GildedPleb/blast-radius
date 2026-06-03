package cli

import "testing"

func TestRunScrubHistory(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// no daemon
	RunScrubHistory(nil)

	// success with removals (delete mode)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":3,"file":"/tmp/hist"}`)
	RunScrubHistory(nil)

	// success with zero removals
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":0}`)
	RunScrubHistory(nil)

	// error
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"daemon busy"}`)
	RunScrubHistory(nil)

	// malformed
	sendDaemonCommandFn = mockSendDaemonCommand(`not valid json at all`)
	RunScrubHistory(nil)

	// dry-run json path (exercises new branches)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","dry_run":true,"mode_used":"redact","would_delete":1,"would_redact":0,"secrets_found":1}`)
	RunScrubHistory([]string{"--dry-run", "--json"})

	// real redact response (exercises redact human output path)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","entries_redacted":2,"secrets_found":3,"file":"/tmp/h","mode_used":"redact"}`)
	RunScrubHistory([]string{"--mode=redact"})

	// no sensitive entries (final else in human output)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":0,"mode_used":"delete"}`)
	RunScrubHistory(nil)

	// error response when jsonOutput is true
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"error","message":"something broke"}`)
	RunScrubHistory([]string{"--json"})

	// dry-run human output with preview examples (exercises more dry-run printing logic)
	sendDaemonCommandFn = mockSendDaemonCommand(`{
		"status":"ok",
		"dry_run":true,
		"mode_used":"redact",
		"file":"/tmp/hist",
		"would_delete":0,
		"would_redact":1,
		"secrets_found":1,
		"preview":{
			"example_scrubbed_lines":["curl -H 'Authorization: Bearer [REDACTED]' https://ex"]
		}
	}`)
	RunScrubHistory([]string{"--dry-run"})

	// --file= override (exercises the arg building path)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":0}`)
	RunScrubHistory([]string{"--file=/custom/history", "--mode=delete"})

	// multi-target redact (exercises aggregate "redacted" fallback so human output
	// does not lie with the "no sensitive entries" message for multi redact runs)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","redacted":4,"secrets":6,"mode_used":"redact","targets":3,"changed":true,"message":"Redacted 6 secret occurrence(s) across 4 entr(ies) in 2 artifact(s)"}`)
	RunScrubHistory(nil)

	// disabled in human (non-json) path; must not fall through to generic success message
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","message":"Pillar 3 (history hygiene) is disabled in config","file":""}`)
	RunScrubHistory(nil)

	// --full/--reset and bare --mode (non-=) flag parser branches (previously 0 blocks)
	RunScrubHistory([]string{"--full"})
	RunScrubHistory([]string{"--reset"})
	RunScrubHistory([]string{"--mode", "redact"})
}
