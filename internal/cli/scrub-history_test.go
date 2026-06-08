package cli

import (
	"strings"
	"testing"
)

func TestRunScrubHistory(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// no daemon
	RunScrubHistory(nil)

	// no daemon + --json (exercises the jsonOutput=true branch that prints
	// the compact JSON error instead of the human daemonNotRunningMsg)
	RunScrubHistory([]string{"--json"})

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

	sendDaemonCommandFn = mockSendDaemonCommand(`this is not valid json at all`)
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

	// two-token --file VALUE and -f VALUE forms (exercises the exact uncovered
	// parser branch: case t == "--file" || t == "-f": with value in tail[i+1])
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":1,"file":"/tmp/two token"}`)
	RunScrubHistory([]string{"--file", "/tmp/two token", "--dry-run"})

	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":0}`)
	RunScrubHistory([]string{"-f", "/tmp/shortform"})

	// spaced path in --file (two-token form and = form). This would have regressed
	// before the parser fixes (Fields + HasPrefix on the tail would mangle the value
	// when building the daemon command string, and the handler would re-split).
	var sent string
	sendDaemonCommandFn = func(cmd string) (string, error) {
		sent = cmd
		return `{"status":"ok","lines_removed":0}`, nil
	}
	RunScrubHistory([]string{"--file=/tmp/dir with spaces/my history", "--dry-run"})
	if !strings.Contains(sent, "with spaces") {
		t.Errorf("spaced path lost in --file daemon command construction; got %q", sent)
	}

	// multi-target redact (exercises aggregate "redacted" fallback so human output
	// does not lie with the "no sensitive entries" message for multi redact runs)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","redacted":4,"secrets":6,"mode_used":"redact","targets":3,"changed":true,"message":"Redacted 6 secret occurrence(s) across 4 entr(ies) in 2 artifact(s)"}`)
	RunScrubHistory(nil)

	// disabled in human (non-json) path; must not fall through to generic success message
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","message":"Pillar 3 (history hygiene) is disabled in config","file":""}`)
	RunScrubHistory(nil)

	// real run with lines_removed > 0 + mode_used=redact + secrets_found
	// (exercises the inner "(redact mode; N secret occurrence(s) replaced)"
	// printf that only lives inside the hasRemoved && removed > 0 branch)
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","lines_removed":5,"file":"/tmp/hist","mode_used":"redact","secrets_found":7}`)
	RunScrubHistory([]string{"--mode=redact"})

	// --full/--reset and bare --mode (non-=) flag parser branches (previously 0 blocks)
	RunScrubHistory([]string{"--full"})
	RunScrubHistory([]string{"--reset"})
	RunScrubHistory([]string{"--mode", "redact"})
}
