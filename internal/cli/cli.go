package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

const (
	socketConnectTimeout = 2 * time.Second
	daemonStartWait      = 500 * time.Millisecond
)

// Overridable for testing (DI via var assignment)
var (
	configLoad            = config.Load
	netDialTimeout        = net.DialTimeout
	execCommand           = exec.Command
	osReadFile            = os.ReadFile
	osUserHomeDir         = os.UserHomeDir
	sendDaemonCommandFn       = realSendDaemonCommand
	sendRecorderCommandFn     = realSendRecorderCommand
	sendRecorderReplayRequestFn = realSendRecorderReplayRequest
	osExit                    = os.Exit
)

// Run is the single coordinator entrypoint for all CLI commands. It owns
// command dispatch, special-case flag handling (e.g. status --json, check-hash),
// and routing to the individual Run* implementations.
//
// This fulfills the Phase 3 "remove the old dispatcher" intent in spirit: the
// thin cmd/blastradius/main.go now delegates everything here. The coordinator
// package is the only place that needs to understand the full user-facing and
// internal command surface (including the "daemon" and "recorder" subcommands
// used for detached lifecycle management).
func Run(osArgs []string) {
	if len(osArgs) == 0 {
		PrintHelp()
		return
	}

	cmd := osArgs[0]
	tail := osArgs[1:]

	switch cmd {
	case "start":
		RunStart()
	case "status":
		jsonOutput := len(tail) > 0 && tail[0] == "--json"
		RunStatus(jsonOutput)
	case "protection":
		RunProtection(tail)
	case "stop", "halt":
		RunStop()
	case "logs":
		RunLogs()
	case "duplicates":
		RunDuplicates()
	case "scrub-history", "scrub_history":
		RunScrubHistory()
	case "redact":
		RunRedact(tail)
	case "check-hash":
		if len(tail) < 1 {
			fmt.Println(`{"known":false,"error":"missing hash argument"}`)
			return
		}
		RunCheckHash(tail[0])
	// "daemon" and "recorder" are internal-only (launched by start/protection
	// via os/exec of the same binary). They are intentionally not documented
	// in help output for end users.
	case "daemon":
		RunDaemon()
	case "recorder":
		RunRecorder(tail)
	case "env":
		name := ""
		if len(tail) > 0 {
			name = tail[0]
		}
		RunEnvCheck(name)
	case "clipboard":
		RunClipboard(tail)
	case "config":
		RunConfig(tail)
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		PrintHelp()
		osExit(1)
	}
}

// IsHelp is exported so the ultra-thin main.go can do the pre-dispatch check
// without duplicating the strings. All real logic lives in the coordinator.
func IsHelp(arg string) bool {
	return arg == "help" || arg == "--help" || arg == "-h"
}
