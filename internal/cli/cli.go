package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

const (
	socketConnectTimeout = 2 * time.Second
	daemonStartWait      = 500 * time.Millisecond
)

// Overridable for testing (DI via var assignment). See RunDaemon, RunStart etc.
// for how error arms use explicit "return" after osExit(1) so that test-time
// no-op overrides (which do not terminate the process) do not fall through into
// success-path code that assumes a non-nil *config.Config (or other post-load
// state). This is the contract for all osExit call sites.
var (
	configLoad          = config.Load
	netDialTimeout      = net.DialTimeout
	execCommand         = exec.Command
	osReadFile          = os.ReadFile
	osUserHomeDir       = os.UserHomeDir
	osExecutable        = os.Executable
	getDaemonLogPathFn  = getDaemonLogPath
	sendDaemonCommandFn = realSendDaemonCommand
	runDaemon           = RunDaemon
	osExit              = os.Exit
)

// Run is the single coordinator entrypoint for all CLI commands. It owns
// command dispatch, special-case flag handling (e.g. status --json, check-hash),
// and routing to the individual Run* implementations.
//
// The coordinator is the only place that needs to understand the full
// user-facing and internal command surface (including the internal "daemon"
// subcommand used for detached lifecycle management).
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
	case "stop", "halt":
		RunStop()
	case "logs":
		RunLogs()
	case "duplicates":
		RunDuplicates()
	case "scrub-history", "scrub_history":
		RunScrubHistory(tail)
	case "check-hash":
		if len(tail) < 1 {
			fmt.Println(`{"known":false,"error":"missing hash argument"}`)
			return
		}
		RunCheckHash(tail[0])
	// "daemon" is internal-only (launched by start via os/exec).
	// It is intentionally not documented in help output for end users.
	case "daemon":
		runDaemon()
	case "env":
		name := ""
		unexpected := []string{}
		for _, t := range tail {
			if t == "--json" {
				continue // for prompt/machine reading; RunEnvCheck always emits JSON
			}
			if name == "" {
				name = t
			} else {
				unexpected = append(unexpected, t)
			}
		}
		if len(unexpected) > 0 {
			fmt.Printf(`{"status":"error","message":"unexpected arguments for env: %s"}`+"\n", strings.Join(unexpected, " "))
			return
		}
		RunEnvCheck(name)
	case "clipboard":
		RunClipboard(tail)
	case "config":
		RunConfig(tail)
	case "crumbs":
		jsonOutput := len(tail) > 0 && tail[0] == "--json"
		RunCrumbs(jsonOutput)
	case "rescan":
		jsonOutput := len(tail) > 0 && tail[0] == "--json"
		RunRescan(jsonOutput)
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
