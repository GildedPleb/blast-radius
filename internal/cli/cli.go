package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
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

	// ensureConfig is overridable for tests. Production calls the real
	// config.EnsureConfigFile (first-touch template creation).
	ensureConfig      = config.EnsureConfigFile
	validateReadiness = config.ValidateReadiness
)

// hasResetFlag reports whether --reset appears anywhere in the args.
// This is the single source of truth for the recovery path that must
// still work even when the config file is completely unparseable.
func hasResetFlag(args []string) bool {
	return slices.Contains(args, "--reset")
}

// Run is the single coordinator entrypoint for all CLI commands. It owns
// command dispatch, special-case flag handling (e.g. status --json, check-hash),
// and routing to the individual Run* implementations.
//
// The coordinator is the only place that needs to understand the full
// user-facing and internal command surface (including the internal "daemon"
// subcommand used for detached lifecycle management).
func Run(osArgs []string) {
	if len(osArgs) == 0 {
		// Bare invocation still participates in first-touch creation (frictionless)
		// but is intentionally lenient for the readiness gate (help is always safe).
		_, _, _ = ensureConfig()
		PrintHelp()
		return
	}

	cmd := osArgs[0]
	tail := osArgs[1:]

	// First-touch creation (writes the intentionally incomplete template with
	// virgin example data values exactly once). The triggering command then
	// runs the contextual ValidateReadiness gate below.
	if p, created, cerr := ensureConfig(); cerr == nil && created {
		fmt.Printf("Created initial config template at %s\n", p)
	}

	// Contextual hard validation for every command.
	// ValidateReadiness is deliberately shallow (data equality against the
	// known virgin emitted values for the pillars this cmd needs) and already
	// returns nil for lenient commands (help, config, logs, etc.).
	// Instructional comments / banner text in the file have no effect.
	cfg, configPath, lerr := configLoad()
	if lerr != nil {
		// Only allow validate/init --reset through as a recovery path.
		// Everything else must die if we can't even read the config.
		if (cmd == "validate" || cmd == "init") && hasResetFlag(tail) {
			// fall through to RunValidate which already handles --reset + load error
		} else {
			fmt.Fprintf(os.Stderr, "FATAL: failed to load config from %s: %v\n", configPath, lerr)
			fmt.Fprintln(os.Stderr, "The config file is unreadable. Fix the YAML or run:")
			fmt.Fprintln(os.Stderr, "    blastradius validate --reset")
			osExit(1)
			return
		}
	} else if verr := validateReadiness(cmd, cfg); verr != nil {
		fmt.Fprintln(os.Stderr, verr.Error())
		osExit(1)
		return
	}

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
	case "validate", "init":
		RunValidate(tail)
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
