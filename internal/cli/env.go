package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// RunEnvCheck is the Pillar 4 primitive function call.
// It runs the named command (from pillar4.commands), searches its output
// content for known secrets (via unified detection + registry), surfaces
// a count in JSON and logs the result (to daemon log) — without ever
// showing secret values. --json is accepted by the caller for prompt readers.
// The function does one thing only; timers/prompt wiring are later.
func RunEnvCheck(name string) {
	_ = logging.Init(getDaemonLogPathFn())

	if name == "" {
		name = "default-env"
	}
	logging.Printf("RunEnvCheck: running Pillar 4 primitive %q", name)

	cfg, _, err := configLoad()
	if err != nil {
		logging.Printf("RunEnvCheck: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
		return
	}

	// Find the command definition.
	var cmd config.RuntimeCommand
	for _, c := range cfg.Pillar4.Commands {
		if c.Name == name {
			cmd = c
			break
		}
	}
	if cmd.Name == "" {
		logging.Printf("RunEnvCheck: unknown pillar4 primitive command: %s", name)
		fmt.Printf(`{"status":"error","message":"unknown pillar4 primitive command: %s"}`+"\n", name)
		return
	}

	// Hard security invariant: commands are always executed via direct exec (no shell).
	// This eliminates an entire class of injection and arbitrary execution risks from config.
	// strings.Fields is naive (no quote support); complex args require a wrapper script you control.
	// We still protect against shell injection because we never pass the string to a shell.
	// The metachar check is a heuristic warning only (the set is not exhaustive for every
	// shell/context; newlines, quotes, globs, ~, etc. are also treated as literal argv elements).
	if strings.ContainsAny(cmd.Cmd, ";|&`$(){}[]<>") {
		logging.Printf("RunEnvCheck: pillar4 cmd %q contains shell-like metacharacters; they become literal argv tokens (per docs: point at a wrapper script for pipes/logic)", cmd.Cmd)
	}
	parts := strings.Fields(cmd.Cmd)
	if len(parts) == 0 {
		fmt.Printf(`{"status":"error","message":"empty command (pillar4 primitive)"}` + "\n")
		return
	}
	// Resolve bare names (no / or ./ prefix) via LookPath when possible. This reduces
	// PATH hijack / cwd resolution risk for the P4 primitive while preserving user
	// intent for explicit relative/absolute paths in pillar4.commands. Complex cases
	// (spaces in args, pipes, env setup) are documented to use a wrapper script.
	// We use the shared util.ResolveCommand helper (deduped with P1/P5 tool resolution).
	prog := parts[0]
	if !strings.Contains(prog, "/") && !strings.HasPrefix(prog, ".") {
		prog = util.ResolveCommand(prog)
	}
	output, runErr := execCommand(prog, parts[1:]...).CombinedOutput()

	// Always search the output content (the core job of the Pillar 4 primitive).
	// Even on nonzero exit the command may have emitted secret material
	// (common with kubectl, wrappers, etc.). We still want to alert.
	candidates := detection.NewDetector().ExtractCandidates(output)

	if runErr != nil {
		logging.Printf("RunEnvCheck: command failed: %v (output was still searched)", runErr)
		// fall through to do the check+count so we can surface secrets_found
		// even for failing commands, then emit error JSON containing the count.
	}

	// Send candidate secret values (not whole lines) to daemon for hashing/checking.
	// This uses the unified detection logic so that realistic output like
	// "KEY=supersecretvalue" or "export FOO=..." is correctly handled.
	known, err := batchCheckKnownSecrets(candidates)
	if err != nil {
		logging.Println("RunEnvCheck: daemon not running")
		fmt.Println(`{"status":"error","message":"daemon not running"}`)
		return
	}
	found := len(known)

	logging.Printf("RunEnvCheck: command=%s, secrets_found=%d", name, found)

	if runErr != nil {
		fmt.Printf(`{"status":"error","message":"command failed: %v","secrets_found":%d}`+"\n", runErr, found)
		return
	}
	fmt.Printf(`{"status":"ok","command":"%s","secrets_found":%d}`+"\n", name, found)
}
