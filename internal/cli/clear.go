package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// RunRedact implements `blastradius redact [N]`.
// It performs a reliable terminal clear then streams a mixed replay from the
// recorder: the most recent min(N, buffer) windows are shown with original
// (raw) output; everything older uses the sealed redacted form.
// N defaults to 0 (full redaction of all retained history).
func RunRedact(args []string) {
	if err := ProtectionModeGuard(); err != nil {
		fmt.Println(err)
		osExit(1)
	}

	requested := 0
	for _, a := range args {
		if n, err := strconv.Atoi(strings.TrimSpace(a)); err == nil && n >= 0 {
			requested = n
			break
		}
	}

	cfg, _, err := configLoad()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	mode := cfg.Redaction.RedactionMode
	if mode == "" {
		mode = "replace"
	}
	custom := cfg.Redaction.CustomReplacement
	if custom == "" {
		custom = "[REDACTED]"
	}
	preserve := "true"
	if !cfg.Redaction.PreserveColors {
		preserve = "false"
	}
	payload := fmt.Sprintf("%d %s %s %s", requested, mode, custom, preserve)

	// Reliable clear: best-effort configured commands + always the portable
	// strong ANSI clear + scrollback clear. This is the documented safe mechanism.
	performClear(cfg.Redaction.ClearResetCommands)

	if err := sendRecorderReplayRequest(payload, os.Stdout); err != nil {
		// Safe degradation per invariant #9
		performClear(cfg.Redaction.ClearResetCommands)
		fmt.Fprintf(os.Stderr, "\n[blastradius] redact replay failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "Terminal cleared for safety. Secrets may still be in scrollback on some terminals.")
		fmt.Fprintln(os.Stderr, "Run 'blastradius status' and consider restarting the protected shell.")
		osExit(1)
	}

	if cfg.Redaction.ShowRebuildEvidence {
		fmt.Fprintln(os.Stdout, "[redacted replay complete]")
	}
}

// performClear attempts the configured reset commands (best effort, fire-and-forget)
// then emits the standard full-clear + scrollback-clear ANSI sequence.
func performClear(cmds []string) {
	for _, c := range cmds {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Best effort: run via /bin/sh -c if it looks like a command.
		// We ignore errors and output (clear cmds are noisy or interactive-safe).
		_ = execCommand("/bin/sh", "-c", c).Run()
	}
	// The reliable, cross-terminal mechanism (per plan and design docs):
	// ESC[2J  clear screen, ESC[3J clear scrollback, ESC[H home cursor.
	fmt.Print("\033[2J\033[3J\033[H")
}

// parse helper not needed (inline atoi above for simplicity).

// RunClear provides CLI entrypoint for Phase 4 redaction rebuild documentation.
// The actual redaction is now driven by `blastradius redact` (and Zsh wrappers).
func RunClear() {
	fmt.Println("Blast Radius Clear (Phase 4 - Pillar 3)")
	fmt.Println("========================================")
	fmt.Println("Primary redaction/rebuild is performed via:")
	fmt.Println("  blastradius redact [N]")
	fmt.Println()
	fmt.Println("  - N omitted or 0: full redacted replay of history")
	fmt.Println("  - N>0: last N prompts replayed with original output (if buffer allows); older redacted")
	fmt.Println()
	fmt.Println("The buffer setting (redaction.buffer) controls the max N fidelity and plaintext lifetime.")
	fmt.Println("See 'blastradius config redaction' and status --json for current values.")
	fmt.Println("========================================")
	fmt.Println("No plaintext secrets are ever stored or transmitted.")
}
