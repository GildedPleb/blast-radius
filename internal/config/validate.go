package config

import "fmt"

// ValidateReadiness performs the shallow, declarative, contextual check described
// in the first-run design.
//
// For a normal command (e.g. "rescan", "crumbs", "scrub-history", "env", "start"):
//   - Only the pillars that command actually needs are examined.
//   - A pillar section is "not ready" only when a source it cares about is
//     (or would be) enabled *and* its critical data still exactly matches the
//     known initial values emitted by the virgin template generator.
//   - Explicitly disabled sources, empty lists (where the pillar supports the
//     documented fallback), or any deviation from the virgin emitted data are
//     treated as substantive user content → ready for that command.
//
// For cmd == "validate" (or "init", or "*"): a full cross-pillar report is
// produced (the function still returns a single error or nil; the validate
// command itself renders the nice multi-pillar output).
//
// Readiness is decided *solely* from the parsed data values. Instructional
// comments or banner text that remain in the file have no effect on the result.
// This upholds the invariant that no meta "setup_complete"/"reviewed" flag
// (or equivalent) is used or respected.
//
// The implementation is deliberately tiny and must not duplicate collector,
// scanner, normalize, or Classifier logic.
func ValidateReadiness(cmd string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("no configuration loaded")
	}

	needs := requiredPillarsFor(cmd)
	if len(needs) == 0 {
		return nil // lenient commands (help, config, logs, stop, etc.)
	}

	for _, p := range needs {
		if err := checkPillarReadiness(p, cfg, cmd); err != nil {
			return err
		}
	}
	return nil
}

// requiredPillarsFor is the tiny declarative map from command (or alias) to the
// pillars whose substantive content must be present for that command to proceed.
// Unrelated pillars are ignored (contextual validation).
func requiredPillarsFor(cmd string) []string {
	switch cmd {
	case "validate", "init", "*":
		return []string{"p1", "p2", "p3", "p4", "p5"}
	case "start", "status", "rescan", "duplicates", "env":
		return []string{"p1"}
	case "crumbs":
		return []string{"p2"}
	case "scrub-history", "scrub_history":
		return []string{"p3"}
	case "clipboard":
		return []string{"p5"}
	default:
		return nil // logs, config, help, stop, halt, unknown — no gate
	}
}

// checkPillarReadiness contains the shallow per-pillar data-equality tests.
// It returns a precise, actionable error (naming the exact config key(s) and
// what the user must do) when the pillar is required and still carries only
// virgin template data for an enabled / relevant source.
func checkPillarReadiness(p string, cfg *Config, cmd string) error {
	switch p {
	case "p1":
		// P1 (env source) is the foundation. In the initial template we ship it
		// enabled: true but with an *empty* project_roots list on purpose.
		// The substantive user action is declaring where their real projects live.
		envSrc, envOK := cfg.Pillar1.Sources["env"]
		if envOK && envSrc.Enabled {
			roots := cfg.GetEnvOptions().ProjectRoots
			if len(roots) == 0 {
				return fmt.Errorf(`Pillar 1 env source is enabled but project_roots is empty.

ACTION REQUIRED (to use commands that need Pillar 1: %s, rescan, duplicates, status details, env, start, etc.):
  Edit %s and add at least one real directory under pillar1.sources.env.options.project_roots
  (or set enabled: false on the env source if you only intend to use bitwarden, or another source).

The initial template leaves project_roots empty because the tool does not know (and should not guess)
your project locations. Universal safe skips (node_modules, .git, common non-secret env vars, etc.)
are pre-populated because they are not specific to you.
See the comments in the generated config and in config.example.yaml for full Pillar 1 documentation.`,
					cmd, mustConfigPath())
			}
		}
		// bitwarden (when the user has explicitly enabled it) has no additional mandatory
		// data in the initial template. Its runtime prereqs are handled best-effort later
		// by the collector Validate path (only when enabled).
		return nil

	case "p2":
		if !cfg.Pillar2.Enabled {
			return fmt.Errorf(`Pillar 2 (crumbs) is disabled in config.

ACTION REQUIRED (to use 'blastradius crumbs' and related Pillar 2 functionality):
  Edit %s and set enabled: true under pillar2, then configure the high-risk dirs[] surfaces
  that matter in your workflow (see the examples and comments in the file and in config.example.yaml).

Pillar 2 is deliberately opt-in because it scans for residue in places like Downloads/Documents/Desktop.
`, mustConfigPath())
		}
		return nil

	case "p3":
		if !cfg.Pillar3.Enabled {
			return fmt.Errorf(`Pillar 3 (history hygiene) is disabled in config.

ACTION REQUIRED (to use 'blastradius scrub-history' and related Pillar 3 functionality):
  Edit %s and set enabled: true under pillar3 (and choose mode: delete or redact, etc. if desired).

Pillar 3 is opt-in so that you must explicitly turn on history scrubbing before the tool will
touch your shell history files.
`, mustConfigPath())
		}
		return nil

	case "p4":
		if !cfg.Pillar4.Enabled {
			return fmt.Errorf(`Pillar 4 is disabled in config.

ACTION REQUIRED (to use 'blastradius env [name]'):
  Edit %s and set enabled: true under pillar4 (the pillar-level opt-in, consistent
  with Pillar 2/3/5). The commands list below it can then be reviewed/customized.

This flag exists so you have an explicit, cross-pillar way to completely disable
the runtime environment hygiene primitive if you do not want it active.
`, mustConfigPath())
		}
		// Even when enabled, require at least one usable command (defense in depth).
		hasUsable := false
		for _, c := range cfg.Pillar4.Commands {
			if c.Cmd != "" {
				hasUsable = true
				break
			}
		}
		if !hasUsable {
			return fmt.Errorf(`Pillar 4 is enabled but has no usable commands configured.

ACTION REQUIRED (to use 'blastradius env [name]'):
  Edit %s under pillar4.commands and ensure at least one entry has a real "cmd".
  All pillar4 commands are executed via direct exec (hard security invariant — no shell).
`, mustConfigPath())
		}
		return nil

	case "p5":
		if !cfg.Pillar5.Enabled {
			return fmt.Errorf(`Pillar 5 (clipboard hygiene) is disabled in config.

ACTION REQUIRED (to use 'blastradius clipboard' commands):
  Edit %s and set enabled: true under pillar5.

This is the explicit master switch for the entire pillar. When disabled, nothing
in Blast Radius will read or act on clipboard contents (neither the background
monitor nor the explicit primitives will be considered "ready" by validation).
Use this if you do not want the daemon or CLI ever touching your copy-paste data.
`, mustConfigPath())
		}
		return nil
	}
	return nil
}
