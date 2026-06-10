package cli

import (
	"fmt"
	"os"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// removeConfigFile is overridable for tests (hermetic reset error injection).
// Production default set here; resetTestOverrides and per-test code can replace it.
var removeConfigFile = config.RemoveConfigFile

// RunValidate is the onboarding / full-diagnosis / reset entrypoint.
// `blastradius validate` (and the alias `init`) runs the complete set of
// readiness checks across all pillars and emits actionable guidance.
// --reset deletes the current config so the next touch will recreate a fresh
// virgin template (useful for testing the first-run flow or starting over).
//
// The command itself always performs (and reports) the full validation even
// if some pillars are intentionally disabled by the user. Exit code is 0 only
// when every pillar reports substantive user content for the sections that
// have requirements.
func RunValidate(tail []string) {
	reset := false
	for _, a := range tail {
		if a == "--reset" {
			reset = true
		}
	}

	if reset {
		if err := removeConfigFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reset config: %v\n", err)
			osExit(1)
			return
		}
		fmt.Println("Config reset. A fresh initial template will be created on next command.")
	}

	// Force creation of (or detect) the template so the user sees the file.
	p, created, _ := ensureConfig()
	if created {
		fmt.Printf("Created initial config template at %s\n", p)
	} else if p != "" {
		fmt.Printf("Config: %s\n", p)
	}

	cfg, _, loadErr := configLoad()
	if loadErr != nil {
		// Still try to report something useful
		fmt.Fprintf(os.Stderr, "Warning: config load error: %v\n", loadErr)
	}

	fmt.Println("Blast Radius — Configuration Validation (all pillars)")
	fmt.Println("======================================================")

	issues := 0

	// P1
	if cfg != nil {
		if env, ok := cfg.Pillar1.Sources["env"]; ok && env.Enabled {
			roots := cfg.GetEnvOptions().ProjectRoots
			if len(roots) == 0 {
				fmt.Println("Pillar 1 (env): ACTION REQUIRED — project_roots is empty.")
				fmt.Println("  Edit pillar1.sources.env.options.project_roots and add real directories.")
				issues++
			} else {
				fmt.Printf("Pillar 1 (env): %d project root(s) configured.\n", len(roots))
			}
		} else {
			fmt.Println("Pillar 1 (env): disabled (or not explicitly enabled) — P1-dependent commands will be limited.")
		}
		if bw, ok := cfg.Pillar1.Sources["bitwarden"]; ok && bw.Enabled {
			fmt.Println("Pillar 1 (bitwarden): enabled — runtime checks (bw in PATH + unlocked) happen on first use/rescan.")
		}
	}

	// P2
	if cfg != nil && cfg.Pillar2.Enabled {
		fmt.Println("Pillar 2 (crumbs): enabled — using configured dirs[]. (P1 authority still enforced at scan time.)")
	} else {
		fmt.Println("Pillar 2 (crumbs): disabled in initial template. Set enabled: true + configure dirs[] to use 'crumbs'.")
	}

	// P3
	if cfg != nil && cfg.Pillar3.Enabled {
		fmt.Printf("Pillar 3 (history): enabled, mode=%s — ready.\n", cfg.Pillar3.Mode)
	} else {
		fmt.Println("Pillar 3 (history): disabled in initial template. Set enabled: true to use 'scrub-history'.")
	}

	// P4
	if cfg != nil {
		if cfg.Pillar4.Enabled {
			fmt.Printf("Pillar 4 (env): enabled, %d command(s) configured.\n", len(cfg.Pillar4.Commands))
		} else {
			fmt.Println("Pillar 4 (env): disabled in initial template. Set enabled: true under pillar4 to use 'blastradius env'.")
		}
	}

	// P5
	if cfg != nil {
		if cfg.Pillar5.Enabled {
			fmt.Printf("Pillar 5 (clipboard): enabled, monitor=%v, alerts=%v.\n",
				cfg.Pillar5.MonitorEnabled, cfg.Pillar5.AlertsEnabled)
		} else {
			fmt.Println("Pillar 5 (clipboard): disabled in initial template. Set enabled: true under pillar5 if you want any clipboard hygiene (this is the master switch that prevents any clipboard reading).")
		}
	}

	fmt.Println("======================================================")

	if issues > 0 {
		fmt.Println("Some pillars still have virgin template data for sections they expose.")
		fmt.Println("Fix the items above, then re-run 'blastradius validate' or the original command.")
		osExit(1)
		return
	}

	fmt.Println("All checked pillars have substantive content or are deliberately disabled.")
	fmt.Println("You can now use the commands whose pillars you have configured.")
}

// (P1 "incomplete" signal for the report is simply: env enabled + len(project_roots) == 0.
// The initial template writes an empty list on purpose. See config.ValidateReadiness
// and the comments inside the generated config for the full rationale.)
