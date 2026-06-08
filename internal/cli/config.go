package cli

import (
	"fmt"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// testOverrides lets tests inject config load results.
var testOverrides struct {
	cfg     *config.Config
	path    string
	loadErr error
}

// RunConfig shows the current configuration location and a summary of key settings.
// It is the "basic config surface" (no subcommands in the current design).
func RunConfig(args []string) {
	if len(args) > 0 {
		fmt.Printf("unknown config subcommand: %s\n", args[0])
		fmt.Println("The 'config' command currently takes no arguments. It shows the config file location and a summary of loaded settings.")
		return
	}

	cfg, configPath, err := configLoad()
	loadErr := err
	if cfg == nil {
		cfg = &config.Config{}
	}

	pathToPrint := configPath
	if pathToPrint == "" {
		pathToPrint = "(test override)"
	}
	fmt.Printf("Config: %s\n", pathToPrint)
	fmt.Printf("Socket: %s\n", config.SocketPath())

	envOpts := cfg.GetEnvOptions()
	if len(envOpts.ProjectRoots) > 0 {
		fmt.Printf("Pillar 1 roots: %v\n", envOpts.ProjectRoots)
	} else {
		fmt.Println("Pillar 1 roots: (not configured — will scan home directory)")
	}

	// Pillar enabled / interesting surface summary (non-sensitive)
	fmt.Printf("Pillar 2 (crumbs):     enabled=%v, surfaces=%d\n", cfg.Pillar2.Enabled, len(cfg.Pillar2.Dirs))
	fmt.Printf("Pillar 3 (history):    enabled=%v, mode=%s\n", cfg.Pillar3.Enabled, cfg.Pillar3.Mode)
	fmt.Printf("Pillar 4 (env) cmds:   %d configured (use 'blastradius env' to invoke)\n", len(cfg.Pillar4.Commands))
	p5 := cfg.Pillar5
	fmt.Printf("Pillar 5 (clipboard):  monitor=%v, alerts=%v, redact=%ds / clear=%ds\n",
		p5.MonitorEnabled, p5.AlertsEnabled, p5.RedactTimeoutSeconds, p5.FullClearTimeoutSeconds)

	if loadErr != nil {
		fmt.Printf("Note: using defaults due to load error: %v\n", loadErr)
	}

	fmt.Println()
	fmt.Println("Edit the YAML file and restart the daemon for most changes to take effect.")
	fmt.Println("See config.example.yaml and docs/pillars/idiomatic_pillars.md for full documentation.")
}
