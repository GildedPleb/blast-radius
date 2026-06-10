package cli

import (
	"fmt"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// PrintHelp displays the main help message and current configuration.
func PrintHelp() {
	cfg, configPath, _ := configLoad()
	if cfg == nil {
		cfg = &config.Config{} // defensive; SocketPath is now a hard-coded invariant
	}

	fmt.Println("Blast Radius - Secret exposure reduction tool")
	fmt.Println()
	fmt.Printf("Config: %s\n", configPath)
	fmt.Println()
	fmt.Println("Settings:")
	envOpts := cfg.GetEnvOptions()
	if len(envOpts.ProjectRoots) > 0 {
		fmt.Printf("  Pillar 1 roots: %v\n", envOpts.ProjectRoots)
	} else {
		fmt.Println("  Pillar 1 roots: (not configured - will scan home directory)")
	}
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  start                Start the background daemon")
	fmt.Println("  status [--json]      Show daemon and registry status (does not start daemon)")
	fmt.Println("  stop, halt           Gracefully stop the running daemon")
	fmt.Println("  logs                 Show recent daemon log output")
	fmt.Println("  duplicates           Show secret hashes duplicated across multiple projects (Pillar 1)")
	fmt.Println("  scrub-history        Scrub shell history of known secret values (Pillar 3)")
	fmt.Println("                         --mode=delete|redact  --dry-run  --json  --file=PATH")
	fmt.Println("  rescan               Trigger manual Pillar 1 discovery refresh (on-demand only)")
	fmt.Println("  env [--json] [name]  Run Pillar 4 primitive (default: printenv; --json for prompt/machine readers)")
	fmt.Println("  clipboard            Pillar 5: status|check|clear|nuke|scrub|redact (macOS primitives + monitor-backed alerts + two-tier auto)")
	fmt.Println("  crumbs               Pillar 2: locate forgotten vault exports & high-entropy dumps in high-risk dirs")
	fmt.Println("  config               Show configuration")
	fmt.Println("  help                 Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  blastradius start")
	fmt.Println("  blastradius status --json")
	fmt.Println()
	fmt.Println("For more information, see the repository README.")
}
