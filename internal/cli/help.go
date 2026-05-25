package cli

import "fmt"

// PrintHelp displays the main help message and current configuration.
func PrintHelp() {
	cfg, configPath, _ := configLoad()

	fmt.Println("Blast Radius - Secret exposure reduction tool")
	fmt.Println()
	fmt.Printf("Config: %s\n", configPath)
	fmt.Println()
	fmt.Println("Settings:")
	fmt.Printf("  Socket:        %s\n", cfg.SocketPath)
	if len(cfg.ProjectRoots) > 0 {
		fmt.Printf("  Project Roots: %v\n", cfg.ProjectRoots)
	} else {
		fmt.Println("  Project Roots: (not configured - will scan home directory)")
	}
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  start          Start the background daemon")
	fmt.Println("  status [--json] Show daemon and registry status (does not start daemon)")
	fmt.Println("  stop, halt     Gracefully stop the running daemon")
	fmt.Println("  logs           Show recent daemon log output")
	fmt.Println("  duplicates     Show secret hashes duplicated across multiple projects (Pillar 1)")
	fmt.Println("  scrub-history  Scrub shell history of known secret values (Pillar 4)")
	fmt.Println("  clear          Trigger or document Phase 4 redaction rebuild (Pillar 3)")
	fmt.Println("  env [name]     Run Pillar 5 runtime hygiene check (default: printenv)")
	fmt.Println("  clipboard      Pillar 2 clipboard status / clear (macOS)")
	fmt.Println("  help           Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  blastradius start")
	fmt.Println("  blastradius status")
	fmt.Println("  blastradius duplicates")
	fmt.Println("  blastradius scrub-history")
	fmt.Println("  blastradius stop")
	fmt.Println()
	fmt.Println("For more information, see the repository README.")
}
