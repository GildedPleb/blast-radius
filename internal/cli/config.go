package cli

import "fmt"

// RunConfig handles subcommands under "blastradius config".
// The previous "config redaction" subcommand was removed with the redaction/recorder pillar.
func RunConfig(args []string) {
	if len(args) == 0 {
		fmt.Println("The 'config' command surface was reduced after removal of the redaction pillar.")
		fmt.Println("See config.example.yaml and the idiomatic_pillars.md documentation for current settings.")
		return
	}
	fmt.Println("unknown config subcommand (the previous 'redaction' subcommand no longer exists)")
}
