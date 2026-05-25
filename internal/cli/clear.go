package cli

import "fmt"

// RunClear provides CLI entrypoint for Phase 4 redaction rebuild.
// In practice, the heavy lifting is done by the Zsh `blastradius_clear` function per-terminal.
// This CLI command can be used to trigger a global awareness or future cross-terminal features.
func RunClear() {
	fmt.Println("Blast Radius Clear (Phase 4 - Pillar 3)")
	fmt.Println("========================================")
	fmt.Println("The primary redaction/rebuild is performed per-terminal via the Zsh function:")
	fmt.Println("  br-clear   or   blastradius_clear")
	fmt.Println()
	fmt.Println("This triggers:")
	fmt.Println("  - Full terminal + scrollback wipe")
	fmt.Println("  - Replay of redacted session history (from live typescript capture)")
	fmt.Println("  - HUD update and state reset")
	fmt.Println()
	fmt.Println("To enable automatic redaction after sensitive commands, ensure your Zsh hooks are installed:")
	fmt.Println("  source ~/.config/blastradius/blastradius.zsh  (or wherever installed)")
	fmt.Println("========================================")
	fmt.Println("No plaintext secrets are ever stored or transmitted.")
}
