package cli

import "fmt"

// RunCheckHash is used by Zsh redaction layer (Phase 4) to query if a SHA-256 hex is known.
func RunCheckHash(hexHash string) {
	line, err := sendDaemonCommand(fmt.Sprintf("CHECK_HASH %s", hexHash))
	if err != nil {
		// Daemon not running — treat as unknown (safe default)
		fmt.Println(`{"known":false,"message":"daemon not running"}`)
		return
	}
	fmt.Print(line) // already JSON
}
