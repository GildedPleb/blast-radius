package cli

import (
	"crypto/sha256"
	"fmt"

	"github.com/GildedPleb/blast-radius/internal/logging"
)

// RunClipboard handles Pillar 2 clipboard operations (macOS only for v1)
func RunClipboard(args []string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status", "check":
		logging.Println("RunClipboard: checking clipboard")
		out, err := execCommand("pbpaste").Output()
		if err != nil {
			logging.Println("RunClipboard: pbpaste failed")
			fmt.Println(`{"status":"error","message":"pbpaste failed (macOS only)"}`)
			return
		}
		hash := sha256.Sum256(out)
		hashHex := fmt.Sprintf("%x", hash[:])
		resp, err := sendDaemonCommand(fmt.Sprintf("CHECK_HASH %s", hashHex))
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
		}
		fmt.Print(resp)
	case "clear":
		logging.Println("RunClipboard: clearing clipboard")
		execCommand("pbcopy").Run()
		fmt.Println(`{"status":"ok","message":"clipboard cleared"}`)
	default:
		fmt.Println("clipboard status|check|clear")
	}
}
