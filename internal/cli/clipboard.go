package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// RunClipboard handles Pillar 5 clipboard operations (macOS only for v1)
func RunClipboard(args []string) {
	_ = logging.Init(getDaemonLogPathFn())

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

		// Use the unified detector instead of hashing the entire clipboard blob.
		candidates := detection.NewDetector().ExtractCandidates(out)

		if len(candidates) == 0 {
			fmt.Println(`{"status":"ok","known":false,"secrets_found":0}`)
			return
		}

		// Open a single connection and send AUTH once (much more efficient than
		// one sendDaemonCommand per candidate).
		socketPath := config.SocketPath()
		conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
		}
		defer conn.Close()

		// Send AUTH handshake
		if tokenBytes, readErr := os.ReadFile(socketPath + ".auth"); readErr == nil {
			authLine := "AUTH " + strings.TrimSpace(string(tokenBytes)) + "\n"
			conn.Write([]byte(authLine))
		}

		found := 0
		reader := bufio.NewReader(conn)
		for _, cand := range candidates {
			if strings.TrimSpace(cand) == "" {
				continue
			}
			h := registry.HashValue([]byte(cand))
			hashHex := fmt.Sprintf("%x", h[:])
			cmdLine := fmt.Sprintf("CHECK_HASH %s\n", hashHex)
			if _, err := conn.Write([]byte(cmdLine)); err != nil {
				logging.Printf("RunClipboard: CHECK_HASH write error (candidate %s): %v (count may be incomplete)", hashHex, err)
				continue
			}
			resp, err := reader.ReadString('\n')
			if err != nil {
				logging.Printf("RunClipboard: CHECK_HASH read error (candidate %s): %v (count may be incomplete)", hashHex, err)
				continue
			}
			if strings.Contains(resp, `"known":true`) {
				found++
			}
		}

		if found > 0 {
			fmt.Printf(`{"status":"ok","known":true,"secrets_found":%d}`+"\n", found)
		} else {
			fmt.Println(`{"status":"ok","known":false,"secrets_found":0}`)
		}
	case "clear":
		logging.Println("RunClipboard: clearing clipboard")
		execCommand("pbcopy").Run()
		fmt.Println(`{"status":"ok","message":"clipboard cleared"}`)
	default:
		fmt.Println("clipboard status|check|clear")
	}
}
