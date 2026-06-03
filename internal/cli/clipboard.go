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

		// Send AUTH handshake (best effort; mirror realSendDaemonCommand behavior).
		// If this write fails we still proceed; the daemon will reject subsequent
		// CHECK_HASH with auth error, which surfaces as incomplete count (same as before).
		if tokenBytes, readErr := os.ReadFile(socketPath + ".auth"); readErr == nil {
			authLine := "AUTH " + strings.TrimSpace(string(tokenBytes)) + "\n"
			if _, werr := conn.Write([]byte(authLine)); werr != nil {
				logging.Printf("RunClipboard: AUTH write error (check): %v (subsequent checks may fail)", werr)
			}
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
	case "clear", "nuke":
		logging.Println("RunClipboard: clearing clipboard")
		if err := execCommand("pbcopy").Run(); err != nil {
			logging.Printf("RunClipboard: pbcopy failed for clear/nuke: %v", err)
			fmt.Println(`{"status":"error","message":"pbcopy failed"}`)
			return
		}
		fmt.Println(`{"status":"ok","message":"clipboard cleared"}`)
	case "scrub", "redact":
		// Story 2: redact only the secrets, preserve the rest of the content.
		logging.Println("RunClipboard: scrubbing clipboard (redact secrets only)")
		out, err := execCommand("pbpaste").Output()
		if err != nil {
			logging.Println("RunClipboard: pbpaste failed")
			fmt.Println(`{"status":"error","message":"pbpaste failed (macOS only)"}`)
			return
		}

		candidates := detection.NewDetector().ExtractCandidates(out)
		if len(candidates) == 0 {
			fmt.Println(`{"status":"ok","action":"noop","secrets_redacted":0}`)
			return
		}

		socketPath := config.SocketPath()
		conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
		}
		defer conn.Close()

		if tokenBytes, readErr := os.ReadFile(socketPath + ".auth"); readErr == nil {
			authLine := "AUTH " + strings.TrimSpace(string(tokenBytes)) + "\n"
			if _, werr := conn.Write([]byte(authLine)); werr != nil {
				logging.Printf("RunClipboard: AUTH write error (scrub): %v (redaction may be incomplete)", werr)
			}
		}

		secretsToRedact := []string{}
		reader := bufio.NewReader(conn)
		for _, cand := range candidates {
			if strings.TrimSpace(cand) == "" {
				continue
			}
			h := registry.HashValue([]byte(cand))
			hashHex := fmt.Sprintf("%x", h[:])
			cmdLine := fmt.Sprintf("CHECK_HASH %s\n", hashHex)
			if _, err := conn.Write([]byte(cmdLine)); err != nil {
				logging.Printf("RunClipboard: scrub CHECK_HASH write error (candidate %s): %v (redaction may be incomplete)", hashHex, err)
				continue
			}
			resp, err := reader.ReadString('\n')
			if err != nil {
				logging.Printf("RunClipboard: scrub CHECK_HASH read error (candidate %s): %v (redaction may be incomplete)", hashHex, err)
				continue
			}
			if strings.Contains(resp, `"known":true`) {
				secretsToRedact = append(secretsToRedact, cand)
			}
		}

		if len(secretsToRedact) == 0 {
			fmt.Println(`{"status":"ok","action":"noop","secrets_redacted":0}`)
			return
		}

		placeholder := "[REDACTED]"
		if cfg, _, cfgErr := configLoad(); cfgErr == nil {
			placeholder = config.EffectiveRedactPlaceholder(
				cfg.Pillar5.RedactPlaceholder,
				cfg.Pillar3.RedactPlaceholder,
				placeholder,
			)
		}

		scrubbed := string(out)
		for _, sec := range secretsToRedact {
			scrubbed = strings.ReplaceAll(scrubbed, sec, placeholder)
		}

		cmd := execCommand("pbcopy")
		cmd.Stdin = strings.NewReader(scrubbed)
		if err := cmd.Run(); err != nil {
			logging.Printf("RunClipboard: pbcopy failed for scrub/redact: %v", err)
			fmt.Println(`{"status":"error","message":"pbcopy failed during redact"}`)
			return
		}

		fmt.Printf(`{"status":"ok","action":"redacted","secrets_redacted":%d,"placeholder":%q}`+"\n", len(secretsToRedact), placeholder)
	default:
		fmt.Println("clipboard status|check|clear|nuke|scrub|redact")
	}
}

// Note: the "scrub" / "redact" subcommand implements story 2 (the redact primitive).
// "nuke" is alias for clear (story 3 blunt). "clear" remains for the "I want it gone now" case.
