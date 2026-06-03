package cli

import (
	"fmt"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
)

// RunClipboard handles Pillar 5 clipboard operations (macOS primitives + monitor-backed behaviors)
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

		known, err := batchCheckKnownSecrets(candidates)
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
		}
		found := len(known)

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
		// Redact only the secrets, preserve the rest of the content.
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

		secretsToRedact, err := batchCheckKnownSecrets(candidates)
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
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

// Note: the "scrub" / "redact" subcommand implements the redact primitive.
// "nuke" is alias for clear (blunt full clear). "clear" remains for the "I want it gone now" case.
