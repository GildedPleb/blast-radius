package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// clipboard.go contains the Pillar 5 reactive monitor (fast first-secret alert
// on copy + two-tier auto redact-then-clear) and its test seams for pbpaste,
// pbcopy, osascript, and afplay.
//
// The Daemon struct definition, clipboard* fields, Pillar5ClipboardStatus
// accessor, and the call site that starts the monitor goroutine live in
// daemon.go (same package). All methods here are attached to *Daemon.

// --- Pillar 5 test seams ---

var (
	// pbpasteFunc / pbcopyFunc provide test seams for the Pillar 5 monitor's
	// clipboard surface access. Mirrors execCommand in cli package.
	// Production uses real pbpaste/pbcopy; tests can inject fakes for content,
	// errors, and to spy on writes without touching real pasteboard.
	pbpasteFunc = func() ([]byte, error) { return exec.Command("pbpaste").Output() }
	pbcopyFunc  = func(data []byte) error {
		if data == nil {
			data = []byte{}
		}
		cmd := exec.Command("pbcopy")
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Run()
	}

	// osascriptFunc / afplayFunc are test seams for the alert side-effects in
	// fireClipboardAlert. Modeled exactly after pbpasteFunc/pbcopyFunc
	// so tests can override without real notifications/sounds and without
	// running the background ticker (per project no-sleep rules in daemon_test.go).
	// Also allows non-mac/headless test envs to avoid side effects.
	osascriptFunc = func(msg string) error {
		return exec.Command("osascript", "-e",
			fmt.Sprintf(`display notification %q with title "Blast Radius"`, msg)).Run()
	}
	afplayFunc = func() error {
		return exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
	}

	// clipboardMonitorInterval is the internal poll rate for the reactive
	// Pillar 5 monitor (cheap 750ms is acceptable because clipboard ops are
	// fast and the "first secret" alert is what matters for latency).
	// It is deliberately not a user-tunable config field in alpha (would
	// require reload, min/max validation in normalize, docs updates, and
	// status exposure). Logged at startup for observability/debug.
	clipboardMonitorInterval = 750 * time.Millisecond
)

// shouldLogPbpasteErr encapsulates the rate-limiting decision for transient
// pbpaste errors inside runClipboardMonitor. It is a pure function so it can
// be unit tested directly without starting the monitor goroutine or tickers
// (forbidden by the project's no-sleep / <5s total wall-time rules for daemon tests).
func shouldLogPbpasteErr(last, now time.Time) (bool, time.Time) {
	const interval = 30 * time.Second
	if last.IsZero() || now.Sub(last) > interval {
		return true, now
	}
	return false, last
}

// --- Pillar 5 Clipboard Monitor ---

// runClipboardMonitor is the long-running goroutine that powers the reactive
// part of Pillar 5: fast first-secret alerts on copy + two-tier auto (redact then full clear).
// It is started only when MonitorEnabled is true.
func (d *Daemon) runClipboardMonitor() {
	if d.cfg == nil {
		return
	}
	if runtime.GOOS != "darwin" {
		logging.Println("Pillar5 monitor: pbpaste/pbcopy clipboard monitoring is macOS-only; disabling monitor (primitives still available via explicit commands)")
		return
	}
	p5 := d.cfg.Pillar5
	interval := clipboardMonitorInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logging.Printf("Pillar5 monitor started (interval=%v, redact_timeout=%ds, full_clear_timeout=%ds)", interval, p5.RedactTimeoutSeconds, p5.FullClearTimeoutSeconds)

	for {
		select {
		case <-d.shutdown:
			logging.Println("Pillar5 monitor shutting down")
			return
		case <-ticker.C:
			// Read current clipboard (best effort, direct like the CLI primitives).
			// Uses pbpasteFunc seam for testability.
			out, err := pbpasteFunc()
			if err != nil {
				// Rate-limit logs for transient macOS pasteboard issues (server restart,
				// perms, etc.). 750ms poll would otherwise spam the daemon log.
				// Success path clears the last-log time so next error logs promptly.
				doLog, newT := shouldLogPbpasteErr(d.lastPbpasteErrLog, time.Now())
				if doLog {
					logging.Printf("Pillar5 monitor: pbpaste failed (will retry): %v", err)
					d.lastPbpasteErrLog = newT
				}
				continue
			}
			// Success: reset so a future transient failure will log immediately.
			d.lastPbpasteErrLog = time.Time{}

			// Quick change detection via content hash (simple + reliable).
			h := sha256.Sum256(out)
			curHash := hex.EncodeToString(h[:])

			d.clipboardMu.Lock()
			prevHash := d.clipboardLastHash
			d.clipboardMu.Unlock()

			if curHash == prevHash {
				// No content change. Check if we need to fire a delayed auto action
				// for the current epoch (if a timer has elapsed since the last change).
				d.maybeFireAutoAction(curHash)
				continue
			}

			// Content changed — perform a full scan.
			d.scanAndActOnClipboard(out, curHash, p5)
		}
	}
}

// scanAndActOnClipboard does the candidate extraction + registry checks for a
// freshly read clipboard blob. It implements the fast-alert requirement:
// the user-visible alert is fired as soon as the *first* secret is confirmed.
// The full count is still computed and stored for status / later inspection.
func (d *Daemon) scanAndActOnClipboard(raw []byte, contentHash string, p5 config.Pillar5Config) {
	if len(raw) == 0 {
		d.updateClipboardState(contentHash, 0)
		return
	}

	cands := detection.NewDetector().ExtractCandidates(raw)
	if len(cands) == 0 {
		d.updateClipboardState(contentHash, 0)
		return
	}

	// Fast path + full count in one pass.
	// As soon as we see the first known secret we fire the alert (if enabled)
	// without waiting for the rest of the (potentially large) candidate list.
	// The caller (monitor) will still finish the loop to get the exact count.
	firstSecretSeen := false
	found := 0

	for _, cand := range cands {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		h := registry.HashValue([]byte(cand))
		if d.registry.Has(h) {
			found++
			if !firstSecretSeen {
				firstSecretSeen = true
				// Fire alert immediately for lowest possible latency.
				// Do not block the scan loop.
				if p5.AlertsEnabled {
					go d.fireClipboardAlert() // best effort, non-blocking
				}
				// Record the moment we first saw a secret for this epoch.
				now := time.Now()
				d.clipboardMu.Lock()
				d.clipboardLastChange = now
				d.clipboardRedacted = false
				d.clipboardCleared = false
				d.clipboardMu.Unlock()
			}
		}
	}

	d.updateClipboardState(contentHash, found)

	// After the scan we also check whether an auto action is due for this
	// new epoch (in case the timers are very short).
	d.maybeFireAutoAction(contentHash)
}

// updateClipboardState is the single place that mutates the clipboard fields
// under the lock (except for the direct sets inside performAuto* for the
// redacted/cleared epochs themselves). It also logs transitions for observability.
//
// Per the state machine: when writing count==0 we *always* reset the per-epoch action
// flags (redacted/cleared). This ensures that a user overwrite of a post-auto
// (redacted or cleared) epoch with clean non-secret content results in a new
// clean epoch with flags=false (otherwise a stale flag would persist because
// the auto path bypasses the normal update when it sets its count=0+flag).
func (d *Daemon) updateClipboardState(contentHash string, count int) {
	d.clipboardMu.Lock()
	defer d.clipboardMu.Unlock()

	prevCount := d.clipboardSecretCount
	d.clipboardLastHash = contentHash
	d.clipboardSecretCount = count

	if count > 0 && prevCount == 0 {
		logging.Printf("Pillar5: secret(s) detected on clipboard (count=%d)", count)
	}
	if count == 0 {
		d.clipboardRedacted = false
		d.clipboardCleared = false
		if prevCount > 0 {
			logging.Println("Pillar5: clipboard is now clean")
		}
		// If prevCount==0 here we are typically transitioning from an auto-redacted
		// or auto-cleared epoch (which set count=0+flag directly) to a fresh clean
		// user epoch; the reset above ensures the new epoch reports clean flags.
	}
}

// fireClipboardAlert surfaces the immediate user notification (fast first-secret path).
// Uses the conventional lightweight macOS mechanisms. Best-effort; failures are
// only logged at debug level so they never affect the monitor loop.
func (d *Daemon) fireClipboardAlert() {
	// Generic message — we deliberately avoid the exact count here because
	// the alert is intentionally fired on the *first* confirmation.
	msg := "Blast Radius: secret detected on clipboard"

	// Notification Center + audible (best effort only). Use seams so tests
	// can override (and non-mac envs can avoid real side effects).
	notifErr := osascriptFunc(msg)
	soundErr := afplayFunc()

	if notifErr == nil || soundErr == nil {
		logging.Println("Pillar5: alert fired (first secret confirmed)")
	} else {
		logging.Println("Pillar5: alert attempt (first secret confirmed); notification/sound best-effort (both failed)")
	}
}

// maybeFireAutoAction checks the current epoch against the two configured
// timeouts and performs the appropriate action (redact or full clear) if due
// and not already done for this fingerprint.
func (d *Daemon) maybeFireAutoAction(currentHash string) {
	d.clipboardMu.Lock()
	lastHash := d.clipboardLastHash
	lastChange := d.clipboardLastChange
	secretCount := d.clipboardSecretCount
	alreadyRedacted := d.clipboardRedacted
	alreadyCleared := d.clipboardCleared
	d.clipboardMu.Unlock()

	if secretCount == 0 || lastHash != currentHash {
		return // nothing to do or epoch has moved on
	}
	if d.cfg == nil {
		return
	}
	p5 := d.cfg.Pillar5
	now := time.Now()

	elapsed := now.Sub(lastChange)

	// Tier 1: auto-redact (if enabled and due)
	if !alreadyRedacted && p5.RedactTimeoutSeconds > 0 && elapsed >= time.Duration(p5.RedactTimeoutSeconds)*time.Second {
		d.performAutoRedact(currentHash)
	}

	// Tier 2: full clear (independent of redact tier per the two configurable timeouts;
	// a full clear can fire even if redact was 0 or its window not yet elapsed.
	// This matches the "two independent user-configurable settings" intent.)
	if !alreadyCleared && p5.FullClearTimeoutSeconds > 0 && elapsed >= time.Duration(p5.FullClearTimeoutSeconds)*time.Second {
		d.performAutoFullClear(currentHash)
	}
}

// performAutoRedact re-reads the clipboard (to be sure we still have the same
// content) and performs an in-place redaction of the known secrets.
func (d *Daemon) performAutoRedact(expectedHash string) {
	out, err := pbpasteFunc()
	if err != nil {
		return
	}
	h := sha256.Sum256(out)
	if hex.EncodeToString(h[:]) != expectedHash {
		// Content changed underneath us — the monitor will pick it up on next tick.
		return
	}

	cands := detection.NewDetector().ExtractCandidates(out)
	if len(cands) == 0 {
		return
	}

	// Collect the actual secret values that are still known right now.
	secretsToRedact := []string{}
	for _, cand := range cands {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		hv := registry.HashValue([]byte(cand))
		if d.registry.Has(hv) {
			secretsToRedact = append(secretsToRedact, cand)
		}
	}
	if len(secretsToRedact) == 0 {
		return
	}

	placeholder := "[REDACTED]"
	if d.cfg != nil {
		placeholder = config.EffectiveRedactPlaceholder(
			d.cfg.Pillar5.RedactPlaceholder,
			d.cfg.Pillar3.RedactPlaceholder,
			placeholder,
		)
	}

	scrubbed := string(out)
	for _, sec := range secretsToRedact {
		scrubbed = strings.ReplaceAll(scrubbed, sec, placeholder)
	}

	// Re-verify the clipboard content is *still* the expected epoch immediately
	// before the write. This closes the TOCTOU window between the initial
	// stability check (right after pbpaste) and the pbcopy (after candidate
	// extraction, registry lookups, and scrubbed-string construction).
	// Any mutation (user copy, concurrent scrub, pasteboard server, etc.) in
	// that window would otherwise cause a blind overwrite of live content with
	// a redaction derived from the *stale* snapshot.
	postCheck, pErr := pbpasteFunc()
	if pErr != nil {
		logging.Printf("Pillar5 auto-redact: post-build pbpaste failed: %v", pErr)
		return
	}
	postH := sha256.Sum256(postCheck)
	if hex.EncodeToString(postH[:]) != expectedHash {
		// Epoch moved on underneath us; monitor will pick up new content on next tick.
		// Do not commit the stale redaction.
		return
	}

	// Write the redacted version back.
	if err := pbcopyFunc([]byte(scrubbed)); err != nil {
		logging.Printf("Pillar5 auto-redact: pbcopy failed: %v", err)
		return
	}

	d.clipboardMu.Lock()
	d.clipboardRedacted = true
	// After redaction the "secret count" ... (comment as before)
	d.clipboardSecretCount = 0
	// Update lastHash to the just-written (redacted) content so the *next* monitor
	// tick does not see a "change" and do an unnecessary re-scan.
	newH := sha256.Sum256([]byte(scrubbed))
	d.clipboardLastHash = hex.EncodeToString(newH[:])
	d.clipboardMu.Unlock()

	logging.Printf("Pillar5: auto-redacted %d secret value(s) after timeout", len(secretsToRedact))
}

// performAutoFullClear just empties the pasteboard (the blunt "nuke" action).
func (d *Daemon) performAutoFullClear(expectedHash string) {
	out, err := pbpasteFunc()
	if err != nil {
		return
	}
	h := sha256.Sum256(out)
	if hex.EncodeToString(h[:]) != expectedHash {
		return
	}

	// Re-check stability right before the (destructive) clear write to close
	// the TOCTOU window (same rationale as in performAutoRedact).
	postCheck, pErr := pbpasteFunc()
	if pErr != nil {
		return
	}
	postH := sha256.Sum256(postCheck)
	if hex.EncodeToString(postH[:]) != expectedHash {
		return
	}

	// Empty the clipboard.
	if err := pbcopyFunc(nil); err != nil {
		logging.Printf("Pillar5 auto-clear: pbcopy failed: %v", err)
		return
	}

	d.clipboardMu.Lock()
	d.clipboardCleared = true
	d.clipboardSecretCount = 0
	// Update lastHash to hash-of-empty so next tick sees stable "clean" and
	// does not treat the clear as a "new change" requiring re-scan.
	emptyH := sha256.Sum256([]byte{})
	d.clipboardLastHash = hex.EncodeToString(emptyH[:])
	d.clipboardMu.Unlock()

	logging.Println("Pillar5: auto full-cleared clipboard after timeout")
}
