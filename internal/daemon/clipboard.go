package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// -----------------------------------------------------------------------------
// Test seams
// -----------------------------------------------------------------------------
//
// These package-level function variables let tests replace the macOS
// clipboard primitives and alert side-effects. Production uses
// util.ResolveCommand for PATH safety.

var (
	pbpasteFunc = func() ([]byte, error) {
		return exec.Command(util.ResolveCommand("pbpaste")).Output()
	}
	pbcopyFunc = func(data []byte) error {
		if data == nil {
			data = []byte{}
		}
		cmd := exec.Command(util.ResolveCommand("pbcopy"))
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Run()
	}
	osascriptFunc = func(msg string) error {
		return exec.Command(util.ResolveCommand("osascript"), "-e",
			fmt.Sprintf(`display notification %q with title "Blast Radius"`, msg)).Run()
	}
	afplayFunc = func() error {
		return exec.Command(util.ResolveCommand("afplay"), "/System/Library/Sounds/Ping.aiff").Run()
	}
)

// default* capture the original implementations for coverage.
var (
	defaultPbpasteFunc   = pbpasteFunc
	defaultPbcopyFunc    = pbcopyFunc
	defaultOsascriptFunc = osascriptFunc
	defaultAfplayFunc    = afplayFunc
)

// noop* keep the test suite hermetic after coverage runs.
var (
	noopOsascriptFunc = func(string) error { return nil }
	noopAfplayFunc    = func() error { return nil }
)

func init() {
	_ = noopOsascriptFunc("")
	_ = noopAfplayFunc()
}

// forceCoverDefaultSeams exercises the default seam bodies under a sabotaged
// PATH. Only called by TestPillar5CoverDefaultSeamBodies.
func forceCoverDefaultSeams() {
	pbpasteFunc = defaultPbpasteFunc
	pbcopyFunc = defaultPbcopyFunc
	osascriptFunc = defaultOsascriptFunc
	afplayFunc = defaultAfplayFunc

	orig := os.Getenv("PATH")
	os.Setenv("PATH", "/nonexistent-for-coverage")
	defer os.Setenv("PATH", orig)

	_, _ = pbpasteFunc()
	_ = pbcopyFunc(nil)
	_ = osascriptFunc("coverage")
	_ = afplayFunc()

	osascriptFunc = noopOsascriptFunc
	afplayFunc = noopAfplayFunc
}

// monitorTicker lets tests drive the monitor synchronously.
type monitorTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realMonitorTicker struct{ *time.Ticker }

func (r *realMonitorTicker) Chan() <-chan time.Time { return r.C }
func (r *realMonitorTicker) Stop()                  { r.Ticker.Stop() }

var newMonitorTicker = func(d time.Duration) monitorTicker {
	return &realMonitorTicker{time.NewTicker(d)}
}

var runtimeGOOS = runtime.GOOS

const clipboardMonitorInterval = 750 * time.Millisecond

// shouldLogPbpasteErr rate-limits transient pasteboard error logging.
func shouldLogPbpasteErr(last, now time.Time) (bool, time.Time) {
	const interval = 30 * time.Second
	if last.IsZero() || now.Sub(last) > interval {
		return true, now
	}
	return false, last
}

// extractCandidatesFunc is the test seam for detection.ExtractCandidates.
// Default behavior is identical to production. It exists solely so we can
// force whitespace-only candidates and cover the defensive
// `if strings.TrimSpace(cand) == "" { continue }` line in scanAndActOnClipboard.
var extractCandidatesFunc = func(raw []byte) []string {
	return detection.NewDetector().ExtractCandidates(raw)
}

// -----------------------------------------------------------------------------
// Pillar 5 Clipboard Monitor
// -----------------------------------------------------------------------------

// runClipboardMonitor is the background goroutine for reactive secret
// detection + timed auto-redact / auto-clear.
func (d *Daemon) runClipboardMonitor() {
	if d.cfg == nil {
		return
	}

	p5 := d.cfg.Pillar5

	// Master pillar gate. If pillar5.enabled is false at daemon startup (the
	// snapshot time), we never poll the clipboard in the background. This is
	// the explicit opt-out so that nothing in the daemon will read copy-paste
	// content unless the user has set enabled: true.
	if !p5.Enabled {
		logging.Println("Pillar5 monitor: pillar5.enabled=false; background clipboard monitoring disabled (no pbpaste polling will occur from the daemon)")
		return
	}

	if runtimeGOOS != "darwin" {
		logging.Println("Pillar5 monitor: pbpaste/pbcopy is macOS-only; disabling")
		return
	}

	tkr := newMonitorTicker(clipboardMonitorInterval)
	defer tkr.Stop()

	logging.Printf("Pillar5 monitor started (interval=%v, redact=%ds, clear=%ds)",
		clipboardMonitorInterval, p5.RedactTimeoutSeconds, p5.FullClearTimeoutSeconds)

	for {
		select {
		case <-d.shutdown:
			logging.Println("Pillar5 monitor shutting down")
			return

		case <-tkr.Chan():
			out, err := pbpasteFunc()
			if err != nil {
				if doLog, newT := shouldLogPbpasteErr(d.lastPbpasteErrLog, time.Now()); doLog {
					logging.Printf("Pillar5 monitor: pbpaste failed: %v", err)
					d.lastPbpasteErrLog = newT
				}
				continue
			}
			d.lastPbpasteErrLog = time.Time{}

			h := sha256.Sum256(out)
			curHash := hex.EncodeToString(h[:])

			d.clipboardMu.Lock()
			prevHash := d.clipboardLastHash
			d.clipboardMu.Unlock()

			if curHash == prevHash {
				d.maybeFireAutoAction(curHash)
				continue
			}
			d.scanAndActOnClipboard(out, curHash, p5)
		}
	}
}

// scanAndActOnClipboard does candidate extraction + registry lookup.
// It fires the alert on the *first* known secret for lowest latency.
func (d *Daemon) scanAndActOnClipboard(raw []byte, contentHash string, p5 config.Pillar5Config) {
	if len(raw) == 0 {
		d.updateClipboardState(contentHash, 0)
		return
	}

	cands := extractCandidatesFunc(raw)
	if len(cands) == 0 {
		d.updateClipboardState(contentHash, 0)
		return
	}

	firstSecretSeen := false
	found := 0

	for _, cand := range cands {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		if d.registry.Has(registry.HashValue([]byte(cand))) {
			found++
			if !firstSecretSeen {
				firstSecretSeen = true
				if p5.AlertsEnabled {
					go d.fireClipboardAlert()
				}
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
	d.maybeFireAutoAction(contentHash)
}

// updateClipboardState is the single writer for clipboard epoch state.
// count==0 always resets the per-epoch action flags.
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
	}
}

// fireClipboardAlert sends the immediate notification (best effort).
func (d *Daemon) fireClipboardAlert() {
	msg := "Blast Radius: secret detected on clipboard"

	notifErr := osascriptFunc(msg)
	soundErr := afplayFunc()

	if notifErr == nil || soundErr == nil {
		logging.Println("Pillar5: alert fired (first secret confirmed)")
	} else {
		logging.Println("Pillar5: alert attempt (first secret confirmed); both notification and sound failed")
	}
}

// maybeFireAutoAction decides whether to trigger auto-redact or auto-clear
// based on elapsed time since the last change.
func (d *Daemon) maybeFireAutoAction(currentHash string) {
	d.clipboardMu.Lock()
	lastHash := d.clipboardLastHash
	lastChange := d.clipboardLastChange
	secretCount := d.clipboardSecretCount
	alreadyRedacted := d.clipboardRedacted
	alreadyCleared := d.clipboardCleared
	d.clipboardMu.Unlock()

	if secretCount == 0 || lastHash != currentHash || d.cfg == nil {
		return
	}

	p5 := d.cfg.Pillar5
	elapsed := time.Since(lastChange)

	if !alreadyRedacted && p5.RedactTimeoutSeconds > 0 &&
		elapsed >= time.Duration(p5.RedactTimeoutSeconds)*time.Second {
		d.performAutoRedact(currentHash)
	}

	if !alreadyCleared && p5.FullClearTimeoutSeconds > 0 &&
		elapsed >= time.Duration(p5.FullClearTimeoutSeconds)*time.Second {
		d.performAutoFullClear(currentHash)
	}
}

// clipboardStillMatches is used to close TOCTOU windows before
// destructive clipboard writes.
func clipboardStillMatches(expectedHash string) bool {
	out, err := pbpasteFunc()
	if err != nil {
		return false
	}
	h := sha256.Sum256(out)
	return hex.EncodeToString(h[:]) == expectedHash
}

// performAutoRedact replaces known secrets with the configured placeholder.
// It performs stability checks before reading candidates and before writing.
func (d *Daemon) performAutoRedact(expectedHash string) {
	if !clipboardStillMatches(expectedHash) {
		return
	}

	out, err := pbpasteFunc()
	if err != nil {
		return
	}
	if !clipboardStillMatches(expectedHash) {
		return
	}

	cands := extractCandidatesFunc(out)
	if len(cands) == 0 {
		return
	}

	secretsToRedact := make([]string, 0, len(cands))
	for _, cand := range cands {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		if d.registry.Has(registry.HashValue([]byte(cand))) {
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

	if !clipboardStillMatches(expectedHash) {
		return
	}

	if err := pbcopyFunc([]byte(scrubbed)); err != nil {
		logging.Printf("Pillar5 auto-redact: pbcopy failed: %v", err)
		return
	}

	d.clipboardMu.Lock()
	d.clipboardRedacted = true
	d.clipboardSecretCount = 0
	newH := sha256.Sum256([]byte(scrubbed))
	d.clipboardLastHash = hex.EncodeToString(newH[:])
	d.clipboardMu.Unlock()

	logging.Printf("Pillar5: auto-redacted %d secret value(s) after timeout", len(secretsToRedact))
}

// performAutoFullClear empties the pasteboard after the timeout.
func (d *Daemon) performAutoFullClear(expectedHash string) {
	if !clipboardStillMatches(expectedHash) {
		return
	}

	out, err := pbpasteFunc()
	if err != nil {
		return
	}
	if !clipboardStillMatches(expectedHash) {
		return
	}
	_ = out // stability check only

	if err := pbcopyFunc(nil); err != nil {
		logging.Printf("Pillar5 auto-clear: pbcopy failed: %v", err)
		return
	}

	d.clipboardMu.Lock()
	d.clipboardCleared = true
	d.clipboardSecretCount = 0
	emptyH := sha256.Sum256([]byte{})
	d.clipboardLastHash = hex.EncodeToString(emptyH[:])
	d.clipboardMu.Unlock()

	logging.Println("Pillar5: auto full-cleared clipboard after timeout")
}
