package daemon

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon/handlers"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/residue"
)

// Test hooks (following the same pattern used successfully in internal/cli).
// These allow unit tests to inject controllable behavior without changing
// production code or public API.
var (
	netListen          = net.Listen
	osRemove           = os.Remove
	osMkdirAll         = os.MkdirAll
	osChmod            = os.Chmod
	signalNotify       = signal.Notify
	signalStop         = signal.Stop
	userHomeDir        = os.UserHomeDir
	getDaemonLogPathFn = getDaemonLogPath

	// writeAuthToken / readAuthToken / removeAuthToken allow tests to intercept
	// token file I/O without touching the real filesystem.
	writeAuthToken  = realWriteAuthToken
	readAuthToken   = realReadAuthToken
	removeAuthToken = realRemoveAuthToken

	// authenticateConnection lets pipe-based handler tests bypass the AUTH
	// requirement while still exercising the real command dispatch logic.
	authenticateConnection = realAuthenticateConnection

	// pbpasteFunc / pbcopyFunc provide test seams for the Pillar 5 monitor's
	// clipboard surface access (stories 4+5). Mirrors execCommand in cli package.
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
	// fireClipboardAlert (story 4). Modeled exactly after pbpasteFunc/pbcopyFunc
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

	// GetDaemonLogPathFnForTesting is the exported pointer to the internal
	// getDaemonLogPathFn seam. Cross-package tests (especially in internal/cli)
	// use it to force a per-test temp log location so we never touch the real
	// user's ~/.local/state/blastradius directory. This is essential for hermeticity.
	GetDaemonLogPathFnForTesting *func() string = &getDaemonLogPathFn
)

// Daemon represents the background singleton process.
type Daemon struct {
	cfg       *config.Config
	registry  *registry.Registry
	discovery *discovery.Manager
	residue   *residue.Manager
	listener  net.Listener
	shutdown  chan struct{}

	// authToken is the hex capability token written at startup.
	// All client connections must present it as the first "AUTH ..." line.
	authToken string

	// mu + busy provide a coarse exclusive guard for long-running mutating
	// operations (primarily SCRUB_HISTORY) to prevent concurrent mutation of
	// the same history files via colliding temp names/renames.
	mu   sync.Mutex
	busy bool

	// Clipboard hygiene state for Pillar 5 (targeted stories 4 + 5).
	// The monitor goroutine updates this; STATUS and explicit commands read it.
	// Protected by clipboardMu.
	clipboardMu          sync.Mutex
	clipboardLastHash    string    // hex sha256 of the raw clipboard bytes for the current epoch
	clipboardLastChange  time.Time // when we last saw a change that produced secrets
	clipboardSecretCount int       // exact count from last full scan (0 means clean)
	clipboardRedacted    bool      // whether auto-redact has been performed for this epoch
	clipboardCleared     bool      // whether full clear has been performed for this epoch

	// lastPbpasteErrLog supports rate-limited logging of transient pbpaste
	// failures inside the monitor (see runClipboardMonitor). Not protected
	// by clipboardMu because it is only written/read by the single monitor goroutine.
	lastPbpasteErrLog time.Time
}

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

// New creates a new Daemon instance.
func New(cfg *config.Config, reg *registry.Registry) *Daemon {
	dm := discovery.NewManager(cfg, reg)
	rm := residue.NewManager(cfg, reg)
	return &Daemon{
		cfg:       cfg,
		registry:  reg,
		discovery: dm,
		residue:   rm,
		shutdown:  make(chan struct{}),
	}
}

// --- Accessors for handlers (keep Daemon encapsulation) ---

func (d *Daemon) RegistrySnapshot() any { return d.registry.Snapshot() }
func (d *Daemon) FindDuplicates() map[registry.SecretHash][]registry.ProjectID {
	return d.registry.FindDuplicates()
}
func (d *Daemon) GetProjectDisplayName(p registry.ProjectID) string {
	return d.discovery.GetProjectDisplayName(p)
}
func (d *Daemon) IsKnownHashHex(h string) bool { return d.registry.IsKnownHashHex(h) }
func (d *Daemon) AllHashes() []registry.SecretHash {
	return d.registry.AllHashes()
}
func (d *Daemon) Now() time.Time   { return time.Now() }
func (d *Daemon) TriggerShutdown() { close(d.shutdown) }

// CrumbsSummary and RunCrumbsScan implement the DaemonContext methods for Pillar 2.
// The summary is exposed in STATUS JSON under the "pillar2" key.
func (d *Daemon) CrumbsSummary() map[string]any {
	if d.residue == nil {
		return map[string]any{"status": "disabled", "count": 0}
	}
	return d.residue.CrumbsSummary()
}

func (d *Daemon) RunCrumbsScan() *residue.ScanResult {
	if d.residue == nil {
		return &residue.ScanResult{Timestamp: time.Now().UTC(), Errors: []string{"residue manager not initialized"}}
	}
	return d.residue.RunScan()
}

// Pillar 1 manual rescan support (explicit on-demand only).
// Full fsnotify reactivity is permanently out of scope (security tradeoff).
func (d *Daemon) TriggerPillar1Rescan() error {
	if d.discovery == nil {
		return nil
	}
	d.discovery.Rescan()
	return nil
}

func (d *Daemon) Pillar1ScanStatus() map[string]any {
	if d.discovery == nil {
		return map[string]any{"status": "unavailable"}
	}
	last := d.discovery.LastScan()
	status := map[string]any{
		"last_scan":  last.UTC().Format(time.RFC3339),
		"scan_state": string(d.registry.GetScanState()),
	}
	if last.IsZero() {
		status["last_scan"] = "never"
	}
	return status
}

func (d *Daemon) LastPillar1Rescan() *discovery.RescanResult {
	if d.discovery == nil {
		return nil
	}
	return d.discovery.LastRescanResult()
}

// Pillar3Config implements the DaemonContext method for the SCRUB_HISTORY handler.
func (d *Daemon) Pillar3Config() config.Pillar3Config {
	if d.cfg == nil {
		// Safe fallback (should never happen in prod)
		return config.Pillar3Config{Enabled: true, Mode: "delete", RedactPlaceholder: "[REDACTED]"}
	}
	return d.cfg.Pillar3
}

// BeginExclusiveOp implements the DaemonContext method. It provides a simple
// mutex-based guard so that only one long-running mutating op (scrub etc.) runs
// at a time. Quick commands (STATUS, PING, etc.) are not serialized.
func (d *Daemon) BeginExclusiveOp(name string) (func(), bool) {
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return func() {}, false
	}
	d.busy = true
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		d.busy = false
		d.mu.Unlock()
	}, true
}

// Pillar5ClipboardStatus implements the DaemonContext method. It exposes the
// live state maintained by the background monitor (fast alerts + two-tier auto).
// This makes Pillar 5 first-class in `blastradius status --json`.
func (d *Daemon) Pillar5ClipboardStatus() map[string]any {
	d.clipboardMu.Lock()
	defer d.clipboardMu.Unlock()

	lastChangeStr := "never"
	if !d.clipboardLastChange.IsZero() {
		lastChangeStr = d.clipboardLastChange.Format(time.RFC3339)
	}

	return map[string]any{
		"secret_count":   d.clipboardSecretCount,
		"last_change":    lastChangeStr,
		"redacted":       d.clipboardRedacted,
		"cleared":        d.clipboardCleared,
		"monitor_active": d.cfg != nil && d.cfg.Pillar5.MonitorEnabled,
	}
}

// Run starts the Unix domain socket server and blocks until shutdown.
func (d *Daemon) Run() error {
	// Setup file logging via logging package
	logPath := getDaemonLogPathFn()
	if err := logging.Init(logPath); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}

	socketPath := config.SocketPath()
	log.Printf("Daemon starting. Listening on %s (0600 + token auth)", socketPath)
	log.Printf("Log file: %s", logPath)

	// Remove stale socket if it exists
	if err := osRemove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}
	// Also remove any leftover auth token from a previous unclean shutdown
	_ = removeAuthToken(socketPath) // best effort

	// Ensure parent directory exists (0700 — private to user)
	if err := osMkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// SECURITY: Close the Listen→Chmod race window.
	// We temporarily set a restrictive umask so the socket inode is created 0600
	// (owner r/w only). We still do the explicit Chmod afterward for defense-in-depth
	// and to make the intent unmistakable in logs/audits.
	oldMask := syscall.Umask(0077)
	ln, err := netListen("unix", socketPath)
	syscall.Umask(oldMask) // restore immediately (umask is process-global)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %w", err)
	}
	d.listener = ln

	// Belt-and-suspenders: enforce 0600 even if umask didn't apply perfectly.
	if err := osChmod(socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// SECURITY: write a fresh capability token next to the socket (hard invariant).
	// Clients must present it as the first message on every connection.
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		ln.Close()
		return fmt.Errorf("failed to generate auth token: %w", err)
	}
	d.authToken = hex.EncodeToString(token)
	if err := writeAuthToken(socketPath, d.authToken); err != nil {
		ln.Close()
		return fmt.Errorf("failed to write auth token: %w", err)
	}

	log.Printf("Blast Radius daemon started and listening on %s (0600 + token auth)", socketPath)

	// Run initial discovery on startup — runs in background
	go d.discovery.RunInitialDiscovery()

	// Pillar 5 reactive monitor (stories 4 + 5): clipboard change detection,
	// fast first-secret alerting, two-tier auto (redact then full clear).
	// Only starts if monitor_enabled in config. Safe no-op otherwise.
	if d.cfg.Pillar5.MonitorEnabled {
		go d.runClipboardMonitor()
	}

	// Handle graceful shutdown (signals + internal HALT command)
	sigCh := make(chan os.Signal, 1)
	signalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			logging.Println("Received signal, shutting down daemon...")
		case <-d.shutdown:
			logging.Println("Received HALT command, shutting down daemon...")
		}
		d.listener.Close()
		_ = removeAuthToken(socketPath) // best effort cleanup of capability token
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed during shutdown
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			logging.Printf("Accept error: %v", err)
			continue
		}
		go d.handleConnection(conn)
	}

	return nil
}

func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// SECURITY: every connection must begin with a valid AUTH line (capability token).
	// The authenticateConnection hook is overridable so net.Pipe tests can
	// bypass it while still exercising the real command dispatch.
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	if !authenticateConnection(firstLine, d.authToken) {
		// Auth failed — tell the client and close. Do not process any commands.
		resp := map[string]string{
			"status":  "error",
			"message": "authentication required or invalid token",
		}
		data, _ := json.Marshal(resp)
		conn.Write(append(data, '\n'))
		return
	}

	// Auth succeeded — now process commands on this connection (supports
	// the multi-CHECK_HASH pattern used by the Pillar 4 env primitive and clipboard).
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logging.Printf("Read error on client connection: %v", err)
			}
			return
		}

		command := line[:len(line)-1] // trim newline
		parts := strings.SplitN(command, " ", 2)
		cmd := parts[0]
		args := ""
		if len(parts) == 2 {
			args = parts[1]
		}

		handler := handlers.GetHandler(cmd)

		response, _ := handler.Handle(args, d)

		if cmd == "HALT" || cmd == "STOP" {
			data, _ := json.Marshal(response)
			conn.Write(append(data, '\n'))
			return
		}

		data, _ := json.Marshal(response)
		conn.Write(append(data, '\n'))
	}
}

// Close shuts down the listener.
func (d *Daemon) Close() error {
	if d.listener != nil {
		return d.listener.Close()
	}
	return nil
}

// getDaemonLogPath returns the canonical location for daemon logs.
// Uses XDG-style ~/.local/state/blastradius/daemon.log (respects our minimalism principles).
func getDaemonLogPath() string {
	home, err := userHomeDir()
	if err != nil {
		// Fallback (should rarely happen)
		return "/tmp/blastradius-daemon.log"
	}
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}

// --- Capability token helpers (hard security invariant) ---

const authTokenSuffix = ".auth"

// realWriteAuthToken writes the hex token next to the socket with 0600.
func realWriteAuthToken(socketPath, hexToken string) error {
	authPath := socketPath + authTokenSuffix
	return os.WriteFile(authPath, []byte(hexToken), 0600)
}

// realReadAuthToken reads the sibling .auth file.
func realReadAuthToken(socketPath string) (string, error) {
	data, err := os.ReadFile(socketPath + authTokenSuffix)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// realRemoveAuthToken removes the sibling .auth file (best effort, ignores not-exist).
func realRemoveAuthToken(socketPath string) error {
	authPath := socketPath + authTokenSuffix
	err := os.Remove(authPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// realAuthenticateConnection returns true if the first line from the client
// is a valid "AUTH <token>" that matches what the daemon wrote at startup.
func realAuthenticateConnection(firstLine, expectedToken string) bool {
	firstLine = strings.TrimSpace(firstLine)
	if !strings.HasPrefix(firstLine, "AUTH ") {
		return false
	}
	provided := strings.TrimSpace(firstLine[5:])
	return provided == expectedToken && expectedToken != ""
}

// --- Pillar 5 Clipboard Monitor (stories 4 + 5) ---

// runClipboardMonitor is the long-running goroutine that powers the reactive
// part of Pillar 5: fast alerts on copy + two-tier auto (redact then full clear).
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
				// for the current dirty epoch.
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
// Per review: when writing count==0 we *always* reset the per-epoch action
// flags (redacted/cleared). This ensures that a user overwrite of a post-auto
// (redacted or cleared) epoch with clean non-secret content results in a new
// clean epoch with flags=false (otherwise the stale flag from the prior epoch
// would "leak" because perform bypassed update when setting its count=0+flag).
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

// fireClipboardAlert surfaces the immediate user notification (story 4 fast path).
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
