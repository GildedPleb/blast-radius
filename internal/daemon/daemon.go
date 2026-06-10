package daemon

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon/handlers"
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

	// GetDaemonLogPathFnForTesting is the exported pointer to the internal
	// getDaemonLogPathFn seam. Cross-package tests (especially in internal/cli)
	// use it to force a per-test temp log location so we never touch the real
	// user's ~/.local/state/blastradius directory. This is essential for hermeticity.
	GetDaemonLogPathFnForTesting *func() string = &getDaemonLogPathFn

	// afterRunSetupForTesting is called (if non-nil) immediately after the
	// "daemon started and listening" log, after token write, before any goroutines
	// (discovery, monitor) or signal setup or the accept loop. Tests use it with
	// controllableListener + net.Pipe to synchronously drive Run's success path
	// + shutdown without blocking or real sockets. See daemon_test.go.
	afterRunSetupForTesting func(*Daemon)

	// randRead and loggingInit are seams for the two early failure paths inside
	// Run() that are otherwise hard to hit hermetically (rand failure after listen,
	// logging init). Prod behavior unchanged.
	randRead    = rand.Read
	loggingInit = logging.Init
)

// P5 (clipboard monitor) test seams and the monitor implementation live in
// clipboard.go (same package).

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

	// Clipboard hygiene state for Pillar 5 (reactive monitor + primitives).
	// The monitor goroutine updates this; STATUS and explicit commands read it.
	// Protected by clipboardMu.
	clipboardMu         sync.Mutex
	clipboardLastHash   string    // hex sha256 of the raw clipboard bytes for the current epoch
	clipboardLastChange time.Time // when we last saw a change that produced secrets

	clipboardSecretCount int  // exact count from last full scan (0 means clean)
	clipboardRedacted    bool // whether auto-redact has been performed for this epoch
	clipboardCleared     bool // whether full clear has been performed for this epoch

	// lastPbpasteErrLog supports rate-limited logging of transient pbpaste
	// failures inside the monitor (see runClipboardMonitor). Not protected
	// by clipboardMu because it is only written/read by the single monitor goroutine.
	lastPbpasteErrLog time.Time
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
		"monitor_active": d.cfg != nil && d.cfg.Pillar5.Enabled && d.cfg.Pillar5.MonitorEnabled,
	}
}

// Run starts the Unix domain socket server and blocks until shutdown.
func (d *Daemon) Run() error {
	// Setup file logging via logging package
	logPath := getDaemonLogPathFn()
	if err := loggingInit(logPath); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}

	socketPath := SocketPath()
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
	if _, err := randRead(token); err != nil {
		ln.Close()
		return fmt.Errorf("failed to generate auth token: %w", err)
	}
	d.authToken = hex.EncodeToString(token)
	if err := writeAuthToken(socketPath, d.authToken); err != nil {
		ln.Close()
		return fmt.Errorf("failed to write auth token: %w", err)
	}

	log.Printf("Blast Radius daemon started and listening on %s (0600 + token auth)", socketPath)

	// afterRunSetupForTesting lets tests inject a conn or force immediate shutdown
	// right after successful startup setup (listen+chmod+token) but before the
	// background goroutines and accept loop. This is what lets us cover the
	// bulk of Run() success + shutdown paths inside the strict no-sleep/net.Pipe
	// test rules. See TestDaemon_Run_Success.
	if afterRunSetupForTesting != nil {
		afterRunSetupForTesting(d)
	}

	// -------------------------------------------------------------------------
	// Background work that is gated by pillar enabled flags (from the cfg
	// snapshot taken at New() / daemon start).
	//
	// IMPORTANT: The *entire* config (including all pX.enabled values and their
	// sub-options) is snapshotted once when the daemon starts. There is no
	// runtime reload. Changing any pillar's enabled flag (or related toggles
	// such as pillar5.monitor_enabled) requires restarting the daemon for the
	// new behavior to take effect.
	//
	// - Pillar 1 per-source enabled (env / bitwarden): controls whether
	//   collectors are wired in NewManager and whether initial discovery /
	//   rescan actually run them. See discovery/manager.go.
	// - Pillar 2 enabled: RunCrumbsScan / residue manager early-returns with
	//   "pillar2.enabled is false" marker (no scanning performed).
	// - Pillar 3 enabled: checked in the SCRUB_HISTORY handler; early "disabled"
	//   response, no history processing.
	// - Pillar 4 enabled: enforced at the CLI layer for the `env` primitive
	//   (no direct daemon background behavior; the primitive is on-demand exec
	//   + CHECK_HASH against the P1 registry).
	// - Pillar 5 enabled + monitor_enabled: see the detailed comment below.
	//
	// This design keeps the daemon simple (true singleton, no hot-reload
	// complexity or extra attack surface). The `blastradius validate` and
	// `blastradius status` surfaces, plus the loud comments in the generated
	// initial config, make the "edit + restart" requirement obvious.
	// -------------------------------------------------------------------------

	// Run initial discovery on startup — runs in background.
	// Guarded so that a zero &Daemon{} (used in NilGuards for accessor coverage)
	// does not panic; real usage always goes through New() which wires discovery.
	if d.discovery != nil {
		go d.discovery.RunInitialDiscovery()
	}

	// Pillar 5 reactive monitor: clipboard change detection, fast first-secret
	// alerting, two-tier auto (redact then full clear).
	//
	// The monitor goroutine is ONLY started when BOTH:
	//   - pillar5.enabled == true (the pillar-wide opt-in, added for explicit
	//     control over whether the daemon ever touches the clipboard at all), AND
	//   - pillar5.monitor_enabled == true (the sub-toggle for the background
	//     polling + auto actions; explicit primitives still work via CLI even
	//     if monitor is off, subject to the pillar enabled).
	//
	// This is evaluated once at daemon startup using the config snapshot.
	// Changing pillar5.enabled (or monitor_enabled/alerts_enabled) requires
	// a daemon restart to take effect. See also the loud comments in the
	// initial config template.
	//
	// Guarded for the same nil-safety reason as discovery (see NilGuards).
	if d.cfg != nil && d.cfg.Pillar5.Enabled && d.cfg.Pillar5.MonitorEnabled {
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
			if isClosedListenerError(err) {
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

// closedListenerErrMsg is the exact string inside the net.OpError returned by
// a closed unix listener (see Run accept loop and controllableListener in tests).
// Centralized here so the brittle string match is in one place.
const closedListenerErrMsg = "use of closed network connection"

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

// isClosedListenerError centralizes the check for the graceful-shutdown
// error from a closed unix listener (used in Run's accept loop to break
// cleanly rather than log "Accept error" + continue). The string is
// defined via closedListenerErrMsg so tests can construct matching errs.
func isClosedListenerError(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err.Error() == closedListenerErrMsg
	}
	return false
}

// See clipboard.go for the P5 reactive monitor implementation.
