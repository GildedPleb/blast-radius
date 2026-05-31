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
	"syscall"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/discovery"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/residue"
	"github.com/GildedPleb/blast-radius/internal/daemon/handlers"
)

// Test hooks (following the same pattern used successfully in internal/cli).
// These allow unit tests to inject controllable behavior without changing
// production code or public API.
var (
	netListen     = net.Listen
	osRemove      = os.Remove
	osMkdirAll    = os.MkdirAll
	osChmod       = os.Chmod
	signalNotify  = signal.Notify
	signalStop    = signal.Stop
	userHomeDir   = os.UserHomeDir
	getDaemonLogPathFn = getDaemonLogPath

	// writeAuthToken / readAuthToken / removeAuthToken allow tests to intercept
	// token file I/O without touching the real filesystem.
	writeAuthToken  = realWriteAuthToken
	readAuthToken   = realReadAuthToken
	removeAuthToken = realRemoveAuthToken

	// authenticateConnection lets pipe-based handler tests bypass the AUTH
	// requirement while still exercising the real command dispatch logic.
	authenticateConnection = realAuthenticateConnection
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

func (d *Daemon) RegistrySnapshot() any                  { return d.registry.Snapshot() }
func (d *Daemon) FindDuplicates() map[[32]byte][]string {
	dups := d.registry.FindDuplicates()
	out := make(map[[32]byte][]string, len(dups))
	for h, ps := range dups {
		strs := make([]string, len(ps))
		for i, p := range ps {
			strs[i] = string(p)
		}
		out[h] = strs
	}
	return out
}
func (d *Daemon) GetProjectDisplayName(p string) string { return d.discovery.GetProjectDisplayName(registry.ProjectID(p)) }
func (d *Daemon) IsKnownHashHex(h string) bool          { return d.registry.IsKnownHashHex(h) }
func (d *Daemon) AllHashes() [][32]byte {
	hashes := d.registry.AllHashes()
	out := make([][32]byte, len(hashes))
	for i, h := range hashes {
		out[i] = [32]byte(h)
	}
	return out
}
func (d *Daemon) Now() time.Time                        { return time.Now() }
func (d *Daemon) TriggerShutdown()                      { close(d.shutdown) }

// CrumbsSummary and RunCrumbsScan implement the new DaemonContext methods for Pillar 2.
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

// Pillar 1 manual rescan support (Phase 3 — explicit on-demand only, no file watching).
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

	// SECURITY (2026): write a fresh capability token next to the socket.
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

	// Run initial discovery on startup (Phase 1) — runs in background
	go d.discovery.RunInitialDiscovery()

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

	// SECURITY (2026): every connection must begin with a valid AUTH line.
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
	// the multi-CHECK_HASH pattern used by the env command).
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

		var handler handlers.CommandHandler
		switch cmd {
		case "STATUS":
			handler = handlers.StatusHandler{}
		case "PING":
			handler = handlers.PingHandler{}
		case "DUPLICATES":
			handler = handlers.DuplicatesHandler{}
		case "SCRUB_HISTORY":
			handler = handlers.ScrubHistoryHandler{}
		case "CHECK_HASH":
			handler = handlers.CheckHashHandler{}
		case "CRUMBS":
			handler = handlers.CrumbsHandler{}
		case "RESCAN":
			handler = handlers.RescanHandler{}
		case "HALT", "STOP":
			handler = handlers.HaltHandler{}
		default:
			handler = handlers.UnknownHandler{}
		}

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

// --- Capability token helpers (Phase D security hardening) ---

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