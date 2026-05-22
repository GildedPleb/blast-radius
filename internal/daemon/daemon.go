package daemon

import (
	"bufio"
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
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Daemon represents the background singleton process.
type Daemon struct {
	cfg       *config.Config
	registry  *registry.Registry
	discovery *discovery.Manager
	listener  net.Listener
	shutdown  chan struct{}
}

// New creates a new Daemon instance.
func New(cfg *config.Config, reg *registry.Registry) *Daemon {
	dm := discovery.NewManager(cfg, reg)
	return &Daemon{
		cfg:       cfg,
		registry:  reg,
		discovery: dm,
		shutdown:  make(chan struct{}),
	}
}

// Run starts the Unix domain socket server and blocks until shutdown.
func (d *Daemon) Run() error {
	// Setup file logging (idiomatic location: ~/.local/state/blastradius/)
	logPath := getDaemonLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	// Note: We intentionally do NOT close this file — it lives for the lifetime of the daemon.

	log.SetOutput(logFile)
	log.SetPrefix("blastradius: ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Printf("Daemon starting. Listening on %s (0600)", d.cfg.SocketPath)
	log.Printf("Log file: %s", logPath)

	socketPath := d.cfg.SocketPath

	// Remove stale socket if it exists
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %w", err)
	}
	d.listener = ln

	// Enforce strict permissions (owner read/write only)
	if err := os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	log.Printf("Blast Radius daemon started and listening on %s (0600)", socketPath)

	// Run initial discovery on startup (Phase 1) — runs in background
	go d.discovery.RunInitialDiscovery()

	// Handle graceful shutdown (signals + internal HALT command)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			log.Println("Received signal, shutting down daemon...")
		case <-d.shutdown:
			log.Println("Received HALT command, shutting down daemon...")
		}
		d.listener.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed during shutdown
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go d.handleConnection(conn)
	}

	return nil
}

func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error on client connection: %v", err)
			}
			return
		}

		command := line[:len(line)-1] // trim newline

		var response any
		var data []byte

		switch command {
		case "STATUS":
			response = map[string]any{
				"status":  "ok",
				"message": "Blast Radius daemon is running",
				"registry": d.registry.Snapshot(),
				"time":    time.Now().Format(time.RFC3339),
			}
		case "PING":
			response = map[string]string{"status": "pong"}
		case "DUPLICATES":
			dups := d.registry.FindDuplicates()
			// Convert to serializable format (hash as hex string for readability)
			serializable := make([]map[string]any, 0, len(dups))
			for hash, projects := range dups {
				projStrs := make([]string, len(projects))
				for i, p := range projects {
					projStrs[i] = d.discovery.GetProjectDisplayName(p)
				}
				serializable = append(serializable, map[string]any{
					"hash":     fmt.Sprintf("%x", hash),
					"projects": projStrs,
					"count":    len(projects),
				})
			}
			response = map[string]any{
				"status":    "ok",
				"duplicates": serializable,
				"total":     len(dups),
			}
		case "SCRUB_HISTORY":
			// For now, we accept an optional path. If empty, we use common Zsh locations.
			response = d.handleScrubHistory()
		case "CHECK_HASH":
			// Phase 4: Check if a SHA-256 hex hash is known in the registry
			// Command format: CHECK_HASH <hexhash>
			parts := strings.SplitN(command, " ", 2)
			known := false
			if len(parts) == 2 {
				hashHex := strings.TrimSpace(parts[1])
				known = d.registry.IsKnownHashHex(hashHex)
			}
			response = map[string]any{
				"status": "ok",
				"known":  known,
			}
		case "HALT", "STOP":
			response = map[string]string{
				"status":  "ok",
				"message": "Shutting down daemon...",
			}
			data, _ = json.Marshal(response)
			conn.Write(append(data, '\n'))
			close(d.shutdown) // trigger graceful shutdown
			return
		default:
			response = map[string]string{
				"status":  "error",
				"message": fmt.Sprintf("unknown command: %s", command),
			}
		}

		data, _ = json.Marshal(response)
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

// handleScrubHistory performs safe history file scrubbing for known secret hashes.
// This implements Pillar 4 (History File Hygiene).
func (d *Daemon) handleScrubHistory() map[string]any {
	log.Println("Starting history scrub operation")

	histFile := d.findHistoryFile()
	if histFile == "" {
		return map[string]any{
			"status":  "error",
			"message": "Could not determine history file location",
		}
	}

	// Read original history
	data, err := os.ReadFile(histFile)
	if err != nil {
		log.Printf("Failed to read history file %s: %v", histFile, err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to read history file: %v", err),
		}
	}

	lines := strings.Split(string(data), "\n")
	originalCount := len(lines)

	// Build set of known hash hex strings for fast lookup
	knownHashes := make(map[string]bool)
	for _, hash := range d.registry.AllHashes() {
		knownHashes[fmt.Sprintf("%x", hash)] = true
	}

	// Filter lines that do NOT contain any known hash
	cleaned := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		shouldRemove := false
		for h := range knownHashes {
			if strings.Contains(line, h) {
				shouldRemove = true
				break
			}
		}
		if shouldRemove {
			removed++
			continue
		}
		cleaned = append(cleaned, line)
	}

	if removed == 0 {
		log.Printf("History scrub complete. No sensitive lines found in %s", histFile)
		return map[string]any{
			"status":        "ok",
			"message":       "No sensitive entries found in history",
			"file":          histFile,
			"lines_removed": 0,
		}
	}

	// Atomic write: write to temp file then rename
	tmpFile := histFile + ".blastradius-tmp"
	cleanContent := strings.Join(cleaned, "\n")
	if err := os.WriteFile(tmpFile, []byte(cleanContent), 0600); err != nil {
		log.Printf("Failed to write temp history file: %v", err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to write cleaned history: %v", err),
		}
	}

	if err := os.Rename(tmpFile, histFile); err != nil {
		os.Remove(tmpFile)
		log.Printf("Failed to replace history file: %v", err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to atomically replace history file: %v", err),
		}
	}

	log.Printf("History scrub complete. Removed %d sensitive line(s) from %s", removed, histFile)
	return map[string]any{
		"status":        "ok",
		"message":       fmt.Sprintf("Scrubbed %d sensitive line(s) from history", removed),
		"file":          histFile,
		"lines_removed": removed,
		"original_lines": originalCount,
	}
}

// findHistoryFile attempts to locate the user's Zsh history file.
func (d *Daemon) findHistoryFile() string {
	// Common locations in order of preference
	candidates := []string{
		os.Getenv("HISTFILE"),
		filepath.Join(os.Getenv("HOME"), ".zsh_history"),
		filepath.Join(os.Getenv("HOME"), ".zhistory"),
		filepath.Join(os.Getenv("HOME"), ".history"),
	}

	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// getDaemonLogPath returns the canonical location for daemon logs.
// Uses XDG-style ~/.local/state/blastradius/daemon.log (respects our minimalism principles).
func getDaemonLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback (should rarely happen)
		return "/tmp/blastradius-daemon.log"
	}
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}