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
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/residue"
	"github.com/GildedPleb/blast-radius/internal/daemon/handlers"
)

// Daemon represents the background singleton process.
type Daemon struct {
	cfg       *config.Config
	registry  *registry.Registry
	discovery *discovery.Manager
	residue   *residue.Manager
	listener  net.Listener
	shutdown  chan struct{}
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

// Run starts the Unix domain socket server and blocks until shutdown.
func (d *Daemon) Run() error {
	// Setup file logging via logging package
	logPath := getDaemonLogPath()
	if err := logging.Init(logPath); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}

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
			logging.Println("Received signal, shutting down daemon...")
		case <-d.shutdown:
			logging.Println("Received HALT command, shutting down daemon...")
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
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback (should rarely happen)
		return "/tmp/blastradius-daemon.log"
	}
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}