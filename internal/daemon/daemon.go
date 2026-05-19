package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Daemon represents the background singleton process.
type Daemon struct {
	cfg      *config.Config
	registry *registry.Registry
	listener net.Listener
	shutdown chan struct{}
}

// New creates a new Daemon instance.
func New(cfg *config.Config, reg *registry.Registry) *Daemon {
	return &Daemon{
		cfg:      cfg,
		registry: reg,
		shutdown: make(chan struct{}),
	}
}

// Run starts the Unix domain socket server and blocks until shutdown.
func (d *Daemon) Run() error {
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

	fmt.Printf("Blast Radius daemon started. Listening on %s (0600)\n", socketPath)

	// Handle graceful shutdown (signals + internal HALT command)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			fmt.Println("\nReceived signal, shutting down daemon...")
		case <-d.shutdown:
			fmt.Println("\nReceived HALT command, shutting down daemon...")
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
			fmt.Printf("Accept error: %v\n", err)
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
				fmt.Printf("Read error: %v\n", err)
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