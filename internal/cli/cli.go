package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

const (
	socketConnectTimeout = 2 * time.Second
	daemonStartWait      = 500 * time.Millisecond
)

// PrintHelp displays the main help message and current configuration.
func PrintHelp() {
	cfg, configPath, _ := config.Load()

	fmt.Println("Blast Radius - Secret exposure reduction tool")
	fmt.Println()
	fmt.Printf("Config: %s\n", configPath)
	fmt.Println()
	fmt.Println("Settings:")
	fmt.Printf("  Socket:        %s\n", cfg.SocketPath)
	if len(cfg.ProjectRoots) > 0 {
		fmt.Printf("  Project Roots: %v\n", cfg.ProjectRoots)
	} else {
		fmt.Println("  Project Roots: (not configured - will scan home directory)")
	}
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  start          Start the background daemon")
	fmt.Println("  status [--json] Show daemon and registry status (does not start daemon)")
	fmt.Println("  stop, halt     Gracefully stop the running daemon")
	fmt.Println("  logs           Show recent daemon log output")
	fmt.Println("  duplicates     Show secret hashes duplicated across multiple projects (Pillar 1)")
	fmt.Println("  scrub-history  Scrub shell history of known secret values (Pillar 4)")
	fmt.Println("  help           Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  blastradius start")
	fmt.Println("  blastradius status")
	fmt.Println("  blastradius duplicates")
	fmt.Println("  blastradius scrub-history")
	fmt.Println("  blastradius stop")
	fmt.Println()
	fmt.Println("For more information, see the repository README.")
}

// RunStatus queries the daemon for status without auto-starting it.
func RunStatus(jsonOutput bool) {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		if jsonOutput {
			fmt.Println(`{"status":"not_running","message":"daemon not running"}`)
		} else {
			fmt.Println("Blast Radius Status")
			fmt.Println("===================")
			fmt.Println("Status:  Not running")
			fmt.Println()
			fmt.Println("The Blast Radius daemon is not currently running.")
			fmt.Println("Use 'blastradius start' to launch it.")
			fmt.Println("===================")
		}
		return
	}
	defer conn.Close()

	// Send STATUS command
	_, err = conn.Write([]byte("STATUS\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send command: %v\n", err)
		os.Exit(1)
	}

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(1)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		fmt.Printf("Raw response: %s\n", line)
		os.Exit(1)
	}

	if jsonOutput {
		fmt.Println(line)
		return
	}

	// Pretty print status
	fmt.Println("Blast Radius Status")
	fmt.Println("===================")
	if status, ok := resp["status"].(string); ok {
		fmt.Printf("Status:     %s\n", status)
	}
	if msg, ok := resp["message"].(string); ok {
		fmt.Printf("Message:    %s\n", msg)
	}
	if reg, ok := resp["registry"].(map[string]any); ok {
		if count, ok := reg["tracked_hashes"].(float64); ok {
			fmt.Printf("Tracked hashes: %d\n", int(count))
		}
		if dups, ok := reg["duplicate_hashes"].(float64); ok && dups > 0 {
			fmt.Printf("Duplicate hashes: %d  ← Pillar 1 Alert\n", int(dups))
		}
		if uptime, ok := reg["uptime"].(string); ok {
			fmt.Printf("Uptime:     %s\n", uptime)
		}
		if scanState, ok := reg["scan_state"].(string); ok {
			fmt.Printf("Scan state:   %s\n", scanState)
		}
	}
	fmt.Printf("Socket:     %s\n", cfg.SocketPath)
	fmt.Println("===================")
	fmt.Println("No plaintext secrets or hashes are stored on disk (invariant upheld).")
}

// RunStop sends a HALT command to the running daemon for graceful shutdown.
func RunStop() {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		fmt.Println("No running Blast Radius daemon found.")
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("HALT\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send HALT command: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(1)
	}

	var resp map[string]any
	json.Unmarshal([]byte(line), &resp)

	if status, ok := resp["status"].(string); ok && status == "ok" {
		fmt.Println("Blast Radius daemon shutdown initiated.")
	} else {
		fmt.Println("Shutdown command sent.")
	}
}

// RunLogs prints recent daemon log output.
func RunLogs() {
	logPath := getDaemonLogPath()

	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No daemon log file found yet.")
			fmt.Printf("Log location: %s\n", logPath)
			return
		}
		fmt.Fprintf(os.Stderr, "Failed to read log file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Blast Radius Daemon Logs (%s) ===\n\n", logPath)
	fmt.Print(string(data))
	fmt.Println("\n=== End of log ===")
}

// RunDuplicates queries the daemon for duplicate secret hashes across projects (Pillar 1).
func RunDuplicates() {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("DUPLICATES\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send DUPLICATES command: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(1)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		fmt.Printf("Failed to parse response: %v\nRaw: %s\n", err, line)
		return
	}

	if status, ok := resp["status"].(string); ok && status != "ok" {
		fmt.Printf("Error: %v\n", resp["message"])
		return
	}

	total := 0
	if t, ok := resp["total"].(float64); ok {
		total = int(t)
	}

	fmt.Println("Blast Radius - Duplicate Secret Detection (Pillar 1)")
	fmt.Println("====================================================")
	if total == 0 {
		fmt.Println("No duplicate secrets detected across projects. Good!")
		fmt.Println("====================================================")
		return
	}

	fmt.Printf("Found %d secret hash(es) duplicated across multiple projects:\n\n", total)

	if dups, ok := resp["duplicates"].([]any); ok {
		for i, item := range dups {
			if m, ok := item.(map[string]any); ok {
				hash := m["hash"]
				projects := m["projects"]
				fmt.Printf("%d. Hash: %s\n", i+1, hash)
				fmt.Printf("   Appears in projects:\n")
				if projList, ok := projects.([]any); ok {
					for _, p := range projList {
						fmt.Printf("     - %s\n", p)
					}
				}
				fmt.Println()
			}
		}
	}
	fmt.Println("====================================================")
	fmt.Println("Recommendation: Review these projects and rotate the shared secrets if unintended.")
}

// RunScrubHistory triggers history file scrubbing (Pillar 4).
func RunScrubHistory() {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
	}
	defer conn.Close()

	fmt.Println("Requesting history scrub (this may take a moment)...")

	_, err = conn.Write([]byte("SCRUB_HISTORY\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send SCRUB_HISTORY command: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(1)
	}

	var resp map[string]any
	json.Unmarshal([]byte(line), &resp)

	if status, ok := resp["status"].(string); ok && status == "ok" {
		if removed, ok := resp["lines_removed"].(float64); ok && removed > 0 {
			fmt.Printf("✓ Successfully scrubbed %d sensitive line(s) from history.\n", int(removed))
			if f, ok := resp["file"].(string); ok {
				fmt.Printf("  File: %s\n", f)
			}
		} else {
			fmt.Println("✓ History scrub complete. No sensitive entries were found.")
		}
	} else {
		msg := "unknown error"
		if m, ok := resp["message"].(string); ok {
			msg = m
		}
		fmt.Printf("Scrub failed: %s\n", msg)
	}
}

// RunStart explicitly starts the daemon in the background.
func RunStart() {
	cfg, configPath, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting Blast Radius daemon...\n")
	fmt.Printf("Config: %s\n", configPath)
	fmt.Printf("Socket: %s\n", cfg.SocketPath)

	if err := startDaemonInBackground(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Daemon start requested. Use 'blastradius status' to verify.")
}

// startDaemonInBackground launches the daemon process detached and redirects its output to the log file.
func startDaemonInBackground() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, "daemon")

	// Redirect daemon output to log file (prevents terminal pollution)
	logPath := getDaemonLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return fmt.Errorf("failed to create log dir: %w", err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open daemon log file: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Start detached
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}

	// Don't wait for it
	go cmd.Wait()

	return nil
}

// getDaemonLogPath returns the canonical location for the daemon log file.
func getDaemonLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/blastradius-daemon.log"
	}
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}

// RunDaemon is the internal entrypoint for the background daemon process.
func RunDaemon() {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	reg := registry.New()
	d := daemon.New(cfg, reg)

	if err := d.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon failed: %v\n", err)
		os.Exit(1)
	}
}
