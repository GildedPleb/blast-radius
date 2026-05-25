package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/daemon"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/recorder"
)

const (
	socketConnectTimeout = 2 * time.Second
	daemonStartWait      = 500 * time.Millisecond
)

// sendDaemonCommand connects to the daemon, sends a single-line command, and returns the response line.
func sendDaemonCommand(cmd string) (string, error) {
	cfg, _, err := config.Load()
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}

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
	fmt.Println("  clear          Trigger or document Phase 4 redaction rebuild (Pillar 3)")
	fmt.Println("  env [name]     Run Pillar 5 runtime hygiene check (default: printenv)")
	fmt.Println("  clipboard      Pillar 2 clipboard status / clear (macOS)")
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
	line, err := sendDaemonCommand("STATUS")
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
	cfg, _, _ := config.Load()
	fmt.Printf("Socket:     %s\n", cfg.SocketPath)
	fmt.Println("===================")
	fmt.Println("No plaintext secrets or hashes are stored on disk (invariant upheld).")
}

// RunStop sends a HALT command to the running daemon for graceful shutdown.
func RunStop() {
	line, err := sendDaemonCommand("HALT")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found.")
		return
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
		logging.Printf("RunLogs: failed to read log file: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to read log file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Blast Radius Daemon Logs (%s) ===\n\n", logPath)
	fmt.Print(string(data))
	fmt.Println("\n=== End of log ===")
}

// RunDuplicates queries the daemon for duplicate secret hashes across projects (Pillar 1).
func RunDuplicates() {
	line, err := sendDaemonCommand("DUPLICATES")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
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
	fmt.Println("Requesting history scrub (this may take a moment)...")

	line, err := sendDaemonCommand("SCRUB_HISTORY")
	if err != nil {
		fmt.Println("No running Blast Radius daemon found. Start it with 'blastradius start'.")
		return
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

// RunClear provides CLI entrypoint for Phase 4 redaction rebuild.
// In practice, the heavy lifting is done by the Zsh `blastradius_clear` function per-terminal.
// This CLI command can be used to trigger a global awareness or future cross-terminal features.
func RunClear() {
	fmt.Println("Blast Radius Clear (Phase 4 - Pillar 3)")
	fmt.Println("========================================")
	fmt.Println("The primary redaction/rebuild is performed per-terminal via the Zsh function:")
	fmt.Println("  br-clear   or   blastradius_clear")
	fmt.Println()
	fmt.Println("This triggers:")
	fmt.Println("  - Full terminal + scrollback wipe")
	fmt.Println("  - Replay of redacted session history (from live typescript capture)")
	fmt.Println("  - HUD update and state reset")
	fmt.Println()
	fmt.Println("To enable automatic redaction after sensitive commands, ensure your Zsh hooks are installed:")
	fmt.Println("  source ~/.config/blastradius/blastradius.zsh  (or wherever installed)")
	fmt.Println("========================================")
	fmt.Println("No plaintext secrets are ever stored or transmitted.")
}

// RunStart explicitly starts the daemon in the background.
func RunStart() {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	cfg, configPath, err := config.Load()
	if err != nil {
		logging.Printf("RunStart: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting Blast Radius daemon...\n")
	fmt.Printf("Config: %s\n", configPath)
	fmt.Printf("Socket: %s\n", cfg.SocketPath)

	if err := startDaemonInBackground(); err != nil {
		logging.Printf("RunStart: failed to start daemon: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	logging.Println("RunStart: daemon start requested")
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
	_ = logging.Init(logging.DefaultDaemonLogPath())

	cfg, _, err := config.Load()
	if err != nil {
		logging.Printf("RunDaemon: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	reg := registry.New()
	d := daemon.New(cfg, reg)

	if err := d.Run(); err != nil {
		logging.Printf("RunDaemon: daemon failed: %v", err)
		fmt.Fprintf(os.Stderr, "Daemon failed: %v\n", err)
		os.Exit(1)
	}
}

// RunCheckHash is used by Zsh redaction layer (Phase 4) to query if a SHA-256 hex is known.
func RunCheckHash(hexHash string) {
	line, err := sendDaemonCommand(fmt.Sprintf("CHECK_HASH %s", hexHash))
	if err != nil {
		// Daemon not running — treat as unknown (safe default)
		fmt.Println(`{"known":false,"message":"daemon not running"}`)
		return
	}
	fmt.Print(line) // already JSON
}

// RunRecorder launches the Go PTY recorder (simple CLI entry for #1).
func RunRecorder(args []string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if len(args) == 0 {
		fmt.Println("recorder start|stop")
		return
	}
	switch args[0] {
	case "start":
		logging.Printf("RunRecorder: starting recorder")
		rec, err := recorder.NewRecorder()
		if err != nil {
			logging.Printf("RunRecorder: failed to start recorder: %v", err)
			fmt.Fprintf(os.Stderr, "recorder start failed: %v\n", err)
			os.Exit(1)
		}
		rec.StartNewWindow()
		socket := os.Getenv("BR_RECORDER_SOCKET")
		if socket == "" {
			socket = filepath.Join(os.TempDir(), "br-recorder.sock")
		}
		fmt.Printf("Recorder started. Control socket: %s\n", socket)
		logging.Printf("RunRecorder: control socket = %s", socket)
		rec.RunControlServer(socket)
	case "stop":
		logging.Println("RunRecorder: stop requested (stub)")
		fmt.Println("use socket or kill for now")
	default:
		fmt.Println("unknown recorder cmd")
	}
}

// RunConfig handles subcommands under "blastradius config".
func RunConfig(args []string) {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Printf(`{"error":"%s"}`+"\n", err)
		return
	}
	if len(args) == 0 {
		fmt.Println("config redaction")
		return
	}
	switch args[0] {
	case "redaction":
		jsonOut, _ := json.Marshal(cfg.Redaction)
		fmt.Println(string(jsonOut))
	default:
		fmt.Println("unknown config subcommand")
	}
}

// RunEnvCheck executes a Pillar 5 command (or default) and reports any known secrets found.
func RunEnvCheck(name string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if name == "" {
		name = "default-env"
	}
	logging.Printf("RunEnvCheck: running pillar5 command %q", name)

	cfg, _, err := config.Load()
	if err != nil {
		logging.Printf("RunEnvCheck: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Find the command definition
	var cmdToRun string
	for _, c := range cfg.Pillar5Commands {
		if c.Name == name {
			cmdToRun = c.Cmd
			break
		}
	}
	if cmdToRun == "" {
		logging.Printf("RunEnvCheck: unknown pillar5 command: %s", name)
		fmt.Printf(`{"status":"error","message":"unknown pillar5 command: %s"}`+"\n", name)
		return
	}

	// Execute the command
	output, err := exec.Command("sh", "-c", cmdToRun).CombinedOutput()
	if err != nil {
		logging.Printf("RunEnvCheck: command failed: %v", err)
		fmt.Printf(`{"status":"error","message":"command failed: %v"}`+"\n", err)
		return
	}

	// Send each line to daemon for hashing/checking
	conn, err := net.DialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		logging.Println("RunEnvCheck: daemon not running")
		fmt.Println(`{"status":"error","message":"daemon not running"}`)
		return
	}
	defer conn.Close()

	lines := strings.Split(string(output), "\n")
	found := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		hash := sha256.Sum256([]byte(line))
		hashHex := fmt.Sprintf("%x", hash[:])
		cmd := fmt.Sprintf("CHECK_HASH %s\n", hashHex)
		conn.Write([]byte(cmd))
		reader := bufio.NewReader(conn)
		resp, _ := reader.ReadString('\n')
		if strings.Contains(resp, `"known":true`) {
			found++
		}
	}

	logging.Printf("RunEnvCheck: command=%s, secrets_found=%d", name, found)
	fmt.Printf(`{"status":"ok","command":"%s","secrets_found":%d}`+"\n", name, found)
}

// RunClipboard handles Pillar 2 clipboard operations (macOS only for v1)
func RunClipboard(args []string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status", "check":
		logging.Println("RunClipboard: checking clipboard")
		out, err := exec.Command("pbpaste").Output()
		if err != nil {
			logging.Println("RunClipboard: pbpaste failed")
			fmt.Println(`{"status":"error","message":"pbpaste failed (macOS only)"}`)
			return
		}
		hash := sha256.Sum256(out)
		hashHex := fmt.Sprintf("%x", hash[:])
		resp, err := sendDaemonCommand(fmt.Sprintf("CHECK_HASH %s", hashHex))
		if err != nil {
			logging.Println("RunClipboard: daemon not running")
			fmt.Println(`{"status":"unknown","message":"daemon not running"}`)
			return
		}
		fmt.Print(resp)
	case "clear":
		logging.Println("RunClipboard: clearing clipboard")
		exec.Command("pbcopy").Run()
		fmt.Println(`{"status":"ok","message":"clipboard cleared"}`)
	default:
		fmt.Println("clipboard status|check|clear")
	}
}
