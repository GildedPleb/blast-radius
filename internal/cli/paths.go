package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// getDaemonLogPath returns the canonical location for the daemon log file.
func getDaemonLogPath() string {
	home, err := osUserHomeDir()
	if err != nil {
		return "/tmp/blastradius-daemon.log"
	}
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}

// startDaemonInBackground launches the daemon process detached and redirects its output to the log file.
func startDaemonInBackground() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := execCommand(exe, "daemon")

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

// getRecorderSocketPath returns deterministic per-terminal recorder socket using TTY hash.
//
// The path is ~/.local/state/blastradius/recorder-<8hex>.sock where the hex is the
// first 8 bytes of sha256( sanitize( controlling-tty-name ) ) with "/" → "_".
//
// Discovery order (robust across Terminal, iTerm, VS Code, tmux, ssh, etc.):
//  1. $TTY (if set by the shell or zsh plugin)
//  2. Output of `tty` command (what the kernel thinks is our ctty)
//  3. Hard fallback "/dev/tty"
func getRecorderSocketPath() string {
	tty := getCurrentTTYName()
	safe := strings.ReplaceAll(tty, "/", "_")
	h := sha256.Sum256([]byte(safe))
	home, _ := osUserHomeDir()
	return filepath.Join(home, ".local", "state", "blastradius", fmt.Sprintf("recorder-%x.sock", h[:8]))
}

// getCurrentTTYName attempts to discover the path of the controlling terminal
// for the current process using multiple strategies. It never returns "".
func getCurrentTTYName() string {
	if t := os.Getenv("TTY"); t != "" {
		return t
	}
	// Ask the OS what our controlling tty is. This works even when the
	// process was not started from a login shell that exported $TTY.
	out, err := execCommand("tty").Output()
	if err == nil {
		name := strings.TrimSpace(string(out))
		if name != "" && !strings.Contains(strings.ToLower(name), "not a tty") {
			return name
		}
	}
	return "/dev/tty"
}

// ProtectionModeGuard returns error if no recorder socket for current TTY.
func ProtectionModeGuard() error {
	path := getRecorderSocketPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("protection mode not active for this terminal (run: blastradius protection start)")
	}
	return nil
}
