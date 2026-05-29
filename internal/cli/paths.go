package cli

import (
	"fmt"
	"os"
	"path/filepath"
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
	exe, err := osExecutable()
	if err != nil {
		return err
	}

	cmd := execCommand(exe, "daemon")

	// Redirect daemon output to log file (prevents terminal pollution)
	logPath := getDaemonLogPathFn()
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
