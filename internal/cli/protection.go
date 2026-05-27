package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RunProtection dispatches protection subcommands.
func RunProtection(args []string) {
	if len(args) == 0 {
		fmt.Println("protection start|stop")
		return
	}
	switch args[0] {
	case "start":
		runProtectionStart()
	case "stop":
		runProtectionStop()
	default:
		fmt.Println("unknown protection cmd")
	}
}

func runProtectionStart() {
	// Fail loudly if global daemon not running
	if _, err := sendDaemonCommand("PING"); err != nil {
		fmt.Fprintf(os.Stderr, "daemon not running (required for protection): %v\n", err)
		osExit(1)
	}

	socket := getRecorderSocketPath()
	if _, err := os.Stat(socket); err == nil {
		// Socket file exists — verify the recorder is actually listening.
		// If a previous recorder died uncleanly we have a stale socket.
		if _, err := sendRecorderCommand("RECORDER_STATUS"); err == nil {
			fmt.Println("protection already active for this terminal")
			return
		}
		// Stale socket — clean it up so we can start fresh.
		_ = os.Remove(socket)
	}

	// Ensure state dir
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create recorder dir: %v\n", err)
		osExit(1)
	}

	// Launch recorder detached with explicit socket
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to locate binary: %v\n", err)
		osExit(1)
	}

	cmd := exec.Command(exe, "recorder", "start", socket)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start recorder: %v\n", err)
		osExit(1)
	}
	go cmd.Wait()

	// Wait for socket registration (short poll)
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(socket); err == nil {
			fmt.Printf("Protection started. Socket: %s\n", socket)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "recorder failed to register socket\n")
	osExit(1)
}

func runProtectionStop() {
	socket := getRecorderSocketPath()
	if _, err := os.Stat(socket); os.IsNotExist(err) {
		fmt.Println("protection not active")
		return
	}

	fmt.Println("stopping protection...")

	// Best-effort graceful shutdown: send STOP (handler will kill inner PTY
	// zsh + close listener + TriggerShutdown). Ignore errors (socket may be
	// half-gone or recorder already exiting).
	_, _ = sendRecorderCommand("STOP")

	// Always unlink the socket so getRecorderSocketPath() + ProtectionModeGuard
	// immediately see protection as inactive. The recorder's own listener
	// close (via shutdown chan) will also clean up on its side.
	_ = os.Remove(socket)

	fmt.Println("Protection stopped.")
}
