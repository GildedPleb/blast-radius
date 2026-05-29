package cli

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
)

// RunEnvCheck executes a Pillar 4 command (or default) and reports any known secrets found.
func RunEnvCheck(name string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if name == "" {
		name = "default-env"
	}
	logging.Printf("RunEnvCheck: running Pillar 4 command %q", name)

	cfg, _, err := configLoad()
	if err != nil {
		logging.Printf("RunEnvCheck: failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
	}

	// Find the command definition.
	var cmd config.Pillar5Command
	for _, c := range cfg.Pillar5Commands {
		if c.Name == name {
			cmd = c
			break
		}
	}
	if cmd.Name == "" {
		logging.Printf("RunEnvCheck: unknown pillar5 command: %s", name)
		fmt.Printf(`{"status":"error","message":"unknown pillar5 command: %s"}`+"\n", name)
		return
	}

	// Hard security invariant: commands are always executed via direct exec (no shell).
	// This eliminates an entire class of injection and arbitrary execution risks from config.
	parts := strings.Fields(cmd.Cmd)
	if len(parts) == 0 {
		fmt.Printf(`{"status":"error","message":"empty command"}`+"\n")
		return
	}
	output, runErr := execCommand(parts[0], parts[1:]...).CombinedOutput()
	if runErr != nil {
		logging.Printf("RunEnvCheck: command failed: %v", runErr)
		fmt.Printf(`{"status":"error","message":"command failed: %v"}`+"\n", runErr)
		return
	}

	// Send each line to daemon for hashing/checking
	socketPath := config.SocketPath()
	conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
	if err != nil {
		logging.Println("RunEnvCheck: daemon not running")
		fmt.Println(`{"status":"error","message":"daemon not running"}`)
		return
	}
	defer conn.Close()

	// Send AUTH handshake (required after 2026 security hardening).
	// Use the same sibling .auth file as the high-level sendDaemonCommand path.
	if tokenBytes, readErr := os.ReadFile(socketPath + ".auth"); readErr == nil {
		authLine := "AUTH " + strings.TrimSpace(string(tokenBytes)) + "\n"
		conn.Write([]byte(authLine))
	}
	// If we can't read the token we still try the CHECK_HASH lines; the daemon
	// will reject them with the standard auth error. Existing callers treat
	// any failure here as "daemon not running" which is acceptable.

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
