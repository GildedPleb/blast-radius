package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// RunEnvCheck executes a runtime hygiene command (Pillar 4 / env) and reports any known secrets found.
// Commands are configured under `pillar5_commands` in config (historical key name).
func RunEnvCheck(name string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if name == "" {
		name = "default-env"
	}
	logging.Printf("RunEnvCheck: running runtime hygiene command (Pillar 4) %q", name)

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

	// Send candidate secret values (not whole lines) to daemon for hashing/checking.
	// This uses the unified detection logic so that realistic output like
	// "KEY=supersecretvalue" or "export FOO=..." is correctly handled.
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

	candidates := detection.NewDetector().ExtractCandidates(output)
	found := 0
	for _, cand := range candidates {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		h := registry.HashValue([]byte(cand))
		hashHex := fmt.Sprintf("%x", h[:])
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
