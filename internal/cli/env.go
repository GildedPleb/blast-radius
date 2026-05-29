package cli

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

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
	output, err := execCommand("sh", "-c", cmdToRun).CombinedOutput()
	if err != nil {
		logging.Printf("RunEnvCheck: command failed: %v", err)
		fmt.Printf(`{"status":"error","message":"command failed: %v"}`+"\n", err)
		return
	}

	// Send each line to daemon for hashing/checking
	conn, err := netDialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
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
