package cli

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestRunEnvCheck(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// config error path (wrap to recover post-osExit deref caused by no-op osExit in tests)
	configLoad = func() (*config.Config, string, error) { return nil, "", errForTest }
	func() {
		defer func() { recover() }()
		RunEnvCheck("")
	}()

	// reset to good config for remaining
	resetTestOverrides(t)

	// Make exec harmless for success case
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	// unknown pillar cmd (early return before dial/exec)
	RunEnvCheck("")
	RunEnvCheck("default-env")
	RunEnvCheck("nonexistent-pillar5-command")

	// valid pillar cmd + exec success + dial fail (override dial to be instant, no 2s timeout)
	cfgWithCmd := defaultTestConfig()
	cfgWithCmd.Pillar5Commands = []config.Pillar5Command{{Name: "default-env", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfgWithCmd, "/tmp/c", nil }
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return nil, errForTest }
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }
	RunEnvCheck("default-env")

	// exec failure path
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("false") }
	RunEnvCheck("default-env")
}

// TestRunEnvCheck_HappyPath exercises the full secret-checking loop using net.Pipe.
// This covers the previously untested happy path: line splitting, hashing,
// CHECK_HASH protocol, response parsing, and "secrets_found" counting.
func TestRunEnvCheck_HappyPath(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Setup a command that produces multiple lines (some will be "known")
	execCommand = func(name string, arg ...string) *exec.Cmd {
		// Use printf for portable multi-line output without extra newlines issues
		return exec.Command("sh", "-c", `printf "secret_value_one\nsecret_value_two\nnormal_line\n"`)
	}

	cfg := defaultTestConfig()
	cfg.Pillar5Commands = []config.Pillar5Command{{Name: "default-env", Cmd: "printenv"}}
	configLoad = func() (*config.Config, string, error) { return &cfg, "", nil }

	// Use a pipe so we can simulate the daemon's CHECK_HASH responses
	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	// Server side: read CHECK_HASH commands and reply with varying "known" results
	// We simulate: first secret known, second unknown, third (normal) unknown
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		knownCount := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "CHECK_HASH ") {
				continue
			}
			// Simple simulation: treat the first two CHECK_HASH as known for coverage
			knownCount++
			resp := `{"known":false}`
			if knownCount == 1 {
				resp = `{"known":true}`
			}
			_, _ = fmt.Fprintf(serverConn, "%s\n", resp)
		}
	}()

	// This should now exercise:
	// - multiple lines
	// - skipping empty
	// - hashing + sending CHECK_HASH
	// - reading responses
	// - counting known matches
	// - printing the final success JSON with secrets_found
	RunEnvCheck("default-env")
}
