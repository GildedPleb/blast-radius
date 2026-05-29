package cli

import (
	"net"
	"os"
	"os/exec"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func resetTestOverrides() {
	configLoad = func() (*config.Config, string, error) {
		cfg := defaultTestConfig()
		return &cfg, "", nil
	}
	netDialTimeout = net.DialTimeout
	execCommand = exec.Command
	osReadFile = os.ReadFile
	osUserHomeDir = os.UserHomeDir
	sendDaemonCommandFn = realSendDaemonCommand
	osExit = func(code int) {} // silent no-op during tests
}

// mockSendDaemonCommand returns a sendDaemonCommandFn that always returns the given line.
func mockSendDaemonCommand(respLine string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		return respLine, nil
	}
}

// defaultTestConfig returns a minimal config for tests.
func defaultTestConfig() config.Config {
	return config.Config{
		SocketPath: "/tmp/br-test.sock",
	}
}
