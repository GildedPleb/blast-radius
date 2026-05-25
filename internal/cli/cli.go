package cli

import (
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

const (
	socketConnectTimeout = 2 * time.Second
	daemonStartWait      = 500 * time.Millisecond
)

// Overridable for testing (DI via var assignment)
var (
	configLoad          = config.Load
	netDialTimeout      = net.DialTimeout
	execCommand         = exec.Command
	osReadFile          = os.ReadFile
	osUserHomeDir       = os.UserHomeDir
	sendDaemonCommandFn = realSendDaemonCommand
	osExit              = os.Exit
)
