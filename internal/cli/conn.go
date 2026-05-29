package cli

import (
	"bufio"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// sendDaemonCommand connects to the daemon, sends a single-line command, and returns the response line.
func sendDaemonCommand(cmd string) (string, error) {
	return sendDaemonCommandFn(cmd)
}

// readAuthTokenForSocket is overridable (test seam) so tests that exercise the
// real send path can supply a token without touching the filesystem.
var readAuthTokenForSocket = realReadAuthTokenForSocket

func realReadAuthTokenForSocket(socketPath string) (string, error) {
	data, err := os.ReadFile(socketPath + ".auth")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// realSendDaemonCommand is the actual implementation.
// It performs the 2026 AUTH handshake (read sibling .auth file, send "AUTH <token>\n")
// before the real command. This is required for all connections after the security hardening.
func realSendDaemonCommand(cmd string) (string, error) {
	if _, _, err := configLoad(); err != nil {
		return "", err
	}

	socketPath := config.SocketPath()
	conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Read the capability token that the daemon wrote next to its socket.
	token, err := readAuthTokenForSocket(socketPath)
	if err != nil {
		// If we can't read the token, the daemon may be an old version or the
		// socket dir is inaccessible. Let the subsequent write fail with a
		// clear "daemon not reachable" style error (existing callers already
		// treat connection/write errors as "daemon not running").
		conn.Close()
		return "", err
	}
	authLine := "AUTH " + token + "\n"
	if _, err := conn.Write([]byte(authLine)); err != nil {
		return "", err
	}

	// Now send the real command the caller wanted.
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}

