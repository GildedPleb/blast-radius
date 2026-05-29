package cli

import (
	"bufio"
)

// sendDaemonCommand connects to the daemon, sends a single-line command, and returns the response line.
func sendDaemonCommand(cmd string) (string, error) {
	return sendDaemonCommandFn(cmd)
}

// realSendDaemonCommand is the actual implementation.
func realSendDaemonCommand(cmd string) (string, error) {
	cfg, _, err := configLoad()
	if err != nil {
		return "", err
	}
	conn, err := netDialTimeout("unix", cfg.SocketPath, socketConnectTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}


