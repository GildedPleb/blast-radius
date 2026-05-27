package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
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

// sendRecorderCommand sends a command to the per-TTY recorder socket and returns the first response line.
// Used for simple control commands. For streaming replays, prefer openRecorderConn + manual read loop.
func sendRecorderCommand(cmd string) (string, error) {
	return sendRecorderCommandFn(cmd)
}

// realSendRecorderCommand is the actual implementation (uses per-TTY socket + same timeout).
func realSendRecorderCommand(cmd string) (string, error) {
	socket := getRecorderSocketPath()
	conn, err := netDialTimeout("unix", socket, socketConnectTimeout)
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

// openRecorderConn dials the per-TTY recorder control socket and returns the live conn.
// Caller is responsible for Close(). Intended for streaming responses (REPLAY_REDACTED).
func openRecorderConn() (net.Conn, error) {
	socket := getRecorderSocketPath()
	return netDialTimeout("unix", socket, socketConnectTimeout)
}

// sendRecorderReplayRequest sends the REPLAY_REDACTED command (with optional N and options)
// over a fresh conn, then streams all output to the provided writer until "OK\n" or error.
// It returns the final status line or error. This is the core of `blastradius redact`.
func sendRecorderReplayRequest(payload string, out *os.File) error {
	return sendRecorderReplayRequestFn(payload, out)
}

func realSendRecorderReplayRequest(payload string, out *os.File) error {
	conn, err := openRecorderConn()
	if err != nil {
		return fmt.Errorf("cannot reach recorder (is protection active?): %w", err)
	}
	defer conn.Close()

	cmdLine := "REPLAY_REDACTED"
	if payload != "" {
		cmdLine += " " + payload
	}
	if _, err := conn.Write([]byte(cmdLine + "\n")); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("replay stream error: %w", err)
		}
		if strings.TrimSpace(line) == "OK" {
			// do not print the OK sentinel to user
			return nil
		}
		// Stream the redacted (or partially raw) history to the terminal
		fmt.Fprint(out, line)
	}
}


