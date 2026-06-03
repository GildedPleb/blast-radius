package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
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
// It performs the AUTH handshake (capability token) before the real command.
func realSendDaemonCommand(cmd string) (string, error) {
	conn, err := openDaemonConn()
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

// openDaemonConn does the full strict AUTH handshake for normal single-command paths.
// It loads config (for socket path) and returns a live conn or error.
func openDaemonConn() (net.Conn, error) {
	if _, _, err := configLoad(); err != nil {
		return nil, err
	}
	socketPath := config.SocketPath()
	conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
	if err != nil {
		return nil, err
	}
	token, err := readAuthTokenForSocket(socketPath)
	if err != nil {
		conn.Close()
		return nil, err
	}
	authLine := "AUTH " + token + "\n"
	if _, err := conn.Write([]byte(authLine)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// openDaemonConnBestEffort does a best-effort AUTH write only (for multi-CHECK batch
// paths like clipboard/env that open one conn and send many CHECK_HASH lines).
// Callers treat write failures as "count may be incomplete" (same as before).
// It uses the package seam readAuthTokenForSocket so tests can override.
func openDaemonConnBestEffort() (net.Conn, error) {
	socketPath := config.SocketPath()
	conn, err := netDialTimeout("unix", socketPath, socketConnectTimeout)
	if err != nil {
		return nil, err
	}
	if token, readErr := readAuthTokenForSocket(socketPath); readErr == nil {
		authLine := "AUTH " + token + "\n"
		if _, werr := conn.Write([]byte(authLine)); werr != nil {
			// best effort; caller will see subsequent CHECKs fail
			logging.Printf("conn: AUTH write error (best-effort): %v (subsequent checks may be incomplete)", werr)
		}
	}
	return conn, nil
}

// batchCheckKnownSecrets opens one post-AUTH conn (best-effort) and issues CHECK_HASH
// for each candidate. Returns the list of *known* secret values (as they appeared in
// the input candidates) for the caller to count or redact. Per-candidate errors are
// logged (via logging) and skipped so a partial count is still useful.
func batchCheckKnownSecrets(candidates []string) ([]string, error) {
	conn, err := openDaemonConnBestEffort()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	var known []string
	for _, cand := range candidates {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		h := registry.HashValue([]byte(cand))
		hashHex := fmt.Sprintf("%x", h[:])
		cmdLine := fmt.Sprintf("CHECK_HASH %s\n", hashHex)
		if _, err := conn.Write([]byte(cmdLine)); err != nil {
			logging.Printf("batchCheck: CHECK_HASH write error (candidate): %v", err)
			continue
		}
		resp, err := reader.ReadString('\n')
		if err != nil {
			logging.Printf("batchCheck: CHECK_HASH read error (candidate): %v", err)
			continue
		}
		if strings.Contains(resp, `"known":true`) {
			known = append(known, cand)
		}
	}
	return known, nil
}

// parseDaemonResponse is a small helper for the common CLI "send + unmarshal" pattern.
//   - On send/conn error: returns err with raw="", so callers treat as "no daemon".
//   - On successful send but bad JSON: returns err (the unmarshal err) with raw set to the
//     received line. Callers can then emit a diagnostic "daemon produced bad response"
//     including the raw, instead of the generic "no daemon" message.
//
// The raw is only populated for the "we heard back but could not parse" case.
func parseDaemonResponse(cmd string) (resp map[string]any, raw string, err error) {
	line, err := sendDaemonCommand(cmd)
	if err != nil {
		return nil, "", err
	}
	raw = line
	var m map[string]any
	if uerr := json.Unmarshal([]byte(line), &m); uerr != nil {
		return nil, raw, uerr
	}
	return m, raw, nil
}

// daemonNotRunningMsg is the common user-facing message for daemon-absent paths.
const daemonNotRunningMsg = "No running Blast Radius daemon found. Start it with 'blastradius start'."
