package cli

import (
	"net"
	"strings"
	"testing"
	"time"
)

// errForTest and silenceOutput are provided by cli_test.go (compiled together into the
// package test binary). They are used by many conn-related tests for consistent
// error injection and output silencing.

func TestParseDaemonResponse_SuccessAndErrors(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Happy path: successful send + valid JSON -> resp map populated, raw set, no err
	sendDaemonCommandFn = mockSendDaemonCommand(`{"status":"ok","known":true,"hash":"deadbeef"}`)
	m, raw, err := parseDaemonResponse("CHECK_HASH deadbeef")
	if err != nil {
		t.Fatalf("unexpected err on happy: %v", err)
	}
	if m["status"] != "ok" || raw == "" {
		t.Errorf("happy parse failed: map=%+v raw=%q", m, raw)
	}

	// Send/conn error path (e.g. no daemon): err returned, raw remains empty string
	sendDaemonCommandFn = func(string) (string, error) { return "", errForTest }
	_, raw, err = parseDaemonResponse("STATUS")
	if err != errForTest || raw != "" {
		t.Errorf("send-err path bad: err=%v raw=%q", err, raw)
	}

	// Successful send but unmarshal fails: err set (json err), raw populated with the bad line
	// (callers can then print a better diagnostic including the raw daemon output)
	sendDaemonCommandFn = mockSendDaemonCommand(`this is not valid json at all`)
	_, raw, err = parseDaemonResponse("PING")
	if err == nil || raw == "" {
		t.Error("bad-json path should return unmarshal err and set raw")
	}
}

func TestOpenDaemonConnBestEffort(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Default (no daemon listening on test socket): dial fails, err returned
	if _, err := openDaemonConnBestEffort(); err == nil {
		t.Error("expected dial error when no daemon")
	}

	// Dial succeeds, token read fails (best-effort semantics): still return conn + nil err
	// (AUTH is skipped; caller will see subsequent ops fail but count may be partial)
	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "", errForTest }
	conn, err := openDaemonConnBestEffort()
	if err != nil {
		t.Fatalf("best-effort should tolerate token read failure: %v", err)
	}
	conn.Close()
	s.Close()

	// Dial succeeds, token ok, but AUTH *write* fails (best-effort): log warning + return conn anyway
	c, s = net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "test-token", nil }
	s.Close() // force immediate write error on AUTH
	conn, err = openDaemonConnBestEffort()
	if err != nil {
		t.Fatalf("best-effort should tolerate AUTH write failure: %v", err)
	}
	conn.Close()
}

func TestBatchCheckKnownSecrets(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// No daemon: open fails -> err returned immediately (no partial results)
	known, err := batchCheckKnownSecrets([]string{"secret-one", "secret-two"})
	if err == nil || len(known) != 0 {
		t.Errorf("no-daemon path: err=%v known=%v (want err + empty)", err, known)
	}

	// All-blank / empty candidates: open succeeds (we force it), loop skips every entry via continue,
	// returns []string{}, nil with no writes or daemon interaction attempted.
	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "", errForTest } // skip AUTH write
	known, err = batchCheckKnownSecrets([]string{"", "   ", "\n\t", ""})
	if err != nil || len(known) != 0 {
		t.Errorf("blank-skip path: err=%v known=%v (want nil err + empty)", err, known)
	}
	c.Close()
	s.Close()
}
