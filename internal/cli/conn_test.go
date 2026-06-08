package cli

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// errForTest and silenceOutput are provided by cli_test.go (compiled together into the
// package test binary).

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

// TestRealSendDaemonCommand_ReadErrorAfterSuccessfulWrite specifically hits the
// ReadString error path inside realSendDaemonCommand (the one still showing as uncovered).
func TestRealSendDaemonCommand_ReadErrorAfterSuccessfulWrite(t *testing.T) {
	resetTestOverrides(t) // not deferred so overrides stay active during the test body

	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "tok123", nil }

	go func() {
		r := bufio.NewReader(s)
		// Consume AUTH line (so client's first Write succeeds)
		_, _ = r.ReadString('\n')
		// Consume the actual command line (so client's second Write succeeds)
		_, _ = r.ReadString('\n')
		// Now close WITHOUT sending any reply → client's ReadString will fail
		s.Close()
	}()

	_, err := realSendDaemonCommand("PING")
	if err == nil {
		t.Error("expected read error from ReadString after successful writes")
	}
}

// TestBatchCheckKnownSecrets_ReadErrorInLoop specifically hits the
// reader.ReadString error path inside the candidate loop in batchCheckKnownSecrets.
func TestBatchCheckKnownSecrets_ReadErrorInLoop(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "tok123", nil }

	go func() {
		r := bufio.NewReader(s)
		// Best-effort AUTH (may or may not be sent depending on timing, just drain)
		_, _ = r.ReadString('\n')
		// Read the CHECK_HASH line the client will send
		_, _ = r.ReadString('\n')
		// Close without replying → the ReadString in batchCheck will error
		s.Close()
	}()

	known, err := batchCheckKnownSecrets([]string{"supersecretvalue123"})
	// We expect no top-level error (batch swallows per-candidate read errs and continues)
	if err != nil {
		t.Fatalf("batchCheckKnownSecrets should not return top-level err on per-candidate read failure: %v", err)
	}
	// known should be empty because the read failed and we continued
	if len(known) != 0 {
		t.Errorf("expected empty known list when read errored, got %v", known)
	}
}

// TestRealSendDaemonCommand_WriteErrorAfterAuth specifically hits the
// Write error path for the *command* (after successful AUTH) inside
// realSendDaemonCommand.
func TestRealSendDaemonCommand_WriteErrorAfterAuth(t *testing.T) {
	resetTestOverrides(t) // not deferred so overrides stay active during the test body

	c, s := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return c, nil
	}
	readAuthTokenForSocket = func(string) (string, error) { return "tok123", nil }

	go func() {
		r := bufio.NewReader(s)
		// Consume AUTH line (so client's first Write in openDaemonConn succeeds)
		_, _ = r.ReadString('\n')
		// Close *without* consuming the command line → client's second Write will fail
		s.Close()
	}()

	_, err := realSendDaemonCommand("PING")
	if err == nil {
		t.Error("expected write error from command Write after successful AUTH")
	}
}
