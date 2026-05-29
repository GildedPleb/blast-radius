package cli

import (
	"errors"
	"os"
	"testing"
)

func TestRunLogs_NoFile(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Point logs to a path that definitely doesn't exist
	getDaemonLogPathFn = func() string {
		return "/tmp/blastradius-nonexistent-test-dir/daemon.log"
	}

	RunLogs()
	// Should print the friendly "No daemon log file found yet" message.
	// We don't assert stdout here (silenced), but the fact it didn't call osExit or panic is the win.
}

func TestRunLogs_Success(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	fakeLogContent := "2026-05-28T10:00:00.123456 blastradius: Daemon started\n" +
		"2026-05-28T10:01:00.234567 blastradius: Registry snapshot: 42 hashes\n"

	getDaemonLogPathFn = func() string { return "/fake/path/daemon.log" }
	osReadFile = func(name string) ([]byte, error) {
		if name == "/fake/path/daemon.log" {
			return []byte(fakeLogContent), nil
		}
		return nil, os.ErrNotExist
	}

	RunLogs()
	// Coverage: happy path through reading + printing the log
}

func TestRunLogs_ReadError(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	exitCalled := false
	osExit = func(code int) { exitCalled = true }

	getDaemonLogPathFn = func() string { return "/some/path/daemon.log" }
	osReadFile = func(name string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}

	RunLogs()

	if !exitCalled {
		t.Error("expected osExit(1) to be called on non-NotExist read error")
	}
}

func TestRunLogs_UsesRealGetDaemonLogPath(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Ensure the default getDaemonLogPathFn still works when not overridden
	// (mostly a smoke test that the wiring is correct)
	tmpHome := t.TempDir()
	osUserHomeDir = func() (string, error) { return tmpHome, nil }

	// Force a not-exist case so we don't need a real log file
	getDaemonLogPathFn = getDaemonLogPath // reset to real impl

	RunLogs()
}
