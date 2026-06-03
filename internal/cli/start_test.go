package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestGetDaemonLogPath(t *testing.T) {
	defer resetTestOverrides(t)

	// Point to a controlled temp home so we don't touch the real ~/.local
	tmpHome := t.TempDir()
	osUserHomeDir = func() (string, error) { return tmpHome, nil }

	p := getDaemonLogPath()
	expected := filepath.Join(tmpHome, ".local", "state", "blastradius", "daemon.log")
	if p != expected {
		t.Errorf("getDaemonLogPath() = %q, want %q", p, expected)
	}
}

func TestGetDaemonLogPath_FallbackOnError(t *testing.T) {
	defer resetTestOverrides(t)

	osUserHomeDir = func() (string, error) { return "", errForTest } // simulate failure

	p := getDaemonLogPath()
	if p != "/tmp/blastradius-daemon.log" {
		t.Errorf("getDaemonLogPath on home error = %q, want fallback", p)
	}
}

// errForTest is a sentinel error for tests.
var errForTest = &testError{}

type testError struct{}

func (e *testError) Error() string { return "test error" }

func TestStartDaemonInBackground(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	tmpHome := t.TempDir()
	osUserHomeDir = func() (string, error) { return tmpHome, nil }

	// Make os.Executable succeed with a fake path
	osExecutable = func() (string, error) { return "/tmp/fake-blastradius", nil }

	// Make exec.Command return something that will "succeed" without real work.
	// Using "true" (exists on macOS and Unix) makes Start + Wait succeed cleanly.
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	err := startDaemonInBackground()
	if err != nil {
		t.Fatalf("startDaemonInBackground returned error: %v", err)
	}
}

func TestRunStart(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	tmpHome := t.TempDir()
	osUserHomeDir = func() (string, error) { return tmpHome, nil }

	osExecutable = func() (string, error) { return "/tmp/fake-blastradius", nil }

	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	// Should not panic or call real os.Exit (thanks to resetTestOverrides)
	RunStart()
}

func TestStartDaemonInBackground_Errors(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// osExecutable error
	osExecutable = func() (string, error) { return "", errForTest }
	if err := startDaemonInBackground(); err == nil {
		t.Error("expected exe error")
	}

	// mkdir error via bad log path (blocker file)
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blockerfile")
	_ = os.WriteFile(blocker, []byte("x"), 0600)
	osUserHomeDir = func() (string, error) { return tmp, nil }
	getDaemonLogPathFn = func() string { return filepath.Join(blocker, "logs", "d.log") }
	osExecutable = func() (string, error) { return "/fake", nil }
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }
	if err := startDaemonInBackground(); err == nil {
		t.Error("expected mkdir error")
	}

	// open log file error: mkdir succeeds (parent is real dir) but the target log path
	// itself is an existing directory -> OpenFile(..., O_WRONLY) fails.
	logAsDir := filepath.Join(tmp, "logasdir")
	_ = os.Mkdir(logAsDir, 0700)
	getDaemonLogPathFn = func() string { return logAsDir }
	if err := startDaemonInBackground(); err == nil {
		t.Error("expected open log error (target is dir)")
	}

	// cmd.Start error (nonexistent binary)
	getDaemonLogPathFn = getDaemonLogPath // restore sensible
	osExecutable = func() (string, error) { return "/fake", nil }
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("/this/binary/does/not/exist/12345")
	}
	if err := startDaemonInBackground(); err == nil {
		t.Error("expected start error")
	}
}

func TestRunStart_Errors(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	tmpHome := t.TempDir()
	osUserHomeDir = func() (string, error) { return tmpHome, nil }
	osExecutable = func() (string, error) { return "/fake", nil }
	execCommand = func(name string, arg ...string) *exec.Cmd { return exec.Command("true") }

	// config load error -> osExit(1) no-op + explicit return (see RunStart and cli.go osExit contract)
	configLoad = func() (*config.Config, string, error) { return nil, "", errForTest }
	RunStart()

	// start daemon error path
	resetTestOverrides(t)
	osUserHomeDir = func() (string, error) { return tmpHome, nil }
	osExecutable = func() (string, error) { return "/fake", nil }
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("/no/such/exe")
	}
	RunStart()
}
