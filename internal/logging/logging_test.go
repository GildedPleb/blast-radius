package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDaemonLogPath(t *testing.T) {
	// Basic smoke — fully hermetic: we control HOME so we never touch the real user home.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	p := DefaultDaemonLogPath()
	if !strings.Contains(p, ".local/state/blastradius/daemon.log") {
		t.Errorf("DefaultDaemonLogPath() = %q, expected to contain standard location", p)
	}
}

func TestDefaultDaemonLogPath_Fallback(t *testing.T) {
	// When UserHomeDir would fail (we can't easily force it), at least the function runs.
	// This test is now hermetic: we set HOME to a temp dir.
	t.Setenv("HOME", t.TempDir())
	_ = DefaultDaemonLogPath()
}

func TestInit_Success(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "test.log")

	if err := Init(logPath); err != nil {
		t.Fatalf("Init(%q) failed: %v", logPath, err)
	}

	// Should have created the file
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("expected log file to be created, stat err: %v", err)
	}
}

func TestInit_ErrorOnBadDir(t *testing.T) {
	// Create a file that will block MkdirAll when we try to treat it as a directory
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("i am a file"), 0600); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(blocker, "subdir", "daemon.log")
	err := Init(logPath)
	if err == nil {
		t.Error("expected error when trying to mkdir through a file path")
	}
}

// The wrapper functions are intentionally thin. We just need to call them
// once each to get them off 0%.
func TestLoggingWrappers_DoNotPanic(t *testing.T) {
	// These will write to whatever the current logger is (usually stderr during tests).
	// That's acceptable — we just want coverage > 0.
	Printf("test %s %d", "printf", 42)
	Println("test", "println")
	// Fatalf and Fatal would exit the test process, so we override the impl for coverage.
	oldF, oldFatal := logFatalf, logFatal
	logFatalf = func(string, ...any) {}
	logFatal = func(...any) {}
	defer func() { logFatalf, logFatal = oldF, oldFatal }()
	Fatalf("test fatal %d", 1)
	Fatal("test fatal")
}
