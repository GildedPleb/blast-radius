package daemon

import (
	"errors"
	"strings"
	"testing"
)

func TestSocketPath_Default(t *testing.T) {
	path := SocketPath()
	if path == "" {
		t.Error("SocketPath() returned empty string")
	}
	if !strings.Contains(path, "blastradius.sock") {
		t.Errorf("SocketPath() = %q, expected to contain blastradius.sock", path)
	}
}

func TestSocketPath_Override(t *testing.T) {
	orig := SocketPathFn
	defer func() { SocketPathFn = orig }()

	custom := "/tmp/custom-test-socket.sock"
	SocketPathFn = func() string { return custom }

	if got := SocketPath(); got != custom {
		t.Errorf("SocketPath() after override = %q, want %q", got, custom)
	}
}

// TestDefaultSocketPath_ErrorPath hits the rare fallback in defaultSocketPath
// (the 0-block at the userHomeDir err || empty check) using the internal seam.
func TestDefaultSocketPath_ErrorPath(t *testing.T) {
	orig := userHomeDir
	defer func() { userHomeDir = orig }()
	userHomeDir = func() (string, error) { return "", errors.New("no home for test") }

	if got := defaultSocketPath(); got != "/tmp/blastradius.sock" {
		t.Errorf("defaultSocketPath on home err = %q, want /tmp fallback", got)
	}
}
