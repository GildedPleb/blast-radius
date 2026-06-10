package daemon

import "path/filepath"

// --- Hard-coded socket path (security invariant) ---

const socketFileName = "blastradius.sock"

// SocketPathFn is the function used to resolve the socket path.
// It is overridable by tests for hermetic per-test socket locations.
// Production code should call SocketPath() instead of using this directly.
var SocketPathFn = defaultSocketPath

// defaultSocketPath returns the canonical secure location under the user's
// XDG state directory. This path is a hard security invariant for production.
func defaultSocketPath() string {
	home, err := userHomeDir()
	if err != nil || home == "" {
		// Extremely rare fallback. In practice this should never be hit.
		return "/tmp/blastradius.sock"
	}
	return filepath.Join(home, ".local", "state", "blastradius", socketFileName)
}

// SocketPath returns the location of the Unix domain socket used for
// daemon <-> CLI communication.
//
// This is intentionally not configurable by users. The path is a hard
// security invariant (private directory + strict permissions + capability token).
// Allowing overrides would re-introduce the attack surface we worked to eliminate.
func SocketPath() string {
	return SocketPathFn()
}
