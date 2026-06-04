package util

import "os/exec"

// ResolveCommand returns an absolute path (via LookPath when possible) for the
// given command name. This is defense-in-depth hardening for the small set of
// external tools the project invokes directly:
//
//   - "bw" (Pillar 1 Bitwarden collector)
//   - pbpaste/pbcopy, osascript, afplay (Pillar 5 clipboard primitives + monitor)
//   - bare names under pillar4.commands (when the caller has decided the name
//     is not an explicit relative or absolute path)
//
// On success the result is an absolute path (reducing PATH hijacking surface).
// On failure (or if LookPath is not applicable) it returns the name unchanged
// so exec.Command will still search PATH (or fail with a clear error at exec time).
//
// Callers dealing with user-configured commands (Pillar 4) that may legitimately
// be relative (./foo, ../bar) or absolute must apply their own heuristic before
// calling ResolveCommand; see internal/cli/env.go. For our hard-coded tool names
// we always attempt resolution.
func ResolveCommand(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}
