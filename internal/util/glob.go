package util

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandPath expands ~ and ~/... to the user's home directory.
// It is the canonical implementation used for ~ expansion by history root
// discovery, explicit history_files, Pillar 1/2 pattern handling, and other
// config-driven paths that accept user-supplied paths.
func ExpandPath(p string) string {
	if p == "~" || p == "~/" {
		if h := os.Getenv("HOME"); h != "" {
			return h
		}
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if h := os.Getenv("HOME"); h != "" {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// MatchesGlobPattern returns true if name matches the given glob-style pattern.
// It supports the pragmatic forms used throughout the codebase:
//
//   - exact match
//   - prefix*          (e.g. "AWS_*")
//   - *suffix          (e.g. "*_NONSECRET")
//   - prefix*suffix    (single internal *)
//   - ** (any number of path components) and **/foo patterns
//   - multiple * via filepath.Match fallback after **/ stripping
//
// This is the single source of truth for env_file_patterns (Pillar 1) and
// the files[] patterns under pillar2.dirs[].
func MatchesGlobPattern(name, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == name {
		return true
	}

	// Normalize: strip leading **/ or ** so that patterns like
	// "**/*_backup*" or "**/*.bak" work when matching against a basename
	// or relative path segment (common real-world expectation).
	clean := strings.TrimPrefix(pattern, "**/")
	clean = strings.TrimPrefix(clean, "**")

	// Direct match after stripping
	if clean == name {
		return true
	}

	// filepath.Match handles * and ? well
	if matched, _ := filepath.Match(clean, name); matched {
		return true
	}

	// Try against base name too (e.g. pattern "*.log" against "dir/foo.log")
	if base := filepath.Base(name); base != name {
		if matched, _ := filepath.Match(clean, base); matched {
			return true
		}
	}

	// Pragmatic prefix/suffix fallbacks (handles cases where filepath.Match
	// is too strict on certain characters).
	if strings.HasSuffix(clean, "*") {
		prefix := strings.TrimSuffix(clean, "*")
		if prefix != "" && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	if strings.HasPrefix(clean, "*") {
		suffix := strings.TrimPrefix(clean, "*")
		if suffix != "" && strings.HasSuffix(name, suffix) {
			return true
		}
	}

	// One internal wildcard (prefix*suffix) after stripping
	if strings.Count(clean, "*") == 1 {
		parts := strings.Split(clean, "*")
		if len(parts) == 2 {
			pre, suf := parts[0], parts[1]
			if (pre == "" || strings.HasPrefix(name, pre)) &&
				(suf == "" || strings.HasSuffix(name, suf)) {
				return true
			}
		}
	}

	return false
}

// MatchesAnyGlobPattern returns true if name matches any of the patterns.
func MatchesAnyGlobPattern(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if MatchesGlobPattern(name, p) {
			return true
		}
	}
	return false
}
