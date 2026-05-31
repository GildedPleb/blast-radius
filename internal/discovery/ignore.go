package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ignoreRule represents one (possibly negated) pattern from an ignore file.
type ignoreRule struct {
	pattern string // pattern with leading ! and trailing / stripped
	negated bool
	dirOnly bool // pattern ended with /
}

// IgnoreMatcher handles gitignore-style ignore patterns with support for
// negation (!), **, anchored paths, and directory-only rules.
//
// This is a significantly improved implementation for Phase 2 while
// preserving the exact public API so existing callers (scanner + residue)
// continue to work unchanged.
type IgnoreMatcher struct {
	root  string
	rules []ignoreRule
}

// NewIgnoreMatcher creates a matcher and loads patterns from the configured ignore files
// (typically .gitignore and .blastradiusignore).
func NewIgnoreMatcher(root string, ignoreFiles []string) *IgnoreMatcher {
	absRoot, _ := filepath.Abs(root)
	m := &IgnoreMatcher{
		root:  absRoot,
		rules: make([]ignoreRule, 0),
	}

	for _, name := range ignoreFiles {
		path := filepath.Join(root, name)
		m.loadPatterns(path)
	}

	return m
}

func (m *IgnoreMatcher) loadPatterns(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule := parseIgnoreRule(line)
		m.rules = append(m.rules, rule)
	}
}

func parseIgnoreRule(line string) ignoreRule {
	negated := false
	if strings.HasPrefix(line, "!") {
		negated = true
		line = strings.TrimPrefix(line, "!")
		line = strings.TrimSpace(line)
	}

	dirOnly := false
	if strings.HasSuffix(line, "/") {
		dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}

	return ignoreRule{
		pattern: line,
		negated: negated,
		dirOnly: dirOnly,
	}
}

// ShouldIgnore returns true if the given absolute path should be ignored
// according to the loaded patterns (respecting negation order).
func (m *IgnoreMatcher) ShouldIgnore(absPath string) bool {
	if m.root == "" {
		return false
	}

	rel, err := filepath.Rel(m.root, absPath)
	if err != nil {
		// If we can't make it relative, fall back to old base-name behavior for safety
		base := filepath.Base(absPath)
		for _, r := range m.rules {
			if !r.negated && simpleMatch(r.pattern, base) {
				return true
			}
		}
		return false
	}

	// Normalize to forward slashes for matching (gitignore style)
	rel = filepath.ToSlash(rel)

	// Determine if this path is (or refers to) a directory.
	// Best-effort; if Stat fails we treat it as non-dir for dirOnly patterns.
	isDir := false
	if info, err := os.Stat(absPath); err == nil {
		isDir = info.IsDir()
	}

	// Gitignore semantics: later rules override earlier ones.
	// We track the last decision that applied.
	ignored := false
	for _, rule := range m.rules {
		if rule.dirOnly && !isDir {
			// For dir-only rules, also check if any ancestor directory would match
			// so that files inside ignored directories are also treated as ignored.
			if !m.anyAncestorMatchesDirRule(rule, rel) {
				continue
			}
		}
		if m.matchesRule(rule, rel) {
			ignored = !rule.negated
		}
	}
	return ignored
}

// anyAncestorMatchesDirRule checks whether a dirOnly rule would have matched
// any parent directory of rel.
func (m *IgnoreMatcher) anyAncestorMatchesDirRule(rule ignoreRule, rel string) bool {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		ancestor := strings.Join(parts[:i], "/")
		if matchWithWildcards(rule.pattern, ancestor) || matchWithWildcards(rule.pattern, parts[i-1]) {
			return true
		}
	}
	return false
}

// matchesRule returns whether this rule's pattern matches the relative path.
func (m *IgnoreMatcher) matchesRule(rule ignoreRule, rel string) bool {
	pat := rule.pattern

	// Anchored at root of the ignore file (leading /)
	anchored := strings.HasPrefix(pat, "/")
	if anchored {
		pat = strings.TrimPrefix(pat, "/")
	}

	// Check direct match first
	if matchWithWildcards(pat, rel) {
		if anchored {
			return strings.HasPrefix(rel, pat) || strings.HasPrefix(rel+"/", pat+"/")
		}
		return true
	}

	// Unanchored: try matching against any suffix of the path (standard behavior)
	if !anchored && strings.Contains(rel, "/") {
		parts := strings.Split(rel, "/")
		for i := range parts {
			suffix := strings.Join(parts[i:], "/")
			if matchWithWildcards(pat, suffix) {
				return true
			}
		}
	}

	// Also allow the pattern to match any individual path segment (helps "dist/" rules catch children)
	if !anchored {
		segments := strings.Split(rel, "/")
		for _, seg := range segments {
			if matchWithWildcards(pat, seg) {
				return true
			}
		}
	}

	return false
}

// matchWithWildcards provides improved matching over the old simple filepath.Match.
// Supports *, **, and basic cases.
func matchWithWildcards(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	if pattern == name {
		return true
	}

	// Handle ** (match any number of directories/components)
	if strings.Contains(pattern, "**") {
		// Replace ** with a very permissive segment matcher
		// Strategy: split on ** and require the literal parts to appear in order
		parts := strings.Split(pattern, "**")
		current := name
		for _, p := range parts {
			if p == "" {
				continue
			}
			// For each literal-ish part, find it with * support
			idx := findWithWildcard(current, p)
			if idx == -1 {
				return false
			}
			current = current[idx+len(p):]
		}
		return true
	}

	// No ** — use Go's filepath.Match (good for * and ?)
	matched, err := filepath.Match(pattern, name)
	if err == nil && matched {
		return true
	}

	// Also try matching against the base name for common cases like "*.log"
	base := filepath.Base(name)
	if base != name {
		matched, _ = filepath.Match(pattern, base)
		if matched {
			return true
		}
	}

	return false
}

// findWithWildcard returns the index in s where the pattern p (which may contain *) starts,
// or -1 if not found. Very small implementation for ** support.
func findWithWildcard(s, p string) int {
	if !strings.Contains(p, "*") {
		return strings.Index(s, p)
	}
	// Simple left-to-right search allowing * to eat characters
	for i := 0; i <= len(s)-len(p)+1; i++ { // rough bound
		if matchAt(s[i:], p) {
			return i
		}
	}
	return -1
}

// matchAt checks if pattern matches s starting at position 0 (with * support)
func matchAt(s, pattern string) bool {
	pi, si := 0, 0
	for pi < len(pattern) {
		if pattern[pi] == '*' {
			pi++
			if pi == len(pattern) {
				return true // trailing * matches rest
			}
			// * consumes until next literal matches
			nextLit := pattern[pi:]
			for si < len(s) {
				if matchAt(s[si:], nextLit) {
					return true
				}
				si++
			}
			return false
		}
		if si >= len(s) || pattern[pi] != s[si] {
			return false
		}
		pi++
		si++
	}
	return si == len(s)
}

// simpleMatch is the old basic logic kept for fallback paths.
func simpleMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.Contains(pattern, "*") {
		m, _ := filepath.Match(pattern, name)
		return m
	}
	return false
}
