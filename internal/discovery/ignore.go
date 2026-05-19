package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreMatcher handles gitignore-style ignore patterns.
// This is a simplified but practical implementation for Phase 1.
type IgnoreMatcher struct {
	patterns []string
}

// NewIgnoreMatcher creates a matcher and loads patterns from the configured ignore files.
func NewIgnoreMatcher(root string, ignoreFiles []string) *IgnoreMatcher {
	m := &IgnoreMatcher{}

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
		m.patterns = append(m.patterns, line)
	}
}

// ShouldIgnore returns true if the given path should be ignored.
func (m *IgnoreMatcher) ShouldIgnore(path string) bool {
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	for _, pattern := range m.patterns {
		// Simple matching rules
		if pattern == base {
			return true
		}
		if strings.HasSuffix(pattern, "/") && strings.HasSuffix(dir, strings.TrimSuffix(pattern, "/")) {
			return true
		}
		if strings.Contains(pattern, "*") {
			matched, _ := filepath.Match(pattern, base)
			if matched {
				return true
			}
		}
		if strings.HasPrefix(pattern, "/") && strings.HasSuffix(path, pattern) {
			return true
		}
	}
	return false
}