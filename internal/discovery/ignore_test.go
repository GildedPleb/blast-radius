package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreMatcher(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("node_modules\n*.log\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})
	if !m.ShouldIgnore(filepath.Join(dir, "node_modules")) {
		t.Error("should ignore node_modules")
	}
	if !m.ShouldIgnore(filepath.Join(dir, "foo.log")) {
		t.Error("should ignore *.log")
	}
	if m.ShouldIgnore(filepath.Join(dir, "keep.txt")) {
		t.Error("should not ignore keep.txt")
	}
}