package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreMatcher(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("# comment line\nnode_modules\n\n*.log\n# trailing comment\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore", ".nonexistentignore"})
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

func TestIgnoreMatcher_Negation(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("*.log\n!important.log\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	if !m.ShouldIgnore(filepath.Join(dir, "normal.log")) {
		t.Error("should ignore normal .log files")
	}
	if m.ShouldIgnore(filepath.Join(dir, "important.log")) {
		t.Error("negation should keep important.log")
	}
	if m.ShouldIgnore(filepath.Join(dir, "keep.txt")) {
		t.Error("should not ignore unrelated files")
	}
}

func TestIgnoreMatcher_DirectoryOnly(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("dist/\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	distDir := filepath.Join(dir, "dist")
	_ = os.Mkdir(distDir, 0755)
	distFile := filepath.Join(distDir, "something.txt")
	_ = os.WriteFile(distFile, []byte("x"), 0644)

	// Directory itself should be ignored
	if !m.ShouldIgnore(distDir) {
		t.Error("should ignore dist/ directory")
	}
	// Files inside should also be ignored because the dir rule applies during walk
	// (our implementation checks the concrete path)
	if !m.ShouldIgnore(distFile) {
		t.Error("files inside ignored dir should also be skipped")
	}
}

func TestIgnoreMatcher_Anchored(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("/Makefile\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	if !m.ShouldIgnore(filepath.Join(dir, "Makefile")) {
		t.Error("anchored /Makefile should match at root")
	}
	// Subdir Makefile should NOT match anchored pattern
	subMakefile := filepath.Join(dir, "subdir", "Makefile")
	_ = os.MkdirAll(filepath.Dir(subMakefile), 0755)
	_ = os.WriteFile(subMakefile, []byte("x"), 0644)
	if m.ShouldIgnore(subMakefile) {
		t.Error("anchored pattern should not match Makefile in subdirectory")
	}
}

func TestIgnoreMatcher_DoubleStar(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("**/node_modules\n**/*.tmp\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	deepNode := filepath.Join(dir, "a", "b", "c", "node_modules")
	_ = os.MkdirAll(deepNode, 0755)
	if !m.ShouldIgnore(deepNode) {
		t.Error("**/node_modules should match deep node_modules")
	}

	deepTmp := filepath.Join(dir, "foo", "bar", "baz.tmp")
	_ = os.MkdirAll(filepath.Dir(deepTmp), 0755)
	_ = os.WriteFile(deepTmp, []byte("x"), 0644)
	if !m.ShouldIgnore(deepTmp) {
		t.Error("**/*.tmp should match deep .tmp files")
	}
}

func TestIgnoreMatcher_NegationOrder(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	// Classic pattern: ignore everything, then un-ignore specific files
	os.WriteFile(gitignore, []byte("*.log\n!important.log\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	if !m.ShouldIgnore(filepath.Join(dir, "normal.log")) {
		t.Error("*.log should ignore normal.log")
	}
	if m.ShouldIgnore(filepath.Join(dir, "important.log")) {
		t.Error("!important.log (later rule) should keep the file")
	}
}

func TestIgnoreMatcher_MultipleIgnoreFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.bak\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".blastradiusignore"), []byte("!keep.bak\nsecrets/\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore", ".blastradiusignore"})

	if !m.ShouldIgnore(filepath.Join(dir, "foo.bak")) {
		t.Error("should still ignore .bak from first file")
	}
	if m.ShouldIgnore(filepath.Join(dir, "keep.bak")) {
		t.Error("negation in second file should protect keep.bak")
	}
	sec := filepath.Join(dir, "secrets", "password.txt")
	_ = os.MkdirAll(filepath.Dir(sec), 0755)
	_ = os.WriteFile(sec, []byte("x"), 0644)
	if !m.ShouldIgnore(sec) {
		t.Error("secrets/ from second ignore file should be ignored")
	}
}

func TestIgnoreMatcher_ComplexPatterns(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("build/\n!build/important.txt\n*.min.js\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	buildDir := filepath.Join(dir, "build")
	_ = os.Mkdir(buildDir, 0755)
	if !m.ShouldIgnore(buildDir) {
		t.Error("build/ dir should be ignored")
	}

	important := filepath.Join(buildDir, "important.txt")
	_ = os.WriteFile(important, []byte("x"), 0644)
	if m.ShouldIgnore(important) {
		t.Error("negated file inside ignored dir should be kept (last match wins)")
	}

	minjs := filepath.Join(dir, "app.min.js")
	_ = os.WriteFile(minjs, []byte("x"), 0644)
	if !m.ShouldIgnore(minjs) {
		t.Error("*.min.js should be ignored")
	}
}

func TestIgnoreMatcher_FallbackSimpleMatch(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	_ = os.WriteFile(gitignore, []byte("secret.txt\n*.tmp\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	// Relative (non-absolute) path forces filepath.Rel error path (baseSlashed != targSlashed).
	// This is the only call site of the old simpleMatch fallback.
	if !m.ShouldIgnore("secret.txt") {
		t.Error("fallback simpleMatch should ignore exact 'secret.txt'")
	}
	if !m.ShouldIgnore("foo.tmp") {
		t.Error("fallback simpleMatch should handle *.tmp glob")
	}
	if m.ShouldIgnore("keep.txt") {
		t.Error("unrelated relative name should not be ignored")
	}
}

func TestIgnoreMatcher_EmptyRoot(t *testing.T) {
	m := &IgnoreMatcher{root: ""}
	if m.ShouldIgnore("/foo/bar") {
		t.Error("ShouldIgnore should return false when root is empty")
	}
	if m.ShouldIgnore("relative.txt") {
		t.Error("ShouldIgnore should return false when root is empty (relative path)")
	}
}

func TestIgnoreMatcher_UnanchoredPathPattern(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	os.WriteFile(gitignore, []byte("foo/bar\n"), 0644) // unanchored, contains "/"

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	// Deep directory whose relative path ends exactly with the pattern
	deepDir := filepath.Join(dir, "src", "packages", "foo", "bar")
	_ = os.MkdirAll(deepDir, 0755)

	if !m.ShouldIgnore(deepDir) {
		t.Error("unanchored 'foo/bar' should match deep foo/bar via suffix loop in matchesRule")
	}
}

func TestMatchWithWildcards_EmptyPattern(t *testing.T) {
	if matchWithWildcards("", "anything") {
		t.Error("empty pattern should return false")
	}
	if matchWithWildcards("", "") {
		t.Error("empty pattern should return false even against empty name")
	}
}

func TestIgnoreMatcher_TrailingStarInDoubleStar(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	// The literal segment after splitting on ** is "/*" → ends with *
	os.WriteFile(gitignore, []byte("**/*\n"), 0644)

	m := NewIgnoreMatcher(dir, []string{".gitignore"})

	deep := filepath.Join(dir, "a", "b", "c", "file.txt")
	_ = os.MkdirAll(filepath.Dir(deep), 0755)
	_ = os.WriteFile(deep, []byte("x"), 0644)

	if !m.ShouldIgnore(deep) {
		t.Error("**/* should hit the trailing * early return in matchAt")
	}
}
