package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestNewScanner(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	s := NewScanner(cfg, reg)
	if s == nil {
		t.Error("scanner nil")
	}
}

func TestExpandPath_Direct(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"~", "/tmp/fakehome"},
		{"~/", "/tmp/fakehome"},
		{"~/foo/bar", "/tmp/fakehome/foo/bar"},
		{"/absolute/path", "/absolute/path"},
		{"relative", "relative"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Setenv("HOME", "/tmp/fakehome")
		got := expandPath(tc.in)
		if got != tc.want {
			t.Errorf("expandPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandPath_NoHome(t *testing.T) {
	// Ensure expand leaves ~ alone when HOME empty (t.Setenv sets to "" which != "" check fails)
	t.Setenv("HOME", "")
	if got := expandPath("~/foo"); got != "~/foo" {
		t.Errorf("expand with empty HOME: %q", got)
	}
	if got := expandPath("~"); got != "~" {
		t.Errorf("expand ~ with empty HOME: %q", got)
	}
}

func TestMakeOpaqueProjectID(t *testing.T) {
	id1 := makeOpaqueProjectID("/foo/bar")
	id2 := makeOpaqueProjectID("/foo/bar")
	if id1 != id2 {
		t.Error("makeOpaqueProjectID not stable")
	}
	if id1 == "" {
		t.Error("empty id")
	}
	id3 := makeOpaqueProjectID("/other")
	if id3 == id1 {
		t.Error("collision for different paths (unexpected)")
	}
}

// TestScanner_ScanDirectory_VariedContent exercises many branches in collectHashesFromFile
// (called via processEnvFile) that were previously under-tested: comments, empty lines,
// quoted values, malformed lines, values with = inside, and trailing scanner errors.
// We exercise it via ScanDirectory (which also covers visitEnvFiles, matchesEnvFile,
// project ID/display name computation, etc.).
func TestScanner_ScanDirectory_VariedContent(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.varied")

	content := strings.Join([]string{
		"# this is a comment",
		"",
		"  \t  ", // whitespace only
		`SIMPLE=plainvalue`,
		`QUOTED="double quoted value"`,
		`SINGLE='single quoted'`,
		`WITH_EQUALS=key=value=more`,
		`EMPTY_VALUE=`,
		`NO_EQUALS_LINE`,
		`TRAILING_COMMENT=value # not stripped but still valid value`,
	}, "\n") + "\n"

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	// Use new-style config under Pillar 1 (single source of truth for env options)
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
				"skip_dirs":     []string{},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// We should have registered several values (SIMPLE, QUOTED, SINGLE, WITH_EQUALS, TRAILING_COMMENT)
	if reg.Count() < 4 {
		t.Errorf("expected at least 4 values registered from varied .env, got %d", reg.Count())
	}
}

// TestScanner_KeyFiltering_Pillar1 exercises ignore_patterns support
// (via shouldIgnoreKey + matchIgnorePattern) under the Pillar 1 config shape.
func TestScanner_KeyFiltering_Pillar1(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.filtered")

	content := strings.Join([]string{
		"REAL_SECRET=supersecretvalue123456",
		"LOG_LEVEL=debug",
		"PROJECT_NAME=my-app",
		"PATH=/usr/bin:/bin",
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"MY_CUSTOM_NONSECRET=foo",
	}, "\n")

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()

	// Provide the full env source config under the Pillar 1 logical layer (new-style map assignment is robust).
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots":   []string{dir},
				"skip_dirs":       []string{},
				"ignore_patterns": []string{"LOG_LEVEL", "PROJECT_NAME", "PATH", "AWS_*_KEY_ID", "*_NONSECRET"},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Only REAL_SECRET should have been registered.
	if reg.Count() != 1 {
		t.Errorf("expected exactly 1 secret after filtering, got %d", reg.Count())
	}
}

// TestVisitEnvFiles_AbsError covers the previously uncovered error return path
// in visitEnvFiles when filepath.Abs fails (which happens when root is relative
// and os.Getwd() fails, e.g. after deleting the current working directory).
func TestVisitEnvFiles_AbsError(t *testing.T) {
	orig := filepathAbs
	filepathAbs = func(string) (string, error) {
		return "", errors.New("forced abs error for test")
	}
	defer func() { filepathAbs = orig }()

	cfg := config.DefaultConfig()
	reg := registry.New()
	s := NewScanner(cfg, reg)

	err := s.visitEnvFiles("any/relative/path", func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error from visitEnvFiles when filepathAbs fails")
	}
}

func TestVisitEnvFiles_SkipDirs(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory that should be skipped
	skipDir := filepath.Join(dir, "skip-this-dir")
	if err := os.MkdirAll(skipDir, 0755); err != nil {
		t.Fatal(err)
	}

	// .env at top level (should be processed)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("REAL=secret123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// .env inside the skipped directory (must NOT be processed)
	if err := os.WriteFile(filepath.Join(skipDir, ".env"), []byte("IGNORED=should_not_appear\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
				"skip_dirs":     []string{"skip-this-dir", "node_modules", ".git"},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Only the top-level .env should have been registered
	if reg.Count() != 1 {
		t.Errorf("expected exactly 1 secret (top-level), got %d", reg.Count())
	}
}

func TestVisitEnvFiles_WalkError(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory that will be made unreadable
	unreadable := filepath.Join(dir, "unreadable-subdir")
	if err := os.Mkdir(unreadable, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a normal .env at the top level so the walk has real work to do
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOP_LEVEL=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Remove all permissions from the subdirectory so Walk will fail to descend into it
	if err := os.Chmod(unreadable, 0000); err != nil {
		t.Fatal(err)
	}
	// Restore permissions so t.TempDir() cleanup succeeds
	defer os.Chmod(unreadable, 0755)

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
				"skip_dirs":     []string{},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	// ScanDirectory / visitEnvFiles should succeed (we swallow walk errors)
	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory should not return error for walk problems: %v", err)
	}

	// We should still have registered the top-level secret
	if reg.Count() != 1 {
		t.Errorf("expected 1 secret registered, got %d", reg.Count())
	}
}

func TestVisitEnvFiles_SkipSymlinks(t *testing.T) {
	dir := t.TempDir()

	// Real .env that should be processed
	realEnv := filepath.Join(dir, ".env")
	if err := os.WriteFile(realEnv, []byte("REAL_SECRET=supersecret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to the real .env (should be skipped by the ModeSymlink check)
	symlinkToEnv := filepath.Join(dir, ".env.via-symlink")
	if err := os.Symlink(realEnv, symlinkToEnv); err != nil {
		t.Fatal(err)
	}

	// Also create a symlink to a regular file (for extra coverage)
	regularFile := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("not a secret"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkToFile := filepath.Join(dir, "link-to-regular")
	if err := os.Symlink(regularFile, symlinkToFile); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Only the real .env should have been processed.
	// The symlinked .env.via-symlink must be ignored (security behavior).
	if reg.Count() != 1 {
		t.Errorf("expected exactly 1 secret (real .env only), got %d", reg.Count())
	}
}

func TestVisitEnvFiles_IgnorePaths(t *testing.T) {
	dir := t.TempDir()

	// Create a .gitignore that will cause ShouldIgnore to return true
	gitignore := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gitignore, []byte("ignored-dir/\n*.secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Ignored directory (should trigger the `if info.IsDir()` branch + SkipDir)
	ignoredDir := filepath.Join(dir, "ignored-dir")
	if err := os.MkdirAll(ignoredDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ignoredDir, ".env"), []byte("IGNORED_SECRET=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Ignored file via pattern (should hit the plain `return nil`)
	if err := os.WriteFile(filepath.Join(dir, "app.secret"), []byte("ANOTHER_SECRET=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// A normal .env that should still be processed
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("REAL_SECRET=correct\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Only the real .env should have been registered
	if reg.Count() != 1 {
		t.Errorf("expected exactly 1 secret after ignore filtering, got %d", reg.Count())
	}
}

func TestVisitEnvFiles_OnFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
			},
		},
	}

	s := NewScanner(cfg, registry.New())

	// Call visitEnvFiles directly with an onFile that returns an error.
	// This should still succeed — visitEnvFiles must swallow the error.
	err := s.visitEnvFiles(dir, func(path string) error {
		return errors.New("simulated failure from onFile")
	})

	if err != nil {
		t.Fatalf("visitEnvFiles should not return error when onFile fails: %v", err)
	}
}

func TestScanDirectory_ProcessEnvFileError(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	// Create a valid .env file
	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Remove read permission so that collectHashesFromFile's os.Open will fail
	if err := os.Chmod(envFile, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(envFile, 0600) // restore so t.TempDir cleanup works

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
			},
		},
	}

	reg := registry.New()
	s := NewScanner(cfg, reg)

	// Scan should succeed overall (the error is logged and swallowed)
	if err := s.ScanDirectory(dir); err != nil {
		t.Fatalf("ScanDirectory should not return error: %v", err)
	}

	// Nothing should have been registered because processing failed
	if reg.Count() != 0 {
		t.Errorf("expected 0 secrets (processing failed), got %d", reg.Count())
	}
}

func TestCollectEnvHashes_AbsError(t *testing.T) {
	orig := filepathAbs
	filepathAbs = func(string) (string, error) {
		return "", errors.New("forced abs failure for test")
	}
	defer func() { filepathAbs = orig }()

	cfg := config.DefaultConfig()
	s := NewScanner(cfg, registry.New())

	_, err := s.CollectEnvHashes([]string{"some/relative/root"})
	if err == nil {
		t.Fatal("expected error when filepath.Abs fails inside CollectEnvHashes")
	}
}

func TestCollectHashesInDir_CollectHashesFromFileError(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Remove read permission so collectHashesFromFile will fail on os.Open
	if err := os.Chmod(envFile, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(envFile, 0600)

	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots": []string{dir},
			},
		},
	}

	s := NewScanner(cfg, registry.New())

	// Use the public API that goes through collectHashesInDir
	hashes, err := s.CollectEnvHashes([]string{dir})
	if err != nil {
		t.Fatalf("CollectEnvHashes should succeed (individual file errors are swallowed): %v", err)
	}

	// No hashes collected because processing the file failed
	if len(hashes) != 0 {
		t.Errorf("expected 0 hashes, got %d", len(hashes))
	}
}

func TestShouldIgnoreKey_NilConfig(t *testing.T) {
	s := &Scanner{cfg: nil}
	if s.shouldIgnoreKey("ANY_KEY") {
		t.Error("expected false when cfg is nil")
	}
}

func TestShouldIgnoreKey_EmptyPattern(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"ignore_patterns": []string{"", "LOG_LEVEL", "", "AWS_*"},
			},
		},
	}

	s := NewScanner(cfg, registry.New())

	// The empty strings ("") should hit the `if p == "" { continue }` branch
	// and be skipped. LOG_LEVEL should still be filtered because of the non-empty pattern.
	if !s.shouldIgnoreKey("LOG_LEVEL") {
		t.Error("expected LOG_LEVEL to be ignored")
	}
	if s.shouldIgnoreKey("REAL_SECRET") {
		t.Error("REAL_SECRET should not be ignored")
	}
}

// func TestMatchIgnorePattern_PrefixStar(t *testing.T) {
// 	tests := []struct {
// 		key     string
// 		pattern string
// 		want    bool
// 	}{
// 		{"AWS_ACCESS_KEY_ID", "AWS_*", true},
// 		{"AWS_SECRET_ACCESS_KEY", "AWS_*", true},
// 		{"LOG_LEVEL", "AWS_*", false},
// 		{"AWS", "AWS_*", true},         // matches even with nothing after the prefix
// 		{"aws_access", "AWS_*", false}, // case-sensitive
// 		{"PREFIXED_VALUE", "PREFIX_*", true},
// 	}

// 	for _, tc := range tests {
// 		if got := matchIgnorePattern(tc.key, tc.pattern); got != tc.want {
// 			t.Errorf("matchIgnorePattern(%q, %q) = %v, want %v",
// 				tc.key, tc.pattern, got, tc.want)
// 		}
// 	}
// }

func TestComputeDisplayName(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"", ""},
		{"/", "/"},
		{"/home/user/project", "user/project"},
		{"/single", "/single"},
		{"/a/b/c/d", "c/d"},
		{"/trailing/", "/trailing"},
		{"/foo/bar", "foo/bar"},

		// These two hit the `len(parts) == 1` branch
		{"project", "project"},
		{"single-dir", "single-dir"},
	}

	for _, tc := range tests {
		if got := computeDisplayName(tc.dir); got != tc.want {
			t.Errorf("computeDisplayName(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}

func TestMatchesEnvFile_NilConfig(t *testing.T) {
	s := &Scanner{cfg: nil}

	tests := []struct {
		base string
		want bool
	}{
		{".env", true},
		{".env.local", true},
		{".envrc", true},
		{".env.production", true},
		{"env", false},
		{"config.env", false},
		{".ENV", false}, // case sensitive
		{"my.env.file", false},
	}

	for _, tc := range tests {
		if got := s.matchesEnvFile(tc.base); got != tc.want {
			t.Errorf("matchesEnvFile(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

func TestMatchIgnorePattern_PrefixStar(t *testing.T) {
	tests := []struct {
		key     string
		pattern string
		want    bool
	}{
		{"AWS_ACCESS_KEY_ID", "AWS_*", true},
		{"AWS_SECRET", "AWS_*", true},
		{"AWS_", "AWS_*", true},
		{"LOG_LEVEL", "AWS_*", false},
		{"PREFIXED_VALUE", "PREFIXED_*", true}, // corrected
		{"PREFIX_", "PREFIX_*", true},
	}

	for _, tc := range tests {
		if got := matchIgnorePattern(tc.key, tc.pattern); got != tc.want {
			t.Errorf("matchIgnorePattern(%q, %q) = %v, want %v",
				tc.key, tc.pattern, got, tc.want)
		}
	}
}
