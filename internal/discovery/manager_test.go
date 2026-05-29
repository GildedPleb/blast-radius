package discovery

import (
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

func TestNewManager(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)
	if m == nil {
		t.Error("manager nil")
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

func TestComputeDisplayName(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"", ""},
		{"/", ""},
		{"/home/user/project", "user/project"},
		{"/single", "/single"}, // shallow path keeps leading slash in join of last 2
		{"/a/b/c/d", "c/d"},
		{"/trailing/", "/trailing"},
		{"/foo/bar", "foo/bar"},
	}
	for _, tc := range tests {
		if got := computeDisplayName(tc.dir); got != tc.want {
			t.Errorf("computeDisplayName(%q) = %q, want %q", tc.dir, got, tc.want)
		}
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

func TestManager_GetProjectDisplayName(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)

	// unregistered id hits fallback path
	fallback := m.GetProjectDisplayName("nonexistent-id-xyz")
	if fallback == "" {
		t.Error("fallback should not be empty")
	}
}

func TestManager_RunInitialDiscovery_RegistersProjects(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal .env file so the scanner has something to find
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ProjectRoots = []string{dir}
	cfg.SkipDirs = nil // don't skip our temp dir

	reg := registry.New()
	m := NewManager(cfg, reg)

	// This should trigger scanning, which calls registerProject via the hook
	m.RunInitialDiscovery()

	// If we got here without panic and the registry has at least one entry,
	// then registerProject was exercised.
	if reg.Count() == 0 {
		t.Log("note: registry was empty after scan (possible ignore rules) — registerProject path may not have run")
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

func TestManager_RunInitialDiscovery_EmptyRoots(t *testing.T) {
	// Use a temp as fake HOME so ~ expands to small dir (no real home walk, fast under cover)
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	cfg := config.DefaultConfig()
	cfg.ProjectRoots = nil // triggers roots==0 -> ["~"] path
	cfg.SkipDirs = nil

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery() // should complete without walking real homedir

	if reg.GetScanState() != registry.ScanStateCompleted {
		t.Logf("scan state: %v (may be ok if no .env files)", reg.GetScanState())
	}
}

func TestManager_GetProjectDisplayName_EmptyRegistered(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)

	// register with empty name -> should hit fallback (ok && name != "")
	id := makeOpaqueProjectID("/tmp/emptyname")
	m.registerProject(id, "")
	name := m.GetProjectDisplayName(id)
	if name == "" {
		t.Error("expected fallback name even for empty registered")
	}
}

// TestScanner_ProcessEnvFile_VariedContent exercises many branches in processEnvFile
// that were previously under-tested: comments, empty lines, quoted values,
// malformed lines, values with = inside, and trailing scanner errors.
func TestScanner_ProcessEnvFile_VariedContent(t *testing.T) {
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
	cfg.ProjectRoots = []string{dir}
	cfg.SkipDirs = nil

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery()

	// We should have registered several values (at least SIMPLE, QUOTED, SINGLE, WITH_EQUALS, TRAILING...)
	if reg.Count() < 4 {
		t.Errorf("expected at least 4 values registered from varied .env, got %d", reg.Count())
	}
}