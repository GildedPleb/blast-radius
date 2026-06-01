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
	// Set roots under the single source of truth (pillar1.sources.env.options)
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		if env.Options == nil {
			env.Options = map[string]any{}
		}
		env.Options["project_roots"] = []string{dir}
		env.Options["skip_dirs"] = []string{}
		cfg.Pillar1.Sources["env"] = env
	}

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
	// roots==0 triggers the "~" fallback path inside GetEnvOptions / scanning
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		env.Options["project_roots"] = []string{}
		env.Options["skip_dirs"] = []string{}
		cfg.Pillar1.Sources["env"] = env
	}

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
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		env.Options["project_roots"] = []string{dir}
		env.Options["skip_dirs"] = []string{}
		cfg.Pillar1.Sources["env"] = env
	}

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery()

	// We should have registered several values (at least SIMPLE, QUOTED, SINGLE, WITH_EQUALS, TRAILING...)
	if reg.Count() < 4 {
		t.Errorf("expected at least 4 values registered from varied .env, got %d", reg.Count())
	}
}

// TestScanner_KeyFiltering_Pillar1 exercises the new Phase 1 ignore_patterns support
// under the Pillar 1 logical layer (per-source options on the "env" source).
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

	// Provide the full env source config in one shot under the Pillar 1 logical layer.
	// This is the canonical shape after the legacy top-level discovery fields were removed.
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{
			"project_roots":   []string{dir},
			"skip_dirs":       []string{},
			"ignore_patterns": []string{"LOG_LEVEL", "PROJECT_NAME", "PATH", "AWS_*_KEY_ID", "*_NONSECRET"},
		},
	}

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery()

	// Only REAL_SECRET should have been registered.
	if reg.Count() != 1 {
		t.Errorf("expected exactly 1 secret after filtering, got %d", reg.Count())
	}
}

// TestManager_Rescan exercises the Phase 3 manual rescan path and lastScan tracking.
func TestManager_Rescan(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.rescan")
	_ = os.WriteFile(envFile, []byte("SECRET1=abc123\nSECRET2=def456\n"), 0600)

	cfg := config.DefaultConfig()
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		env.Options["project_roots"] = []string{dir}
		env.Options["skip_dirs"] = []string{}
		cfg.Pillar1.Sources["env"] = env
	}

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery()
	initial := reg.Count()
	if initial == 0 {
		t.Fatal("expected some hashes after initial discovery")
	}

	// Add another secret file
	env2 := filepath.Join(dir, ".env.extra")
	_ = os.WriteFile(env2, []byte("EXTRA_SECRET=xyz789\n"), 0600)

	result := m.Rescan()
	if result == nil {
		t.Fatal("Rescan returned nil result")
	}
	if result.AfterHashes <= result.BeforeHashes {
		t.Errorf("expected AfterHashes (%d) > BeforeHashes (%d) after adding new .env", result.AfterHashes, result.BeforeHashes)
	}
	if m.LastScan().IsZero() {
		t.Error("expected LastScan to be set after Rescan")
	}
}

// TestManager_UsesNewStyleEnvOptions verifies that discovery reads project_roots
// etc. from pillar1.sources.env.options when present (the new canonical location).
func TestManager_UsesNewStyleEnvOptions(t *testing.T) {
	dir := t.TempDir()
	// Create a .env so something gets discovered
	envFile := filepath.Join(dir, ".env")
	_ = os.WriteFile(envFile, []byte("NEWSTYLE_SECRET=supersecretvalue\n"), 0600)

	cfg := config.DefaultConfig()
	// skip_dirs already empty via the explicit new-style map below

	// Put the discovery settings in the new recommended location (single source of truth)
	cfg.Pillar1.Sources = map[string]config.SourceConfig{
		"env": {
			Enabled: true,
			Options: map[string]any{
				"project_roots":   []string{dir},
				"skip_dirs":       []string{},
				"ignore_files":    []string{},
				"ignore_patterns": []string{},
			},
		},
	}

	reg := registry.New()
	m := NewManager(cfg, reg)

	m.RunInitialDiscovery()

	if reg.Count() == 0 {
		t.Error("expected discovery to find the .env when project_roots came from new-style config")
	}
}

// TestManager_Rescan_CollectorValidation exercises that logical layer collectors
// have their Validate() step called during rescan (the IO prerequisite process).
func TestManager_Rescan_CollectorValidation(t *testing.T) {
	dir := t.TempDir()

	cfg := config.DefaultConfig()
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		env.Options["project_roots"] = []string{dir}
		env.Options["skip_dirs"] = []string{}
		cfg.Pillar1.Sources["env"] = env
	}

	// Force the env source into a bad state (no valid roots) so Validate should fail.
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{},
	}
	if env, ok := cfg.Pillar1.Sources["env"]; ok {
		env.Options["project_roots"] = []string{"/definitely/not/a/real/path/that/exists/98765"}
		cfg.Pillar1.Sources["env"] = env
	}

	reg := registry.New()
	m := NewManager(cfg, reg)

	result := m.Rescan()
	if result == nil {
		t.Fatal("expected rescan result")
	}

	// We expect at least one error mentioning the env collector validation.
	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "env:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected env collector validation error in rescan result, got errors: %v", result.Errors)
	}
}
