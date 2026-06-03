package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Pillar1.Sources) == 0 || len(cfg.Pillar4.Commands) == 0 {
		t.Error("defaults missing required pillar fields")
	}
	if len(cfg.Pillar2.Dirs) == 0 {
		t.Error("pillar2 defaults not populated")
	}
	if cfg.Pillar5.RedactTimeoutSeconds == 0 || cfg.Pillar5.FullClearTimeoutSeconds == 0 || cfg.Pillar5.RedactPlaceholder == "" {
		t.Error("pillar5 defaults not populated")
	}
	if cfg.Pillar5.RedactPlaceholder != "[REDACTED]" {
		t.Error("pillar5 redact_placeholder default should be [REDACTED]")
	}
	// Exercise normalizePillar5 (clamps negatives; sets placeholder default; called from Load after unmarshal)
	cfg2 := &Config{Pillar5: Pillar5Config{RedactTimeoutSeconds: -5, FullClearTimeoutSeconds: -1}}
	normalizePillar5(cfg2)
	if cfg2.Pillar5.RedactTimeoutSeconds != 0 || cfg2.Pillar5.FullClearTimeoutSeconds != 0 {
		t.Error("normalizePillar5 should clamp negative timeouts to 0 (disables tier)")
	}
	if cfg2.Pillar5.RedactPlaceholder != "[REDACTED]" {
		t.Error("normalizePillar5 should set default redact_placeholder")
	}
	// Explicit value is preserved (not overwritten)
	cfg3 := &Config{Pillar5: Pillar5Config{RedactPlaceholder: "***"}}
	normalizePillar5(cfg3)
	if cfg3.Pillar5.RedactPlaceholder != "***" {
		t.Error("normalizePillar5 must preserve explicit redact_placeholder")
	}
	// Pillar 1 logical sources (v1: env + bitwarden)
	if cfg.Pillar1.Sources == nil {
		t.Error("pillar1.sources map missing in defaults")
	}
	envSrc, ok := cfg.Pillar1.Sources["env"]
	if !ok || !envSrc.Enabled {
		t.Error("env source should be present and enabled by default")
	}
	bwSrc, ok := cfg.Pillar1.Sources["bitwarden"]
	if !ok || bwSrc.Enabled {
		t.Error("bitwarden source should be present and disabled by default")
	}
}

func TestLoad_NoFile(t *testing.T) {
	// Default behavior when no config exists — now fully hermetic.
	origHome := userHomeDir
	userHomeDir = func() (string, error) { return t.TempDir(), nil }
	defer func() { userHomeDir = origHome }()

	_, _, _ = Load()
}

func TestLoad_WithValidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `project_roots: ["/tmp"]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		if filepath.Base(name) == "config.yaml" {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}

	_, path, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// socket_path is no longer a user-configurable field (hard-coded security invariant)
	if path == "" {
		t.Error("expected configPath to be returned")
	}
}

func TestLoad_BadYAML(t *testing.T) {
	dir := t.TempDir()

	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		return []byte("socket_path: [not valid yaml"), nil
	}

	_, _, err := Load()
	if err == nil {
		t.Error("expected error on bad YAML")
	}
}

func TestLoad_PartialResidueConfig(t *testing.T) {
	dir := t.TempDir()

	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		return []byte("pillar2:\n  enabled: true\n"), nil
	}

	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// Should have filled in defaults for Dirs (the only supported shape).
	if len(cfg.Pillar2.Dirs) == 0 {
		t.Error("expected pillar2 defaults to be populated on partial config")
	}
}

func TestSave_HappyPath(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origMkdir := osMkdirAll
	origWrite := osWriteFile
	defer func() {
		userHomeDir = origHome
		osMkdirAll = origMkdir
		osWriteFile = origWrite
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osMkdirAll = func(path string, perm os.FileMode) error { return nil }
	osWriteFile = func(name string, data []byte, perm os.FileMode) error { return nil }

	cfg := DefaultConfig()
	err := cfg.Save()
	if err != nil {
		t.Errorf("Save failed: %v", err)
	}
}

// Additional fast edge cases via hooks.
func TestLoad_HomeDirFails(t *testing.T) {
	origHome := userHomeDir
	defer func() { userHomeDir = origHome }()

	userHomeDir = func() (string, error) { return "", errors.New("no home") }

	_, path, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// socket path is now a hard-coded invariant; no longer part of Config

	if path != "" {
		t.Error("expected empty path when home fails")
	}
}

func TestSave_HomeDirFails(t *testing.T) {
	origHome := userHomeDir
	defer func() { userHomeDir = origHome }()

	userHomeDir = func() (string, error) { return "", errors.New("no home") }

	cfg := DefaultConfig()
	err := cfg.Save()
	if err == nil {
		t.Error("expected error when home dir fails on Save")
	}
}

// Two more tiny hook-driven edges for Load/Save coverage.
func TestLoad_BadYAMLViaHook(t *testing.T) {
	dir := t.TempDir()
	origHome := userHomeDir
	origRead := osReadFile
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) { return []byte("not: valid: yaml: ["), nil }

	_, _, err := Load()
	if err == nil {
		t.Error("expected unmarshal error on bad YAML")
	}
}

func TestSave_WriteError(t *testing.T) {
	dir := t.TempDir()
	origHome := userHomeDir
	origMkdir := osMkdirAll
	origWrite := osWriteFile
	defer func() {
		userHomeDir = origHome
		osMkdirAll = origMkdir
		osWriteFile = origWrite
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osMkdirAll = func(path string, perm os.FileMode) error { return nil }
	osWriteFile = func(name string, data []byte, perm os.FileMode) error { return errors.New("disk full") }

	cfg := DefaultConfig()
	err := cfg.Save()
	if err == nil {
		t.Error("expected write error")
	}
}

func TestSave_ErrorPath(t *testing.T) {
	cfg := DefaultConfig()
	_ = cfg.Save() // socket path is no longer a field on Config
}

// Extra edges for Load coverage (other read err, socket defaulting, residue defaults fill).
func TestLoad_ReadOtherError(t *testing.T) {
	dir := t.TempDir()
	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrPermission // non-NotExist error
	}
	_, _, err := Load()
	if err == nil {
		t.Error("expected error on permission-like read failure")
	}
}

func TestLoad_ResidueDefaults(t *testing.T) {
	dir := t.TempDir()
	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	// yaml with pillar2 enabled:false + explicit empty dirs (triggers the fill block in Load,
	// which would otherwise be skipped because DefaultConfig pre-populates Dirs and unmarshal
	// of absent key leaves them).
	osReadFile = func(name string) ([]byte, error) {
		return []byte("pillar2:\n  enabled: false\n  dirs: []\n"), nil
	}
	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// socket path is a hard-coded invariant and no longer appears in user config

	if len(cfg.Pillar2.Dirs) == 0 {
		t.Error("expected pillar2 dirs filled from defaults")
	}
	if cfg.Pillar2.Enabled {
		t.Error("enabled should be false from yaml")
	}
}

func TestSave_MkdirError(t *testing.T) {
	dir := t.TempDir()
	origHome := userHomeDir
	origMkdir := osMkdirAll
	defer func() {
		userHomeDir = origHome
		osMkdirAll = origMkdir
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osMkdirAll = func(path string, perm os.FileMode) error { return errors.New("mkdir denied") }
	cfg := DefaultConfig()
	if err := cfg.Save(); err == nil {
		t.Error("expected mkdir error on Save")
	}
}

func TestSave_MarshalError(t *testing.T) {
	dir := t.TempDir()
	origHome := userHomeDir
	origMkdir := osMkdirAll
	origMarshal := yamlMarshal
	defer func() {
		userHomeDir = origHome
		osMkdirAll = origMkdir
		yamlMarshal = origMarshal
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osMkdirAll = func(path string, perm os.FileMode) error { return nil }
	yamlMarshal = func(v any) ([]byte, error) { return nil, errors.New("yaml is angry today") }

	cfg := DefaultConfig()
	if err := cfg.Save(); err == nil {
		t.Error("expected marshal error on Save")
	}
}

func TestSocketPath_Default(t *testing.T) {
	path := SocketPath()
	if path == "" {
		t.Error("SocketPath() returned empty string")
	}
	if !strings.Contains(path, "blastradius.sock") {
		t.Errorf("SocketPath() = %q, expected to contain blastradius.sock", path)
	}
}

func TestSocketPath_Override(t *testing.T) {
	orig := SocketPathFn
	defer func() { SocketPathFn = orig }()

	custom := "/tmp/custom-test-socket.sock"
	SocketPathFn = func() string { return custom }

	if got := SocketPath(); got != custom {
		t.Errorf("SocketPath() after override = %q, want %q", got, custom)
	}
}

func TestPillar1Sources_Normalization_And_Accessor(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// Partial config: user only enables bitwarden and supplies one ignore pattern for env
	content := `
pillar1:
  sources:
    bitwarden:
      enabled: true
    env:
      options:
        ignore_patterns: ["DEBUG*", "*_TEST"]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		if filepath.Base(name) == "config.yaml" {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}

	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Pillar1.Sources["bitwarden"].Enabled {
		t.Error("bitwarden should be enabled from partial yaml")
	}
	// When user supplies a partial env block, we respect the zero-value Enabled (false)
	// unless they explicitly set enabled: true. This is the intended "user intent" semantics.
	// (Full migration story will default env on when the new pillar1 block is completely absent.)
	if cfg.Pillar1.Sources["env"].Enabled {
		t.Error("env Enabled should be false when user supplied partial block without explicit enabled:true")
	}

	ignores := cfg.GetSourceIgnorePatterns("env")
	if len(ignores) != 2 || ignores[0] != "DEBUG*" {
		t.Errorf("expected normalized ignore_patterns for env, got %v", ignores)
	}

	// bitwarden should have empty list (not nil) after normalization
	bwIgnores := cfg.GetSourceIgnorePatterns("bitwarden")
	if bwIgnores == nil {
		t.Error("bitwarden ignore_patterns should be non-nil slice")
	}
}

// Legacy GetEnvOptions fallback tests were removed when the top-level
// project_roots / skip_dirs / ignore_files fields and migration logic were deleted.
// The single source of truth is now pillar1.sources.env.options (see GetEnvOptions).

func TestGetEnvOptions_NewStyleOnly(t *testing.T) {
	cfg := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"project_roots":   []string{"~/projects", "~/work"},
						"skip_dirs":       []string{"node_modules", ".git", "vendor"},
						"ignore_files":    []string{".gitignore", ".blastradiusignore"},
						"ignore_patterns": []string{"LOG_*", "*_SECRET"},
					},
				},
			},
		},
	}

	opts := cfg.GetEnvOptions()

	if len(opts.ProjectRoots) != 2 || opts.ProjectRoots[0] != "~/projects" {
		t.Errorf("ProjectRoots not taken from pillar1: %v", opts.ProjectRoots)
	}
	if len(opts.SkipDirs) != 3 || opts.SkipDirs[0] != "node_modules" {
		t.Errorf("SkipDirs not taken from pillar1: %v", opts.SkipDirs)
	}
	if len(opts.IgnoreFiles) != 2 || opts.IgnoreFiles[0] != ".gitignore" {
		t.Errorf("IgnoreFiles not taken from pillar1: %v", opts.IgnoreFiles)
	}
	if len(opts.IgnorePatterns) != 2 || opts.IgnorePatterns[0] != "LOG_*" {
		t.Errorf("IgnorePatterns not taken from pillar1: %v", opts.IgnorePatterns)
	}
}

func TestGetEnvOptions_Empty(t *testing.T) {
	cfg := &Config{}
	opts := cfg.GetEnvOptions()
	// Normalization guarantees non-nil slices
	if opts.ProjectRoots == nil || opts.SkipDirs == nil || opts.IgnoreFiles == nil || opts.IgnorePatterns == nil {
		t.Errorf("Expected non-nil slices for empty config, got %+v", opts)
	}
}

func TestGetSourceIgnorePatterns_NilAndEmpty(t *testing.T) {
	// nil receiver (early return)
	var c *Config
	if got := c.GetSourceIgnorePatterns("env"); len(got) != 0 {
		t.Errorf("nil.GetSourceIgnorePatterns = %v, want []", got)
	}
	if got := c.GetSourceIgnorePatterns("bitwarden"); len(got) != 0 {
		t.Errorf("nil.GetSourceIgnorePatterns(bw) = %v, want []", got)
	}

	// empty struct (Sources==nil path)
	empty := &Config{}
	if got := empty.GetSourceIgnorePatterns("env"); len(got) != 0 {
		t.Errorf("empty.GetSourceIgnorePatterns = %v, want []", got)
	}

	// source present but no Options (or Options nil)
	cfg := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"bitwarden": {Enabled: true /* Options nil */},
			},
		},
	}
	if got := cfg.GetSourceIgnorePatterns("bitwarden"); got == nil {
		t.Error("GetSourceIgnorePatterns for src with nil Options should be non-nil empty")
	}
	if got := cfg.GetSourceIgnorePatterns("missing-src"); len(got) != 0 {
		t.Errorf("missing src = %v, want []", got)
	}
}

func TestGetEnvOptions_NilReceiver(t *testing.T) {
	var c *Config
	opts := c.GetEnvOptions()
	if opts.ProjectRoots == nil || opts.IgnorePatterns == nil {
		t.Errorf("nil receiver GetEnvOptions should return non-nil slices, got %+v", opts)
	}
}

func TestNormalizePillar3(t *testing.T) {
	// nil config
	normalizePillar3(nil)

	// disabled + no mode → should default mode
	cfg := &Config{Pillar3: Pillar3Config{Enabled: false}}
	normalizePillar3(cfg)
	if cfg.Pillar3.Mode != "delete" {
		t.Errorf("disabled empty mode: got %q", cfg.Pillar3.Mode)
	}

	// enabled + invalid mode → reset to delete
	cfg = &Config{Pillar3: Pillar3Config{Enabled: true, Mode: "banana"}}
	normalizePillar3(cfg)
	if cfg.Pillar3.Mode != "delete" {
		t.Error("invalid mode should become delete")
	}

	// enabled + empty placeholder + nil HistoryFiles + nil HistoryRoots
	// (we no longer force non-nil; discovery + docs treat nil as "use $HOME only")
	cfg = &Config{Pillar3: Pillar3Config{Enabled: true, Mode: "redact"}}
	normalizePillar3(cfg)
	if cfg.Pillar3.RedactPlaceholder != "[REDACTED]" {
		t.Error("empty placeholder should be defaulted")
	}
	if cfg.Pillar3.HistoryFiles != nil {
		t.Error("HistoryFiles should remain nil (discovery treats nil/empty equivalently)")
	}
	if cfg.Pillar3.HistoryRoots != nil {
		t.Error("HistoryRoots should remain nil (discovery treats nil/empty equivalently)")
	}

	// fully valid config should be left alone (including HistoryRoots)
	cfg = &Config{Pillar3: Pillar3Config{
		Enabled:           true,
		Mode:              "redact",
		RedactPlaceholder: "***",
		HistoryFiles:      []string{"/custom/hist"},
		HistoryRoots:      []string{"/other/home"},
	}}
	normalizePillar3(cfg)
	if cfg.Pillar3.RedactPlaceholder != "***" || len(cfg.Pillar3.HistoryFiles) != 1 || len(cfg.Pillar3.HistoryRoots) != 1 {
		t.Error("valid config was mutated")
	}
}

// TestEffectiveRedactPlaceholder covers the helper extracted to dedupe P5/P3
// fallback logic (review nit 8). It is called from CLI scrub and daemon auto paths;
// we test it directly here so the config package's coverage profile sees it.
func TestEffectiveRedactPlaceholder(t *testing.T) {
	cases := []struct {
		name     string
		p5, p3   string
		fallback string
		want     string
	}{
		{"p5 wins", "[P5]", "[P3]", "[DEF]", "[P5]"},
		{"p3 fallback when p5 empty", "", "[P3]", "[DEF]", "[P3]"},
		{"default when both empty", "", "", "[DEF]", "[DEF]"},
		{"hard default when all empty", "", "", "", "[REDACTED]"},
		{"p5 explicit empty string still falls to p3", "", "[P3]", "[DEF]", "[P3]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EffectiveRedactPlaceholder(c.p5, c.p3, c.fallback); got != c.want {
				t.Errorf("EffectiveRedactPlaceholder(%q,%q,%q) = %q, want %q", c.p5, c.p3, c.fallback, got, c.want)
			}
		})
	}
}

// TestNormalizeStringList_AllArms directly exercises the helper used by
// normalizePillar1Sources (and thus Load) for project_roots/skip_dirs etc.
// Covers all type arms that were showing 0-block coverage in prior runs.
func TestNormalizeStringList_AllArms(t *testing.T) {
	if got := normalizeStringList(nil); len(got) != 0 {
		t.Errorf("nil -> %v", got)
	}
	if got := normalizeStringList([]string{"a", "b"}); len(got) != 2 || got[0] != "a" {
		t.Errorf("[]string -> %v", got)
	}
	if got := normalizeStringList([]any{"x", 123, "y"}); len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf("[]any mixed -> %v", got)
	}
	if got := normalizeStringList("single"); len(got) != 1 || got[0] != "single" {
		t.Errorf("string -> %v", got)
	}
	if got := normalizeStringList(""); len(got) != 0 {
		t.Errorf("empty string -> %v", got)
	}
	if got := normalizeStringList(42); len(got) != 0 {
		t.Errorf("other type -> %v", got)
	}
}

// TestDefaultSocketPath_ErrorPath hits the rare fallback in defaultSocketPath
// (the 0-block at the userHomeDir err || empty check) using the internal seam.
func TestDefaultSocketPath_ErrorPath(t *testing.T) {
	orig := userHomeDir
	defer func() { userHomeDir = orig }()
	userHomeDir = func() (string, error) { return "", errors.New("no home for test") }

	if got := defaultSocketPath(); got != "/tmp/blastradius.sock" {
		t.Errorf("defaultSocketPath on home err = %q, want /tmp fallback", got)
	}
}

// TestNormalizePillar1Sources_NilAndMissingSources directly exercises the nil-map make
// and per-source !ok default-creation arms (the 0 blocks at 341/347) without going
// through Load (which always starts from DefaultConfig that pre-populates Sources).
func TestNormalizePillar1Sources_NilAndMissingSources(t *testing.T) {
	// nil map case
	cfg := &Config{Pillar1: Pillar1Config{Sources: nil}}
	normalizePillar1Sources(cfg)
	if cfg.Pillar1.Sources == nil {
		t.Fatal("normalize should have created Sources map")
	}
	if _, ok := cfg.Pillar1.Sources["env"]; !ok {
		t.Error("env entry should be created for nil starting map")
	}

	// missing one source (e.g. only bitwarden present)
	cfg2 := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"bitwarden": {Enabled: true, Options: map[string]any{}},
			},
		},
	}
	normalizePillar1Sources(cfg2)
	if _, ok := cfg2.Pillar1.Sources["env"]; !ok {
		t.Error("env should be created when missing")
	}
	if !cfg2.Pillar1.Sources["bitwarden"].Enabled {
		t.Error("existing bitwarden entry preserved")
	}
	// Options normalized to non-nil even for created
	if cfg2.Pillar1.Sources["env"].Options == nil {
		t.Error("created env should have non-nil Options")
	}
}

// TestLoad_Pillar1SourcesNilTriggersNormalize hits the Sources==nil make + per-name !ok creation
// paths in normalizePillar1Sources (previously 0 blocks) by loading yaml with no pillar1 block at all.
func TestLoad_Pillar1SourcesNilTriggersNormalize(t *testing.T) {
	dir := t.TempDir()
	origRead := osReadFile
	origHome := userHomeDir
	defer func() {
		osReadFile = origRead
		userHomeDir = origHome
	}()
	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) {
		// No pillar1 at all -> after unmarshal Sources remains nil (from zero value)
		// then normalize creates the map + env + bitwarden entries.
		return []byte("log_level: info\n"), nil
	}

	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Pillar1.Sources == nil {
		t.Fatal("expected Sources map to be created by normalize")
	}
	if _, ok := cfg.Pillar1.Sources["env"]; !ok {
		t.Error("env source should have been created")
	}
	if _, ok := cfg.Pillar1.Sources["bitwarden"]; !ok {
		t.Error("bitwarden source should have been created")
	}
	// env defaults to enabled, bitwarden to disabled
	if !cfg.Pillar1.Sources["env"].Enabled {
		t.Error("env should be enabled by normalize default")
	}
	if cfg.Pillar1.Sources["bitwarden"].Enabled {
		t.Error("bitwarden should be disabled by normalize default")
	}
}
