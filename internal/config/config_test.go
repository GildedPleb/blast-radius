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
	if len(cfg.SkipDirs) == 0 || len(cfg.Pillar5Commands) == 0 {
		t.Error("defaults missing required fields")
	}
	if !cfg.ResidueHunter.FlagSuspiciousFilenames || len(cfg.ResidueHunter.TargetDirs) == 0 {
		t.Error("residue_hunter defaults not populated")
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
		return []byte("residue_hunter:\n  enabled: true\n"), nil
	}

	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// Should have filled in defaults for TargetDirs etc.
	if len(cfg.ResidueHunter.TargetDirs) == 0 {
		t.Error("expected residue defaults to be populated on partial config")
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
	// yaml with residue enabled:false + empty targets (triggers fill)
	osReadFile = func(name string) ([]byte, error) {
		return []byte("residue_hunter:\n  enabled: false\n  target_dirs: []\n"), nil
	}
	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// socket path is a hard-coded invariant and no longer appears in user config

	if len(cfg.ResidueHunter.TargetDirs) == 0 {
		t.Error("expected residue target dirs filled from defaults")
	}
	if cfg.ResidueHunter.Enabled {
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

func TestGetEnvOptions_NewStyle(t *testing.T) {
	cfg := &Config{
		// Legacy values that should be ignored when new style is present
		ProjectRoots: []string{"/legacy/root"},
		SkipDirs:     []string{"legacy_skip"},
		IgnoreFiles:  []string{".legacyignore"},
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
		t.Errorf("ProjectRoots not taken from new style: %v", opts.ProjectRoots)
	}
	if len(opts.SkipDirs) != 3 || opts.SkipDirs[0] != "node_modules" {
		t.Errorf("SkipDirs not taken from new style: %v", opts.SkipDirs)
	}
	if len(opts.IgnoreFiles) != 2 || opts.IgnoreFiles[0] != ".gitignore" {
		t.Errorf("IgnoreFiles not taken from new style: %v", opts.IgnoreFiles)
	}
	if len(opts.IgnorePatterns) != 2 || opts.IgnorePatterns[0] != "LOG_*" {
		t.Errorf("IgnorePatterns not taken from new style: %v", opts.IgnorePatterns)
	}
}

func TestGetEnvOptions_LegacyFallback(t *testing.T) {
	cfg := &Config{
		ProjectRoots: []string{"~/legacy-projects"},
		SkipDirs:     []string{"legacy-node_modules"},
		IgnoreFiles:  []string{".legacy-gitignore"},
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true}, // no options at all
			},
		},
	}

	opts := cfg.GetEnvOptions()

	if len(opts.ProjectRoots) != 1 || opts.ProjectRoots[0] != "~/legacy-projects" {
		t.Errorf("Expected legacy ProjectRoots, got %v", opts.ProjectRoots)
	}
	if len(opts.SkipDirs) != 1 || opts.SkipDirs[0] != "legacy-node_modules" {
		t.Errorf("Expected legacy SkipDirs, got %v", opts.SkipDirs)
	}
	if len(opts.IgnoreFiles) != 1 || opts.IgnoreFiles[0] != ".legacy-gitignore" {
		t.Errorf("Expected legacy IgnoreFiles, got %v", opts.IgnoreFiles)
	}
}

func TestGetEnvOptions_NewStyleWins(t *testing.T) {
	cfg := &Config{
		ProjectRoots: []string{"/legacy-should-be-ignored"},
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"project_roots": []string{"~/new-projects"},
					},
				},
			},
		},
	}

	opts := cfg.GetEnvOptions()
	if len(opts.ProjectRoots) != 1 || opts.ProjectRoots[0] != "~/new-projects" {
		t.Errorf("New style should win over legacy: %v", opts.ProjectRoots)
	}
}

func TestGetEnvOptions_Empty(t *testing.T) {
	cfg := &Config{}
	opts := cfg.GetEnvOptions()
	// After normalization we guarantee non-nil slices (better API)
	if opts.ProjectRoots == nil || opts.SkipDirs == nil || opts.IgnoreFiles == nil {
		t.Errorf("Expected non-nil slices for empty config (we normalize), got %+v", opts)
	}
}