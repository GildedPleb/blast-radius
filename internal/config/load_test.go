package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	// (When no pillar1 block at all, normalization still ensures the known sources exist.)
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

// -----------------------------------------------------------------------------
// First-run / Ensure + ValidateReadiness tests (hermetic via hooks)
// -----------------------------------------------------------------------------

func TestEnsureConfigFile_CreatesOnAbsent(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRead := osReadFile
	origMkdir := osMkdirAll
	origWrite := osWriteFile
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
		osMkdirAll = origMkdir
		osWriteFile = origWrite
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	// First read sees nothing.
	osReadFile = func(name string) ([]byte, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(path string, perm os.FileMode) error { return nil }
	var written []byte
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		written = append([]byte(nil), data...)
		return nil
	}

	p, created, err := EnsureConfigFile()
	if err != nil {
		t.Fatalf("EnsureConfigFile failed: %v", err)
	}
	if !created {
		t.Error("expected created=true on first ensure")
	}
	if !strings.HasSuffix(p, "config.yaml") {
		t.Errorf("unexpected path: %s", p)
	}
	if len(written) == 0 {
		t.Fatal("no data written")
	}
	content := string(written)
	// The initial template now deliberately leaves project_roots empty (the
	// substantive user action is to fill it). We still expect the key and a
	// loud comment explaining the requirement.
	if !strings.Contains(content, "project_roots: []") {
		t.Error("written template should have empty project_roots (user must fill)")
	}
	if !strings.Contains(content, "project_roots is deliberately LEFT EMPTY") {
		t.Error("written template should document why project_roots is left empty")
	}
}

func TestEnsureConfigFile_IdempotentWhenPresent(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRead := osReadFile
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) { return []byte("already here"), nil }

	_, created, err := EnsureConfigFile()
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	if created {
		t.Error("expected created=false when file already present")
	}
}

func TestRemoveConfigFile(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRemove := osRemove
	defer func() {
		userHomeDir = origHome
		osRemove = origRemove
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	removed := false
	osRemove = func(name string) error {
		removed = true
		return nil
	}

	if err := RemoveConfigFile(); err != nil {
		t.Fatalf("RemoveConfigFile failed: %v", err)
	}
	if !removed {
		t.Error("expected osRemove to be called")
	}
}

// -----------------------------------------------------------------------------
// Additional EnsureConfigFile error path coverage (previously missing)
// -----------------------------------------------------------------------------

func TestEnsureConfigFile_ConfigPathFails(t *testing.T) {
	origHome := userHomeDir
	defer func() { userHomeDir = origHome }()

	userHomeDir = func() (string, error) { return "", errors.New("no home") }

	_, created, err := EnsureConfigFile()
	if err == nil {
		t.Error("expected error when ConfigPath fails")
	}
	if created {
		t.Error("created should be false on ConfigPath error")
	}
}

func TestEnsureConfigFile_ReadOtherError(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRead := osReadFile
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	// Return a non-NotExist error (e.g. permission). This hits the
	// "else if !os.IsNotExist(readErr)" branch in EnsureConfigFile.
	osReadFile = func(name string) ([]byte, error) {
		return nil, os.ErrPermission
	}

	_, created, err := EnsureConfigFile()
	if err == nil {
		t.Error("expected error on non-NotExist read failure")
	}
	if created {
		t.Error("created should be false on read error")
	}
}

func TestEnsureConfigFile_MkdirError(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRead := osReadFile
	origMkdir := osMkdirAll
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
		osMkdirAll = origMkdir
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(path string, perm os.FileMode) error {
		return errors.New("mkdir denied")
	}

	_, created, err := EnsureConfigFile()
	if err == nil {
		t.Error("expected error when osMkdirAll fails")
	}
	if created {
		t.Error("created should be false on mkdir failure")
	}
}

func TestEnsureConfigFile_WriteError(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRead := osReadFile
	origMkdir := osMkdirAll
	origWrite := osWriteFile
	defer func() {
		userHomeDir = origHome
		osReadFile = origRead
		osMkdirAll = origMkdir
		osWriteFile = origWrite
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	osReadFile = func(name string) ([]byte, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(path string, perm os.FileMode) error { return nil }
	// Fail when writing the initial template. This covers the final
	// osWriteFile error return path in EnsureConfigFile.
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		return errors.New("disk full while writing template")
	}

	_, created, err := EnsureConfigFile()
	if err == nil {
		t.Error("expected error when osWriteFile fails writing template")
	}
	if created {
		t.Error("created should be false on template write failure")
	}
}

func TestRemoveConfigFile_ConfigPathFails(t *testing.T) {
	origHome := userHomeDir
	defer func() { userHomeDir = origHome }()

	userHomeDir = func() (string, error) { return "", errors.New("no home") }

	err := RemoveConfigFile()
	if err == nil {
		t.Error("expected error when ConfigPath fails")
	}
}

func TestRemoveConfigFile_RemoveError(t *testing.T) {
	dir := t.TempDir()

	origHome := userHomeDir
	origRemove := osRemove
	defer func() {
		userHomeDir = origHome
		osRemove = origRemove
	}()

	userHomeDir = func() (string, error) { return dir, nil }
	// Return a real error that is *not* os.IsNotExist. This exercises the
	// "if err := osRemove(p); err != nil && !os.IsNotExist(err)" branch.
	osRemove = func(name string) error {
		return errors.New("permission denied")
	}

	err := RemoveConfigFile()
	if err == nil {
		t.Error("expected error when osRemove fails with a non-NotExist error")
	}
}

func TestMustConfigPath_Fallback(t *testing.T) {
	origHome := userHomeDir
	defer func() { userHomeDir = origHome }()

	userHomeDir = func() (string, error) { return "", errors.New("no home") }

	if got := mustConfigPath(); got != "~/.config/blastradius/config.yaml" {
		t.Errorf("expected fallback path, got %q", got)
	}
}
