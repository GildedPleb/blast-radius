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