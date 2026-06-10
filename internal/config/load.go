package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Test hooks for improved testability (consistent with cli and daemon packages).
// These are overridden in tests to avoid touching the real filesystem.
var (
	userHomeDir = os.UserHomeDir
	osReadFile  = os.ReadFile
	osWriteFile = os.WriteFile
	osMkdirAll  = os.MkdirAll
	osRemove    = os.Remove
	yamlMarshal = yaml.Marshal
)

// Load reads configuration from the standard location (see ConfigPath).
// If the file does not exist, it returns defaults (and the path that would have been used).
// It also returns the path it attempted to load from.
//
// First-run behavior lives in EnsureConfigFile (called by the CLI layer on any
// command touch). Load itself never creates files and continues to return safe
// defaults on absence so that tests and internal paths remain unchanged.
func Load() (cfg *Config, configPath string, err error) {
	cfg = DefaultConfig()

	var pathErr error
	configPath, pathErr = ConfigPath()
	if pathErr != nil {
		// Extremely rare (home dir failure). Return defaults + empty path so
		// callers degrade safely.
		return cfg, "", nil
	}

	data, err := osReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, configPath, nil
		}
		return nil, configPath, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, configPath, err
	}

	// Pillar 2 — fill sensible defaults if the user only partially populated the block.
	if !cfg.Pillar2.Enabled && len(cfg.Pillar2.Dirs) == 0 {
		def := DefaultConfig().Pillar2
		cfg.Pillar2.Dirs = def.Dirs
	}

	// Pillar 3 (History Hygiene)
	normalizePillar3(cfg)

	// Pillar 1 logical sources
	normalizePillar1Sources(cfg)

	// Pillar 4
	normalizePillar4(cfg)

	// Pillar 5
	normalizePillar5(cfg)

	return cfg, configPath, nil
}

// Save writes the configuration to disk.
func (c *Config) Save() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := osMkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yamlMarshal(c)
	if err != nil {
		return err
	}

	return osWriteFile(path, data, 0600)
}

// ConfigPath returns the canonical user config location under the XDG config
// directory. It is the single source of truth for the persisted path.
func ConfigPath() (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "blastradius", "config.yaml"), nil
}

// EnsureConfigFile creates the standard config file at the XDG location using
// the initial template if and only if no file exists there. It is the hook for
// "first touch by any command".
//
// Returns the path, created=true when a new template was written, and any error.
func EnsureConfigFile() (path string, created bool, err error) {
	p, err := ConfigPath()
	if err != nil {
		return "", false, err
	}

	// Existence check via the test hook (hermetic).
	if _, readErr := osReadFile(p); readErr == nil {
		return p, false, nil // already exists
	} else if !os.IsNotExist(readErr) {
		return p, false, readErr
	}

	// Need to create dir + write template.
	dir := filepath.Dir(p)
	if err := osMkdirAll(dir, 0700); err != nil {
		return p, false, err
	}

	// Note: initialConfigTemplate() now sources from config.example.yaml
	// (see template handling after your step 1 changes).
	tmpl := initialConfigTemplate()
	if err := osWriteFile(p, tmpl, 0600); err != nil {
		return p, false, err
	}
	return p, true, nil
}

// RemoveConfigFile removes the user config file if it exists (used by
// `blastradius validate --reset`). Safe on non-existence.
func RemoveConfigFile() error {
	p, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := osRemove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// mustConfigPath is a tiny helper so error messages can safely include the path
// even in the (extremely rare) case that userHomeDir fails.
func mustConfigPath() string {
	if p, err := ConfigPath(); err == nil && p != "" {
		return p
	}
	return "~/.config/blastradius/config.yaml"
}
