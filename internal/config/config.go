package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds user configuration. It must NEVER contain secrets or discovered hashes.
type Config struct {
	// SocketPath allows overriding the default Unix socket location.
	SocketPath string `yaml:"socket_path,omitempty"`

	// ProjectRoots is a list of directories to monitor (hybrid discovery in later phases).
	ProjectRoots []string `yaml:"project_roots,omitempty"`

	// LogLevel for future use.
	LogLevel string `yaml:"log_level,omitempty"`
}

// DefaultConfig returns a safe default configuration.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		SocketPath:   "/tmp/blastradius.sock",
		ProjectRoots: []string{home}, // conservative default; will be refined
		LogLevel:     "info",
	}
}

// Load reads configuration from the standard location.
// If the file does not exist, returns defaults.
func Load() (*Config, error) {
	cfg := DefaultConfig()

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil // fall back to defaults
	}

	path := filepath.Join(home, ".config", "blastradius", "config.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultConfig().SocketPath
	}

	return cfg, nil
}

// Save writes the configuration (for future use).
func (c *Config) Save() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	dir := filepath.Join(home, ".config", "blastradius")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(dir, "config.yaml")

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}