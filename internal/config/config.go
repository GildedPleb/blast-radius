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

	// ProjectRoots is a list of directories to monitor.
	ProjectRoots []string `yaml:"project_roots,omitempty"`

	// SkipDirs are directory basenames we should never descend into during discovery.
	// These supplement the built-in safe defaults for performance and noise reduction.
	SkipDirs []string `yaml:"skip_dirs,omitempty"`

	// IgnoreFiles lists the filenames to treat as ignore files (e.g. ".gitignore", ".blastradiusignore").
	// Order matters — later files can override earlier behavior if we add precedence later.
	IgnoreFiles []string `yaml:"ignore_files,omitempty"`

	// LogLevel for future use.
	LogLevel string `yaml:"log_level,omitempty"`

	// Pillar5Commands defines user-specified commands whose output should be scanned for secrets.
	// Only the first command defaults to auto_on_prompt: true (printenv).
	Pillar5Commands []Pillar5Command `yaml:"pillar5_commands,omitempty"`

	// ClipboardClearSeconds is the time after which detected secrets in clipboard are auto-cleared.
	ClipboardClearSeconds int `yaml:"clipboard_clear_seconds,omitempty"`
}

// Pillar5Command represents a single command to execute for runtime hygiene checks.
type Pillar5Command struct {
	Name         string `yaml:"name"`
	Cmd          string `yaml:"cmd"`
	AutoOnPrompt bool   `yaml:"auto_on_prompt"`
}

// DefaultConfig returns a safe default configuration.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		SocketPath:   "/tmp/blastradius.sock",
		ProjectRoots: []string{home},
		SkipDirs: []string{
			"node_modules",
			".git",
			"vendor",
			"dist",
			"build",
			".next",
			"target",
			"out",
			".cache",
			"coverage",
			".venv",
			"__pycache__",
		},
		IgnoreFiles: []string{".gitignore", ".blastradiusignore"},
		LogLevel:    "info",
		Pillar5Commands: []Pillar5Command{
			{Name: "default-env", Cmd: "printenv", AutoOnPrompt: true},
		},
		ClipboardClearSeconds: 30,
	}
}

// Load reads configuration from the standard location.
// If the file does not exist, returns defaults.
// It also returns the path it attempted to load from.
func Load() (cfg *Config, configPath string, err error) {
	cfg = DefaultConfig()

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, "", nil
	}

	configPath = filepath.Join(home, ".config", "blastradius", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, configPath, nil
		}
		return nil, configPath, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, configPath, err
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultConfig().SocketPath
	}

	return cfg, configPath, nil
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