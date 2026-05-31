package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Test hooks for improved testability (consistent with cli and daemon packages).
var (
	userHomeDir = os.UserHomeDir
	osReadFile  = os.ReadFile
	osWriteFile = os.WriteFile
	osMkdirAll  = os.MkdirAll
)

// Config holds user configuration. It must NEVER contain secrets or discovered hashes.
type Config struct {
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
	//
	// All commands are executed with direct argv (no shell) as a hard invariant.
	// For complex logic (pipes etc.), use a wrapper script you control.
	Pillar5Commands []Pillar5Command `yaml:"pillar5_commands,omitempty"`

	// ClipboardClearSeconds is the time after which detected secrets in clipboard are auto-cleared.
	ClipboardClearSeconds int `yaml:"clipboard_clear_seconds,omitempty"`

	// ResidueHunter configures Pillar 2 (Crumbs) — scoped high-risk directory secret residue scanning.
	ResidueHunter ResidueHunterConfig `yaml:"residue_hunter,omitempty"`

	// Pillar1 configures the logical layer for legitimate secret discovery (Pillar 1).
	// v1: explicit "env" and "bitwarden" sources under a unified interface.
	// Per-source options (especially ignore_patterns) feed the key-filtering engine.
	Pillar1 Pillar1Config `yaml:"pillar1,omitempty"`
}

// Pillar5Command represents a single command to execute for runtime hygiene checks.
//
// Commands are always executed via direct exec (no shell) as a hard security
// invariant. This prevents shell metacharacter injection and arbitrary command
// execution from user configuration. If you need pipes or complex logic, point
// at a wrapper script you control instead of putting shell syntax here.
type Pillar5Command struct {
	Name         string `yaml:"name"`
	Cmd          string `yaml:"cmd"`
	AutoOnPrompt bool   `yaml:"auto_on_prompt"`
}

// ResidueHunterConfig holds settings for Pillar 2 "Crumbs" (illegitimate secret residue hunter).
// v1: only enabled + target_dirs are required; detectors are fixed and always-on when enabled.
type ResidueHunterConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	TargetDirs              []string `yaml:"target_dirs,omitempty"`
	FlagSuspiciousFilenames bool     `yaml:"flag_suspicious_filenames,omitempty"`
}

// Pillar1Config configures the logical layer for legitimate secret discovery (Pillar 1).
// v1 supports two explicit sources under a unified interface: "env" (.env* files)
// and "bitwarden" (hard-coded bw CLI collector owned by the project).
type Pillar1Config struct {
	Sources map[string]SourceConfig `yaml:"sources,omitempty"`
}

// SourceConfig is the common envelope for an activatable Pillar 1 source.
type SourceConfig struct {
	Enabled bool           `yaml:"enabled"`
	Options map[string]any `yaml:"options,omitempty"` // populated into typed options by collectors
}

// EnvOptions holds configuration specific to the "env" logical source
// (the modern location under pillar1.sources.env.options).
type EnvOptions struct {
	ProjectRoots   []string `json:"project_roots,omitempty"`
	SkipDirs       []string `json:"skip_dirs,omitempty"`
	IgnoreFiles    []string `json:"ignore_files,omitempty"`
	IgnorePatterns []string `json:"ignore_patterns,omitempty"`
}

// BitwardenOptions holds configuration specific to the "bitwarden" logical source.
type BitwardenOptions struct {
	IgnorePatterns []string `json:"ignore_patterns,omitempty"`
	// Future fields (session handling hints, folder filters, etc.) can be added here.
}

// DefaultConfig returns a safe default configuration.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()

	return &Config{
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
		ResidueHunter: ResidueHunterConfig{
			Enabled:                 false,
			TargetDirs:              []string{"~/Downloads", "~/Documents", "~/Desktop"},
			FlagSuspiciousFilenames: true,
		},
		// Pillar 1 logical sources (env + bitwarden in v1).
		// We now recommend putting project_roots, skip_dirs, and ignore_files
		// under pillar1.sources.env.options (see GetEnvOptions for fallback logic).
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						// Users are encouraged to put project_roots / skip_dirs / ignore_files
						// here under pillar1.sources.env.options going forward.
						"ignore_patterns": []string{
							"PATH", "HOME", "PWD", "USER", "SHELL", "TERM",
							"LANG", "LC_*", "EDITOR", "VISUAL", "PAGER",
							"COLORTERM", "DISPLAY", "XDG_*",
							"DBUS_*", "DESKTOP_SESSION", "GNOME_*", "KDE_*",
							"SSH_*", "GPG_*", "LESS*", "MORE",
							"PS1", "PS2", "PROMPT*", "HIST*", "HISTSIZE",
						},
					},
				},
				"bitwarden": {
					Enabled: false,
					Options: map[string]any{},
				},
			},
		},
	}
}

// Load reads configuration from the standard location.
// If the file does not exist, returns defaults.
// It also returns the path it attempted to load from.
func Load() (cfg *Config, configPath string, err error) {
	cfg = DefaultConfig()

	home, err := userHomeDir()
	if err != nil {
		return cfg, "", nil
	}

	configPath = filepath.Join(home, ".config", "blastradius", "config.yaml")

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

	// Ensure residue hunter has sensible defaults even if user only partially populated the block
	if !cfg.ResidueHunter.Enabled && len(cfg.ResidueHunter.TargetDirs) == 0 {
		def := DefaultConfig().ResidueHunter
		cfg.ResidueHunter.TargetDirs = def.TargetDirs
		cfg.ResidueHunter.FlagSuspiciousFilenames = def.FlagSuspiciousFilenames
	}

	// Pillar 1 logical sources: ensure the map exists and both known v1 sources
	// have entries. This gives collectors a stable place to look for options
	// (especially ignore_patterns) even when the user only partially configured.
	normalizePillar1Sources(cfg)

	return cfg, configPath, nil
}

// normalizePillar1Sources ensures the Pillar1.Sources map and the two v1
// providers ("env", "bitwarden") always exist after unmarshal.
func normalizePillar1Sources(cfg *Config) {
	if cfg.Pillar1.Sources == nil {
		cfg.Pillar1.Sources = make(map[string]SourceConfig)
	}

	for _, name := range []string{"env", "bitwarden"} {
		src, ok := cfg.Pillar1.Sources[name]
		if !ok {
			src = SourceConfig{Enabled: name == "env", Options: map[string]any{}}
		}
		if src.Options == nil {
			src.Options = map[string]any{}
		}

		// If the user is using the new pillar1.sources.env.options style,
		// we respect those values. Otherwise we migrate legacy top-level keys
		// into the env source options for a smooth transition.
		if name == "env" {
			migrateLegacyDiscoveryKeys(cfg, &src)
		}

		// Normalize common list fields and ensure they are never nil slices.
		for _, key := range []string{"project_roots", "skip_dirs", "ignore_files", "ignore_patterns"} {
			if raw, exists := src.Options[key]; exists && raw != nil {
				normalized := normalizeStringList(raw)
				src.Options[key] = normalized // always set, even if empty
			} else {
				// Guarantee the key exists as a non-nil slice
				src.Options[key] = []string{}
			}
		}

		cfg.Pillar1.Sources[name] = src
	}
}

// migrateLegacyDiscoveryKeys moves project_roots / skip_dirs / ignore_files
// from the old top level into pillar1.sources.env.options when the new keys
// are not already present. This provides a transparent migration path.
func migrateLegacyDiscoveryKeys(cfg *Config, envSrc *SourceConfig) {
	if envSrc.Options == nil {
		envSrc.Options = map[string]any{}
	}

	if _, has := envSrc.Options["project_roots"]; !has && len(cfg.ProjectRoots) > 0 {
		envSrc.Options["project_roots"] = cfg.ProjectRoots
	}
	if _, has := envSrc.Options["skip_dirs"]; !has && len(cfg.SkipDirs) > 0 {
		envSrc.Options["skip_dirs"] = cfg.SkipDirs
	}
	if _, has := envSrc.Options["ignore_files"]; !has && len(cfg.IgnoreFiles) > 0 {
		envSrc.Options["ignore_files"] = cfg.IgnoreFiles
	}
}

// normalizeStringList accepts []string, []any, or a single string and returns []string.
func normalizeStringList(v any) []string {
	if v == nil {
		return []string{}
	}
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return []string{}
		}
		return []string{x}
	default:
		return []string{}
	}
}

// GetSourceIgnorePatterns returns the normalized ignore patterns for a named
// Pillar 1 source (e.g. "env" or "bitwarden"). Safe to call on any config.
// It never returns nil — missing patterns are represented as an empty slice.
func (c *Config) GetSourceIgnorePatterns(sourceName string) []string {
	if c == nil || c.Pillar1.Sources == nil {
		return []string{}
	}
	src, ok := c.Pillar1.Sources[sourceName]
	if !ok || src.Options == nil {
		return []string{}
	}
	if list, ok := src.Options["ignore_patterns"].([]string); ok {
		if list == nil {
			return []string{}
		}
		return list
	}
	// Also try the typed path via GetEnvOptions for "env" for convenience
	if sourceName == "env" {
		return c.GetEnvOptions().IgnorePatterns
	}
	return []string{}
}

// GetEnvOptions returns the effective configuration for the "env" source.
//
// Priority (highest first):
// 1. Values under pillar1.sources.env.options (new recommended location)
// 2. Legacy top-level project_roots / skip_dirs / ignore_files (for compatibility)
func (c *Config) GetEnvOptions() EnvOptions {
	if c == nil {
		return EnvOptions{}
	}

	opts := EnvOptions{}

	// New style: pillar1.sources.env.options takes precedence
	if c.Pillar1.Sources != nil {
		if envSrc, ok := c.Pillar1.Sources["env"]; ok && envSrc.Options != nil {
			if v, ok := envSrc.Options["project_roots"].([]string); ok && len(v) > 0 {
				opts.ProjectRoots = v
			}
			if v, ok := envSrc.Options["skip_dirs"].([]string); ok && len(v) > 0 {
				opts.SkipDirs = v
			}
			if v, ok := envSrc.Options["ignore_files"].([]string); ok && len(v) > 0 {
				opts.IgnoreFiles = v
			}
			if v, ok := envSrc.Options["ignore_patterns"].([]string); ok {
				if v == nil {
					opts.IgnorePatterns = []string{}
				} else {
					opts.IgnorePatterns = v
				}
			}
		}
	}

	// Fall back to legacy top-level keys
	if len(opts.ProjectRoots) == 0 {
		opts.ProjectRoots = append([]string{}, c.ProjectRoots...)
	}
	if len(opts.SkipDirs) == 0 {
		opts.SkipDirs = append([]string{}, c.SkipDirs...)
	}
	if len(opts.IgnoreFiles) == 0 {
		opts.IgnoreFiles = append([]string{}, c.IgnoreFiles...)
	}
	if opts.IgnorePatterns == nil {
		opts.IgnorePatterns = []string{}
	}

	return opts
}


// Save writes the configuration (for future use).
func (c *Config) Save() error {
	home, err := userHomeDir()
	if err != nil {
		return err
	}

	dir := filepath.Join(home, ".config", "blastradius")
	if err := osMkdirAll(dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(dir, "config.yaml")

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return osWriteFile(path, data, 0600)
}

// --- Hard-coded socket path (security invariant) ---

const socketFileName = "blastradius.sock"

// SocketPathFn is the function used to resolve the socket path.
// It is overridable by tests for hermetic per-test socket locations.
// Production code should call SocketPath() instead of using this directly.
var SocketPathFn = defaultSocketPath

// defaultSocketPath returns the canonical secure location under the user's
// XDG state directory. This path is a hard security invariant for production.
func defaultSocketPath() string {
	home, err := userHomeDir()
	if err != nil || home == "" {
		// Extremely rare fallback. In practice this should never be hit.
		return "/tmp/blastradius.sock"
	}
	return filepath.Join(home, ".local", "state", "blastradius", socketFileName)
}

// SocketPath returns the location of the Unix domain socket used for
// daemon <-> CLI communication.
//
// This is intentionally not configurable by users. The path is a hard
// security invariant (private directory + strict permissions + capability token).
// Allowing overrides would re-introduce the attack surface we worked to eliminate.
func SocketPath() string {
	return SocketPathFn()
}