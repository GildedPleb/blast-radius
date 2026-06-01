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
//
// The persisted shape is deliberately organized around the five pillars for
// maximum user clarity (see docs/pillars/idiomatic_pillars.md). Only true
// cross-cutting core settings (e.g. log_level) live at the top level.
type Config struct {
	// LogLevel for future use (debug | info | warn | error).
	LogLevel string `yaml:"log_level,omitempty"`

	// Pillar1 configures Legitimate Secret Discovery — the "where secrets should be" layer.
	// All discovery roots, skip/ignore rules, and per-source options live under here.
	Pillar1 Pillar1Config `yaml:"pillar1,omitempty"`

	// Pillar2 configures Illegitimate Secret Residue hunting (the "Crumbs" hunter).
	// This is the deliberate inversion of Pillar 1: finds vault exports and high-entropy
	// dumps in high-risk user directories (Downloads, Documents, Desktop, etc.).
	Pillar2 Pillar2Config `yaml:"pillar2,omitempty"`

	// Pillar3 (History Hygiene) currently has no user-configurable surface.
	// Scrubbing uses the registry populated by Pillar 1. Placeholder kept for ordering.
	Pillar3 struct{} `yaml:"pillar3,omitempty"`

	// Pillar4 configures Runtime Environment Hygiene (commands whose output is scanned
	// for secrets, most commonly printenv). All commands execute via direct exec only.
	Pillar4 Pillar4Config `yaml:"pillar4,omitempty"`

	// Pillar5 configures Clipboard Hygiene (macOS auto-clear timer today).
	Pillar5 Pillar5Config `yaml:"pillar5,omitempty"`
}

// RuntimeCommand represents a single command whose output should be scanned for secrets
// (Pillar 4 — Runtime Environment Hygiene).
//
// Commands are always executed via direct exec (no shell) as a hard security
// invariant. This prevents shell metacharacter injection and arbitrary command
// execution from user configuration. If you need pipes or complex logic, point
// at a wrapper script you control instead of putting shell syntax here.
type RuntimeCommand struct {
	Name         string `yaml:"name"`
	Cmd          string `yaml:"cmd"`
	AutoOnPrompt bool   `yaml:"auto_on_prompt"`
}

// Pillar2Config holds settings for Pillar 2 "Crumbs" (illegitimate secret residue hunter).
// v1: only enabled + target_dirs are required; detectors are fixed and always-on when enabled.
type Pillar2Config struct {
	Enabled                 bool     `yaml:"enabled"`
	TargetDirs              []string `yaml:"target_dirs,omitempty"`
	FlagSuspiciousFilenames bool     `yaml:"flag_suspicious_filenames,omitempty"`
}

// Pillar4Config groups the runtime hygiene commands (Pillar 4).
type Pillar4Config struct {
	Commands []RuntimeCommand `yaml:"commands,omitempty"`
}

// Pillar5Config groups clipboard hygiene settings (Pillar 5).
type Pillar5Config struct {
	ClearSeconds int `yaml:"clear_seconds,omitempty"`
}

// Pillar1Config configures the logical layer for legitimate secret discovery (Pillar 1).
// v1 supports two explicit sources under a unified interface: "env" (.env* files)
// and "bitwarden" (hard-coded bw CLI collector owned by the project).
//
// All discovery settings (project_roots, skip_dirs, ignore_files, ignore_patterns)
// now live under sources.<name>.options — this is the only supported location.
type Pillar1Config struct {
	Sources map[string]SourceConfig `yaml:"sources,omitempty"`
}

// SourceConfig is the common envelope for an activatable Pillar 1 source.
// Options are stored as map[string]any for forward extensibility (new sources
// or source-specific knobs do not require struct changes). The well-known
// keys (project_roots, skip_dirs, ignore_files, ignore_patterns) are normalized
// to []string by normalizePillar1Sources.
type SourceConfig struct {
	Enabled bool           `yaml:"enabled"`
	Options map[string]any `yaml:"options,omitempty"` // populated into typed options by collectors
}

// EnvOptions holds the effective (typed) configuration for the "env" logical source
// under pillar1.sources.env.options. This is the single source of truth after the
// removal of the legacy top-level project_roots / skip_dirs / ignore_files fields.
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
//
// All defaults now live under the pillarN: sections (single source of truth).
// The legacy top-level project_roots/skip_dirs/ignore_files fields have been removed.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()

	return &Config{
		LogLevel: "info",
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"project_roots": []string{home},
						"skip_dirs": []string{
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
						"ignore_files": []string{".gitignore", ".blastradiusignore"},
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
		Pillar2: Pillar2Config{
			Enabled:                 false,
			TargetDirs:              []string{"~/Downloads", "~/Documents", "~/Desktop"},
			FlagSuspiciousFilenames: true,
		},
		// Pillar3 has no settings yet — struct{} keeps the key order visible if marshaled.
		Pillar3: struct{}{},
		Pillar4: Pillar4Config{
			Commands: []RuntimeCommand{
				{Name: "default-env", Cmd: "printenv", AutoOnPrompt: true},
			},
		},
		Pillar5: Pillar5Config{
			ClearSeconds: 30,
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

	// Pillar 2 (residue hunter) — fill sensible defaults if the user only partially
	// populated the block (enabled:false + empty target_dirs is common).
	if !cfg.Pillar2.Enabled && len(cfg.Pillar2.TargetDirs) == 0 {
		def := DefaultConfig().Pillar2
		cfg.Pillar2.TargetDirs = def.TargetDirs
		cfg.Pillar2.FlagSuspiciousFilenames = def.FlagSuspiciousFilenames
	}

	// Pillar 1 logical sources: ensure the map exists and both known v1 sources
	// have entries. This gives collectors a stable place to look for options
	// (especially ignore_patterns) even when the user only partially configured.
	normalizePillar1Sources(cfg)

	return cfg, configPath, nil
}

// normalizePillar1Sources ensures the Pillar1.Sources map and the two v1
// providers ("env", "bitwarden") always exist after unmarshal.
//
// With the legacy top-level project_roots/skip_dirs/ignore_files fields removed,
// this function no longer performs any migration. It only guarantees a stable
// shape for collectors and GetEnvOptions.
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
	// For the env source, prefer GetEnvOptions (which now defensively normalizes
	// []any lists from yaml and guarantees non-nil slices).
	if sourceName == "env" {
		return c.GetEnvOptions().IgnorePatterns
	}
	// For other sources (bitwarden, future ones), normalize directly.
	return normalizeStringList(src.Options["ignore_patterns"])
}

// GetEnvOptions returns the effective configuration for the "env" source
// (Pillar 1 legitimate secret discovery).
//
// This is now the single source of truth. All values come from
// pillar1.sources.env.options (the legacy top-level project_roots / skip_dirs /
// ignore_files fields and migration logic have been removed).
func (c *Config) GetEnvOptions() EnvOptions {
	if c == nil {
		return EnvOptions{
			ProjectRoots:   []string{},
			SkipDirs:       []string{},
			IgnoreFiles:    []string{},
			IgnorePatterns: []string{},
		}
	}

	opts := EnvOptions{}

	if c.Pillar1.Sources != nil {
		if envSrc, ok := c.Pillar1.Sources["env"]; ok && envSrc.Options != nil {
			// Defensively normalize from []any (what yaml.Unmarshal into map[string]any produces)
			// as well as []string. This makes the public accessor robust even when a Config
			// is constructed manually or unmarshaled without going through Load().
			if v := normalizeStringList(envSrc.Options["project_roots"]); len(v) > 0 {
				opts.ProjectRoots = v
			}
			if v := normalizeStringList(envSrc.Options["skip_dirs"]); len(v) > 0 {
				opts.SkipDirs = v
			}
			if v := normalizeStringList(envSrc.Options["ignore_files"]); len(v) > 0 {
				opts.IgnoreFiles = v
			}
			opts.IgnorePatterns = normalizeStringList(envSrc.Options["ignore_patterns"])
		}
	}

	// Always return non-nil slices for the well-known fields. This matches the
	// contract that Load() + normalizePillar1Sources() provides, makes direct
	// struct construction in tests ergonomic, and prevents surprising nils for
	// callers that do &Config{} or partial configs.
	if opts.ProjectRoots == nil {
		opts.ProjectRoots = []string{}
	}
	if opts.SkipDirs == nil {
		opts.SkipDirs = []string{}
	}
	if opts.IgnoreFiles == nil {
		opts.IgnoreFiles = []string{}
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
