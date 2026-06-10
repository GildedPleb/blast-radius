package config

import (
	"embed"
	"os"
)

//go:embed config.example.yaml
var configExampleFS embed.FS

// initialConfigTemplate returns the exact content of config.example.yaml.
//
// We deliberately ignore the error from ReadFile. The file is embedded at
// compile time via //go:embed. If it is missing, the build fails before this
// code can ever run. There is no meaningful runtime error path to handle or test.
func initialConfigTemplate() []byte {
	data, _ := configExampleFS.ReadFile("config.example.yaml")
	return data
}

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

	// Pillar3 configures History Hygiene (scrub-history command).
	// Supports configurable redaction modes for cleaning secrets from shell history
	// (zsh, bash, and other common shells per the LCD research in the Pillar 3 plan).
	Pillar3 Pillar3Config `yaml:"pillar3,omitempty"`

	// Pillar4 configures the commands for the Pillar 4 primitive (the `env`
	// function call). The primitive runs the cmd via direct exec, searches its
	// output for known secrets via the unified detector, surfaces a count and
	// logs to the daemon log (never the secret values). See RuntimeCommand for
	// the `enabled` field used by future wiring.
	Pillar4 Pillar4Config `yaml:"pillar4,omitempty"`

	// Pillar5 configures Clipboard Hygiene.
	// See Pillar5Config for the two-tier timeouts (redact + full clear),
	// redact_placeholder (for manual/auto redaction), and monitor/alert
	// controls for the reactive background monitor.
	Pillar5 Pillar5Config `yaml:"pillar5,omitempty"`
}

// RuntimeCommand represents a single command that the Pillar 4 primitive
// (`blastradius env [name]`) can run.
//
// The primitive (RunEnvCheck) does one thing: exec the cmd (direct only),
// search its output content via unified detection for known secrets (from P1
// registry), surface a count + log the result to the daemon log — never
// showing secret values.
//
// Commands are always executed via direct exec (no shell) as a hard security
// invariant. This prevents shell metacharacter injection and arbitrary command
// execution from user configuration. If you need pipes or complex logic, point
// at a wrapper script you control instead of putting shell syntax here.
//
// The `enabled` field indicates commands that should be considered for future
// automation (prompt wiring, periodic callers, etc.). The primitive runs any
// named command regardless.
type RuntimeCommand struct {
	Name    string `yaml:"name"`
	Cmd     string `yaml:"cmd"`
	Enabled bool   `yaml:"enabled"`
}

// Pillar2Dir describes one configured surface for Pillar 2 residue hunting.
// Each entry lets you target a specific directory and give it the exact
// files[] patterns that make sense for the kind of residue or exports that
// actually appear in that location.
//
// See internal/config/config.example.yaml for realistic examples (including /tmp, ~/tmp,
// ~/Library/Logs, project trees, etc.).
//
// P1 authority rule (enforced by internal/policy.Classifier, not here):
// Any file that matches an active pillar1.sources.env env_file_patterns under
// a P1 project_root is *never* treated as a P2 crumb, even if it matches a
// dirs[].files pattern. Pillar 1 has priority and authority over Pillar 2.
type Pillar2Dir struct {
	Path  string   `yaml:"path" json:"path"`
	Files []string `yaml:"files,omitempty" json:"files,omitempty"`
}

// Pillar2Config holds settings for Pillar 2 "Crumbs" (illegitimate secret residue hunter).
// The dirs[] array is the mechanism for declaring the actual locations that matter
// (user dump folders, /tmp, ~/tmp, logs directories, project trees, etc.) and giving
// each one the narrow, location-appropriate files[] patterns.
//
// P1 authority rule (enforced by internal/policy.Classifier):
// Anything claimed by an active Pillar 1 env source via env_file_patterns
// is off-limits to Pillar 2.
type Pillar2Config struct {
	Enabled bool         `yaml:"enabled"`
	Dirs    []Pillar2Dir `yaml:"dirs,omitempty"`
}

// Pillar4Config groups the commands available to the Pillar 4 primitive
// function call (`blastradius env [name]` / RunEnvCheck).
//
// The top-level `enabled` field is the pillar-wide opt-in (consistent with
// Pillar 2, 3, and now 5). Even if commands are listed, the primitive and
// related validation will treat the pillar as inactive until enabled: true
// is set. This gives users an explicit way to disable the `env` primitive
// entirely.
type Pillar4Config struct {
	Enabled  bool             `yaml:"enabled"`
	Commands []RuntimeCommand `yaml:"commands,omitempty"`
}

// Pillar5Config groups clipboard hygiene settings (Pillar 5): the status/visibility
// primitive, explicit redact/scrub + clear primitives via CLI/daemon commands,
// and (when MonitorEnabled) the optional reactive background monitor providing
// fast first-secret alerting plus two-tier auto (redact after timeout, then full
// clear after a further or independent timeout).
//
// The top-level `enabled` field is the pillar-wide opt-in switch (consistent
// convention across pillars). When false, the background monitor will not run
// and validation for `blastradius clipboard` commands will guide the user to
// enable it. This is the explicit control if you do not want the daemon (or
// CLI paths) touching/reading your clipboard contents at all.
//
// RedactTimeoutSeconds: after a secret is detected and the clipboard content
// remains stable, automatically redact known secrets (P3-style placeholder
// replacement) after this many seconds. Gives a safe use window for intentional
// pastes (e.g. paste secret to AI) before the system cleans the values for you.
// FullClearTimeoutSeconds: after (or independently of) the redact timeout, if
// still stable, do a full clipboard clear. The two timers are independent and
// user-configurable.
//
// RedactPlaceholder: the string used to replace detected secrets during
// clipboard redaction (both explicit `scrub`/`redact` and auto-redact in monitor).
// Defaults to "[REDACTED]". Can be set independently of pillar3 for clipboard
// hygiene preferences.
type Pillar5Config struct {
	Enabled bool `yaml:"enabled"`

	RedactTimeoutSeconds    int `yaml:"redact_timeout_seconds,omitempty"`
	FullClearTimeoutSeconds int `yaml:"full_clear_timeout_seconds,omitempty"`

	// RedactPlaceholder is the user's preferred placeholder for redacting
	// secrets in clipboard content. Falls back to pillar3.redact_placeholder
	// or the hard default if not set.
	RedactPlaceholder string `yaml:"redact_placeholder,omitempty"`

	// Monitor controls the background watcher that enables reactive alerts
	// and the two-tier auto actions. When false the explicit primitives
	// (check, scrub, redact, clear) still work via `blastradius clipboard` commands.
	// The pillar-level Enabled above is the master switch for the whole feature.
	MonitorEnabled bool `yaml:"monitor_enabled,omitempty"`

	// AlertsEnabled controls whether the monitor fires user-visible alerts
	// (notification / sound) on secret detection. The monitor still updates
	// status even if alerts are off.
	AlertsEnabled bool `yaml:"alerts_enabled,omitempty"`
}

// Pillar3Config holds settings for Pillar 3 (History Hygiene).
// Mode controls redaction strategy: "delete" (remove entire history entry, current default)
// or "redact" (replace detected secret values in-place with the placeholder, preserving
// command shape, timestamps in extended zsh format, etc.).
// HistoryFiles allows fully explicit additional paths (all of them are now processed).
// HistoryRoots allows additional base directories that will be searched for the
// built-in LCD history names plus their common rotated/backup siblings
// (.bash_history.1, *.old, *.bak, etc.). This is the primary mechanism for
// covering containers, secondary homes, and other restorable locations without
// listing every file. Defaults to the current user's home.
type Pillar3Config struct {
	Enabled           bool     `yaml:"enabled"`
	Mode              string   `yaml:"mode"`                         // "delete" | "redact"
	RedactPlaceholder string   `yaml:"redact_placeholder,omitempty"` // e.g. "[REDACTED]"
	HistoryFiles      []string `yaml:"history_files,omitempty"`      // explicit paths (all processed)
	HistoryRoots      []string `yaml:"history_roots,omitempty"`      // additional search bases for LCD + auto-rotated
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
// under pillar1.sources.env.options. This is the single source of truth for
// P1 discovery settings (project roots, skip/ignore lists, and env_file_patterns
// which declares P1 authority over matching files).
//
// EnvFilePatterns is the positive list of file globs (e.g. ".env*", ".env.local",
// ".private", ".secret", ".pk", ".cert") that this source claims as its authoritative
// on-disk secret containers. This is the declaration of "P1 authority".
// When empty after normalization, the conventional default [".env*"] is used.
type EnvOptions struct {
	ProjectRoots    []string `json:"project_roots,omitempty"`
	SkipDirs        []string `json:"skip_dirs,omitempty"`
	IgnoreFiles     []string `json:"ignore_files,omitempty"`
	IgnorePatterns  []string `json:"ignore_patterns,omitempty"`
	EnvFilePatterns []string `json:"env_file_patterns,omitempty"`
}

// BitwardenOptions holds configuration specific to the "bitwarden" logical source.
type BitwardenOptions struct {
	IgnorePatterns []string `json:"ignore_patterns,omitempty"`
	// Future fields (session handling hints, folder filters, etc.) can be added here.
}

// DefaultConfig returns a safe default configuration.
//
// All defaults live under the pillarN: sections. The supported shape matches
// config.example.yaml. Universal safe lists are defined in defaults.go so they
// stay in sync between DefaultConfig() and other consumers.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()

	return &Config{
		LogLevel: "info",
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"project_roots":   []string{home},
						"skip_dirs":       DefaultSkipDirs,
						"ignore_files":    DefaultIgnoreFiles,
						"ignore_patterns": DefaultIgnorePatterns,
					},
				},
				"bitwarden": {
					Enabled: false,
					Options: map[string]any{},
				},
			},
		},
		Pillar2: Pillar2Config{
			Enabled: false,
			Dirs:    DefaultPillar2Dirs,
		},
		Pillar3: Pillar3Config{
			Enabled:           false,
			Mode:              "delete",
			RedactPlaceholder: "[REDACTED]",
			HistoryFiles:      nil,
			HistoryRoots:      nil,
		},
		Pillar4: Pillar4Config{
			Enabled: false,
			Commands: []RuntimeCommand{
				{Name: "default-env", Cmd: "printenv", Enabled: true},
			},
		},
		Pillar5: Pillar5Config{
			Enabled:                 false,
			RedactTimeoutSeconds:    30,
			FullClearTimeoutSeconds: 60,
			RedactPlaceholder:       "[REDACTED]",
			MonitorEnabled:          false,
			AlertsEnabled:           false,
		},
	}
}

// See normalize.go for the normalization helpers and EffectiveRedactPlaceholder.

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
// pillar1.sources.env.options (the single source of truth for env source settings).
func (c *Config) GetEnvOptions() EnvOptions {
	if c == nil {
		return EnvOptions{
			ProjectRoots:    []string{},
			SkipDirs:        []string{},
			IgnoreFiles:     []string{},
			IgnorePatterns:  []string{},
			EnvFilePatterns: []string{},
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
			opts.EnvFilePatterns = normalizeStringList(envSrc.Options["env_file_patterns"])
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
	if opts.EnvFilePatterns == nil {
		opts.EnvFilePatterns = []string{}
	}

	return opts
}
