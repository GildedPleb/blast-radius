package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Pillar1.Sources) == 0 || len(cfg.Pillar4.Commands) == 0 {
		t.Error("defaults missing required pillar fields")
	}
	if cfg.Pillar4.Enabled {
		t.Error("pillar4 should be disabled by default")
	}
	if cfg.Pillar5.Enabled {
		t.Error("pillar5 should be disabled by default")
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

// GetEnvOptions tests cover the pillar1.sources.env.options shape (the current single source of truth).
// The single source of truth is pillar1.sources.env.options (see GetEnvOptions and AGENTS.md).

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
