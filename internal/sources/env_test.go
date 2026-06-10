package sources

import (
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestEnvCollector_Enabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name: "env disabled",
			cfg: &config.Config{
				Pillar1: config.Pillar1Config{
					Sources: map[string]config.SourceConfig{
						"env": {Enabled: false},
					},
				},
			},
			expected: false,
		},
		{
			name: "env enabled",
			cfg: &config.Config{
				Pillar1: config.Pillar1Config{
					Sources: map[string]config.SourceConfig{
						"env": {Enabled: true},
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewEnvCollector(tc.cfg)
			if got := c.Enabled(); got != tc.expected {
				t.Errorf("Enabled() = %v, want %v", got, tc.expected)
			}
			if c.Name() != "env" {
				t.Errorf("Name() = %q, want %q", c.Name(), "env")
			}
		})
	}
}

func TestEnvCollector_GetIgnorePatterns(t *testing.T) {
	cfg := &config.Config{
		Pillar1: config.Pillar1Config{
			Sources: map[string]config.SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"ignore_patterns": []string{"PATH", "LOG_*"},
					},
				},
			},
		},
	}

	c := NewEnvCollector(cfg)
	pats := c.GetIgnorePatterns()
	if len(pats) != 2 || pats[0] != "PATH" {
		t.Errorf("GetIgnorePatterns() = %v, want [PATH LOG_*]", pats)
	}
}

func TestEnvCollector_Validate(t *testing.T) {
	t.Run("nil cfg", func(t *testing.T) {
		c := NewEnvCollector(nil)
		if err := c.Validate(); err == nil {
			t.Error("expected error for nil cfg in Validate")
		}
	})

	t.Run("disabled source", func(t *testing.T) {
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {Enabled: false},
				},
			},
		}
		c := NewEnvCollector(cfg)
		if err := c.Validate(); err == nil {
			t.Error("expected error when env source is disabled")
		}
	})

	t.Run("no project roots configured", func(t *testing.T) {
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{"project_roots": []string{}},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		// Current behavior falls back to ~, which should usually exist in tests.
		// This test mainly ensures we don't panic and the flow is exercised.
		_ = c.Validate()
	})

	t.Run("nonexistent root", func(t *testing.T) {
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{"project_roots": []string{"/this/path/does/not/exist/for/sure/12345"}},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		if err := c.Validate(); err == nil {
			t.Error("expected error for nonexistent project root")
		}
	})

	t.Run("tilde expansion in roots (exercises expandForValidation)", func(t *testing.T) {
		t.Setenv("HOME", "/tmp/fakehome-for-env-test")
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{
							"project_roots": []string{"~/nonexistent/12345"},
						},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		// Will fail on stat of expanded path (good, we just want the expand path executed)
		if err := c.Validate(); err == nil {
			t.Error("expected error for expanded nonexistent ~ root")
		}
	})

	t.Run("root exists but cannot access (non-NotExist err, e.g. not-a-directory)", func(t *testing.T) {
		// Use a path under a file (/dev/null) so os.Stat reliably fails with a non-IsNotExist error
		// (e.g. "not a directory"). This hits the "cannot access configured project root" return
		// without relying on chown/perm bits (owner can often still stat 000 dirs on macOS).
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{"project_roots": []string{"/dev/null/this-will-stat-fail-12345"}},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		err := c.Validate()
		if err == nil {
			t.Error("expected error for inaccessible project root")
		}
		// Distinguish from the "does not exist" message to ensure the !IsNotExist path.
		if err != nil && (strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "configured project root does not exist")) {
			t.Errorf("got 'does not exist' error, wanted 'cannot access': %v", err)
		}
	})

	t.Run("success - valid existing project root", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{
							"project_roots": []string{tmpDir},
						},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error for valid root: %v", err)
		}
	})

	t.Run("success - tilde-expanded root exists (exercises expandForValidation happy path)", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)

		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Enabled: true,
						Options: map[string]any{
							"project_roots": []string{"~/"},
						},
					},
				},
			},
		}
		c := NewEnvCollector(cfg)
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error for ~/ root: %v", err)
		}
	})
}

func TestEnvCollector_Collect(t *testing.T) {
	c := NewEnvCollector(&config.Config{})

	// No scan func set
	hashes, err := c.Collect()
	if err != nil || hashes != nil {
		t.Errorf("expected nil, nil when no scanFunc, got %v, %v", hashes, err)
	}

	// With scan func
	expected := []registry.SecretHash{{1, 2, 3}}
	c.SetScanFunc(func() ([]registry.SecretHash, error) {
		return expected, nil
	})

	hashes, err = c.Collect()
	if err != nil || len(hashes) != 1 {
		t.Errorf("expected 1 hash from scanFunc, got %v, %v", hashes, err)
	}
}

func TestEnvCollector_GetIgnorePatterns_NilConfig(t *testing.T) {
	c := NewEnvCollector(nil)
	if pats := c.GetIgnorePatterns(); pats != nil {
		t.Errorf("expected nil for nil config, got %v", pats)
	}
}

func TestScanStats_Struct(t *testing.T) {
	// Just to get some coverage on the otherwise unused ScanStats type.
	s := ScanStats{
		Source:    "env",
		Hashes:    42,
		Duration:  123,
		Error:     "",
		Timestamp: time.Now(),
	}
	if s.Source != "env" || s.Hashes != 42 {
		t.Error("ScanStats did not store values correctly")
	}
}
