package sources

import (
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
			ProjectRoots: []string{},
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {Enabled: true},
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
			ProjectRoots: []string{"/this/path/does/not/exist/for/sure/12345"},
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {Enabled: true},
				},
			},
		}
		c := NewEnvCollector(cfg)
		if err := c.Validate(); err == nil {
			t.Error("expected error for nonexistent project root")
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
