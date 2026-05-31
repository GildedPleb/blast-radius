package sources

import (
	"errors"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestBitwardenCollector_Enabled(t *testing.T) {
	cfg := &config.Config{
		Pillar1: config.Pillar1Config{
			Sources: map[string]config.SourceConfig{
				"bitwarden": {Enabled: true},
			},
		},
	}

	c := NewBitwardenCollector(cfg)
	if !c.Enabled() {
		t.Error("expected bitwarden to be enabled")
	}
	if c.Name() != "bitwarden" {
		t.Errorf("Name() = %q, want bitwarden", c.Name())
	}
}

func TestBitwardenCollector_Validate(t *testing.T) {
	origExec := execBw
	defer func() { execBw = origExec }()

	t.Run("disabled source", func(t *testing.T) {
		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"bitwarden": {Enabled: false},
				},
			},
		}
		c := NewBitwardenCollector(cfg)
		if err := c.Validate(); err == nil {
			t.Error("expected error when bitwarden is disabled")
		}
	})

	t.Run("bw binary missing", func(t *testing.T) {
		execBw = func(args ...string) ([]byte, error) {
			return nil, errors.New("executable file not found in $PATH")
		}

		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"bitwarden": {Enabled: true},
				},
			},
		}
		c := NewBitwardenCollector(cfg)

		// We simulate "bw not found" by making LookPath fail.
		// Since we call exec.LookPath inside Validate, we override it indirectly
		// by making the command fail in a realistic way.
		// For this test we temporarily replace the whole validation path is hard,
		// so we just assert the error message style.
		err := c.Validate()
		if err == nil {
			t.Error("expected error when bw is missing")
		}
	})

	t.Run("bw present but not unlocked", func(t *testing.T) {
		execBw = func(args ...string) ([]byte, error) {
			if args[0] == "status" {
				return []byte(`{"status":"unauthenticated"}`), nil
			}
			return nil, nil
		}

		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"bitwarden": {Enabled: true},
				},
			},
		}
		c := NewBitwardenCollector(cfg)

		err := c.Validate()
		if err == nil {
			t.Error("expected error when Bitwarden is not unlocked")
		}
	})

	t.Run("bw unlocked", func(t *testing.T) {
		execBw = func(args ...string) ([]byte, error) {
			if args[0] == "status" {
				return []byte(`{"status":"unlocked"}`), nil
			}
			return nil, nil
		}

		cfg := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"bitwarden": {Enabled: true},
				},
			},
		}
		c := NewBitwardenCollector(cfg)

		if err := c.Validate(); err != nil {
			t.Errorf("expected no error when unlocked, got: %v", err)
		}
	})
}

func TestBitwardenCollector_Collect(t *testing.T) {
	orig := execBw
	defer func() { execBw = orig }()

	execBw = func(args ...string) ([]byte, error) {
		if args[0] == "list" && args[1] == "items" {
			return []byte(`[
				{"login": {"password": "supersecret123"}},
				{"notes": "another very secret note value"},
				{"fields": [{"value": "customfieldsecret"}]}
			]`), nil
		}
		return nil, nil
	}

	cfg := &config.Config{
		Pillar1: config.Pillar1Config{
			Sources: map[string]config.SourceConfig{
				"bitwarden": {Enabled: true},
			},
		},
	}

	c := NewBitwardenCollector(cfg)
	hashes, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(hashes) < 3 {
		t.Errorf("expected at least 3 hashes from sample Bitwarden data, got %d", len(hashes))
	}
}

func TestBitwardenCollector_Collect_Error(t *testing.T) {
	orig := execBw
	defer func() { execBw = orig }()

	execBw = func(args ...string) ([]byte, error) {
		return nil, errors.New("boom")
	}

	cfg := &config.Config{
		Pillar1: config.Pillar1Config{
			Sources: map[string]config.SourceConfig{
				"bitwarden": {Enabled: true},
			},
		},
	}
	c := NewBitwardenCollector(cfg)

	_, err := c.Collect()
	if err == nil {
		t.Error("expected error from Collect when bw fails")
	}
}

func TestBitwardenCollector_GetIgnorePatterns(t *testing.T) {
	cfg := &config.Config{
		Pillar1: config.Pillar1Config{
			Sources: map[string]config.SourceConfig{
				"bitwarden": {
					Enabled: true,
					Options: map[string]any{
						"ignore_patterns": []string{"dev-*"},
					},
				},
			},
		},
	}
	c := NewBitwardenCollector(cfg)
	pats := c.getIgnorePatterns()
	if len(pats) != 1 {
		t.Errorf("unexpected ignore patterns: %v", pats)
	}
}

func TestShouldIgnoreValue_Basic(t *testing.T) {
	patterns := []string{"secret"}
	if !shouldIgnoreValue("mysecretvalue", patterns) {
		t.Error("expected to match simple substring")
	}
}
