package sources

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

	// nil cfg path (was partial)
	if NewBitwardenCollector(nil).Enabled() {
		t.Error("nil cfg should be disabled")
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

	t.Run("nil cfg", func(t *testing.T) {
		c := NewBitwardenCollector(nil)
		if err := c.Validate(); err == nil {
			t.Error("expected error for nil cfg in Validate")
		}
	})

	t.Run("bw binary missing", func(t *testing.T) {
		// Guarantee LookPath("bw") fails hermetically regardless of test env PATH
		// (coverage collection envs may have bw; previous test was env-dependent).
		t.Setenv("PATH", "/no/such/bw/dir/ever")

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

		err := c.Validate()
		if err == nil {
			t.Error("expected error when bw is missing")
		}
	})

	t.Run("bw present (fake in PATH) but status exec fails (covers comms err after LookPath)", func(t *testing.T) {
		// Create a temp dir with a fake "bw" executable so real exec.LookPath("bw") succeeds.
		// We still override execBw var, so the fake is never executed; it only satisfies LookPath.
		tmp := t.TempDir()
		fake := filepath.Join(tmp, "bw")
		_ = os.WriteFile(fake, []byte("#!/bin/sh\nexit 0"), 0755)
		origPath := os.Getenv("PATH")
		t.Setenv("PATH", tmp+":"+origPath)

		planted := "BW_STATUS_LEAKED_TOKEN_1234567890ABCDEF"
		execBw = func(args ...string) ([]byte, error) {
			if args[0] == "status" {
				return []byte(`{"status":"unlocked","user":"` + planted + `"}`), errors.New("simulated bw status comms failure")
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
			t.Error("expected comms error from status call")
		}
		if err != nil && strings.Contains(err.Error(), planted) {
			t.Errorf("regression: sensitive data from bw status output leaked into Validate error: %v", err)
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
				{"fields": [{"value": "customfieldsecret"}]},
				{"password": "top-level-pw-secret-9876543210"}
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
	if len(hashes) < 4 {
		t.Errorf("expected at least 4 hashes from sample Bitwarden data (incl top-level pw), got %d", len(hashes))
	}
}

func TestBitwardenCollector_Collect_Error(t *testing.T) {
	orig := execBw
	defer func() { execBw = orig }()

	// Simulate a failing bw that returns output containing a secret value (as real
	// CombinedOutput does on non-zero exit). The collector must *never* put that
	// raw output (or the secret) into the error returned to callers / rescan results / logs.
	plantedSecret := "BW_SECRET_ABCDEF1234567890HIGHENTROPYVALUE"
	execBw = func(args ...string) ([]byte, error) {
		output := []byte(`{"items":[{"login":{"password":"` + plantedSecret + `"}}]}`)
		return output, errors.New("boom")
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
	if err != nil && strings.Contains(err.Error(), plantedSecret) {
		t.Errorf("regression: secret value from bw failure output leaked into Collect error: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "output:") {
		t.Errorf("regression: raw bw output leaked into Collect error (should be sanitized): %v", err)
	}
}

func TestBitwardenCollector_Collect_UnmarshalError(t *testing.T) {
	orig := execBw
	defer func() { execBw = orig }()

	execBw = func(args ...string) ([]byte, error) {
		if args[0] == "list" && args[1] == "items" {
			return []byte(`this is not valid json [[[`), nil
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

	_, err := c.Collect()
	if err == nil {
		t.Error("expected unmarshal error from Collect when bw list returns non-JSON")
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

	// nil cfg path for getIgnorePatterns (66% partial)
	if got := NewBitwardenCollector(nil).getIgnorePatterns(); got != nil {
		t.Errorf("nil getIgnorePatterns = %v want nil", got)
	}
}

func TestShouldIgnoreValue_Basic(t *testing.T) {
	patterns := []string{"secret"}
	if !shouldIgnoreValue("mysecretvalue", patterns) {
		t.Error("expected to match simple substring")
	}
}
