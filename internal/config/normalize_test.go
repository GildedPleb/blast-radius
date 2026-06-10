package config

import "testing"

func TestNormalizePillar1Sources_NilAndMissingSources(t *testing.T) {
	// nil map case
	cfg := &Config{Pillar1: Pillar1Config{Sources: nil}}
	normalizePillar1Sources(cfg)
	if cfg.Pillar1.Sources == nil {
		t.Fatal("normalize should have created Sources map")
	}
	if _, ok := cfg.Pillar1.Sources["env"]; !ok {
		t.Error("env entry should be created for nil starting map")
	}

	// missing one source (e.g. only bitwarden present)
	cfg2 := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"bitwarden": {Enabled: true, Options: map[string]any{}},
			},
		},
	}
	normalizePillar1Sources(cfg2)
	if _, ok := cfg2.Pillar1.Sources["env"]; !ok {
		t.Error("env should be created when missing")
	}
	if !cfg2.Pillar1.Sources["bitwarden"].Enabled {
		t.Error("existing bitwarden entry preserved")
	}
	// Options normalized to non-nil even for created
	if cfg2.Pillar1.Sources["env"].Options == nil {
		t.Error("created env should have non-nil Options")
	}
}

func TestNormalizePillar3(t *testing.T) {
	// nil config
	normalizePillar3(nil)

	// disabled + no mode → should default mode
	cfg := &Config{Pillar3: Pillar3Config{Enabled: false}}
	normalizePillar3(cfg)
	if cfg.Pillar3.Mode != "delete" {
		t.Errorf("disabled empty mode: got %q", cfg.Pillar3.Mode)
	}

	// enabled + invalid mode → reset to delete
	cfg = &Config{Pillar3: Pillar3Config{Enabled: true, Mode: "banana"}}
	normalizePillar3(cfg)
	if cfg.Pillar3.Mode != "delete" {
		t.Error("invalid mode should become delete")
	}

	// enabled + empty placeholder + nil HistoryFiles + nil HistoryRoots
	// (we no longer force non-nil; discovery + docs treat nil as "use $HOME only")
	cfg = &Config{Pillar3: Pillar3Config{Enabled: true, Mode: "redact"}}
	normalizePillar3(cfg)
	if cfg.Pillar3.RedactPlaceholder != "[REDACTED]" {
		t.Error("empty placeholder should be defaulted")
	}
	if cfg.Pillar3.HistoryFiles != nil {
		t.Error("HistoryFiles should remain nil (discovery treats nil/empty equivalently)")
	}
	if cfg.Pillar3.HistoryRoots != nil {
		t.Error("HistoryRoots should remain nil (discovery treats nil/empty equivalently)")
	}

	// fully valid config should be left alone (including HistoryRoots)
	cfg = &Config{Pillar3: Pillar3Config{
		Enabled:           true,
		Mode:              "redact",
		RedactPlaceholder: "***",
		HistoryFiles:      []string{"/custom/hist"},
		HistoryRoots:      []string{"/other/home"},
	}}
	normalizePillar3(cfg)
	if cfg.Pillar3.RedactPlaceholder != "***" || len(cfg.Pillar3.HistoryFiles) != 1 || len(cfg.Pillar3.HistoryRoots) != 1 {
		t.Error("valid config was mutated")
	}
}

func TestNormalizeStringList_AllArms(t *testing.T) {
	if got := normalizeStringList(nil); len(got) != 0 {
		t.Errorf("nil -> %v", got)
	}
	if got := normalizeStringList([]string{"a", "b"}); len(got) != 2 || got[0] != "a" {
		t.Errorf("[]string -> %v", got)
	}
	if got := normalizeStringList([]any{"x", 123, "y"}); len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf("[]any mixed -> %v", got)
	}
	if got := normalizeStringList("single"); len(got) != 1 || got[0] != "single" {
		t.Errorf("string -> %v", got)
	}
	if got := normalizeStringList(""); len(got) != 0 {
		t.Errorf("empty string -> %v", got)
	}
	if got := normalizeStringList(42); len(got) != 0 {
		t.Errorf("other type -> %v", got)
	}
}

func TestEffectiveRedactPlaceholder(t *testing.T) {
	cases := []struct {
		name     string
		p5, p3   string
		fallback string
		want     string
	}{
		{"p5 wins", "[P5]", "[P3]", "[DEF]", "[P5]"},
		{"p3 fallback when p5 empty", "", "[P3]", "[DEF]", "[P3]"},
		{"default when both empty", "", "", "[DEF]", "[DEF]"},
		{"hard default when all empty", "", "", "", "[REDACTED]"},
		{"p5 explicit empty string still falls to p3", "", "[P3]", "[DEF]", "[P3]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EffectiveRedactPlaceholder(c.p5, c.p3, c.fallback); got != c.want {
				t.Errorf("EffectiveRedactPlaceholder(%q,%q,%q) = %q, want %q", c.p5, c.p3, c.fallback, got, c.want)
			}
		})
	}
}

// TestNormalizePillar4 exercises the nil-Commands initialization path
// (previously showing 0 coverage on the assignment inside the if).
// The function intentionally does nothing when Commands is already non-nil
// (even if empty), consistent with "only fix what YAML left broken".
func TestNormalizePillar4(t *testing.T) {
	// Zero-value / fresh Config → Pillar4.Commands is nil (Go zero value)
	cfg := &Config{}
	normalizePillar4(cfg)
	if cfg.Pillar4.Commands == nil {
		t.Fatal("normalizePillar4 should have initialized Commands to a non-nil slice")
	}
	if len(cfg.Pillar4.Commands) != 0 {
		t.Errorf("expected empty Commands slice after normalization, got len=%d", len(cfg.Pillar4.Commands))
	}

	// Already non-nil (populated) → must be left exactly as-is
	existing := []RuntimeCommand{
		{Name: "check-env", Cmd: "printenv", Enabled: true},
	}
	cfg2 := &Config{
		Pillar4: Pillar4Config{
			Enabled:  true,
			Commands: existing,
		},
	}
	normalizePillar4(cfg2)
	if len(cfg2.Pillar4.Commands) != 1 || cfg2.Pillar4.Commands[0].Name != "check-env" {
		t.Error("normalizePillar4 must not touch an already-populated Commands slice")
	}
}
