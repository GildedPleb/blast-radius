package config

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// ValidateReadiness tests
//
// These were extracted from config_test.go so that validation logic
// (the declarative first-run / pillar readiness gates) has its own
// focused test file alongside validate.go.
// -----------------------------------------------------------------------------

func TestValidateReadiness_P1EmptyRootsFails(t *testing.T) {
	cfg := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {
					Enabled: true,
					Options: map[string]any{
						"project_roots": []string{},
					},
				},
			},
		},
	}
	err := ValidateReadiness("rescan", cfg)
	if err == nil {
		t.Error("expected error for empty project_roots on P1-needing command")
	}
	if !strings.Contains(err.Error(), "project_roots is empty") {
		t.Errorf("error should mention empty project_roots, got: %v", err)
	}
}

func TestValidateReadiness_P1CustomizedOrDisabledOK(t *testing.T) {
	// Customized (non-empty) roots → ready for P1 commands
	cfg1 := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{"~/real"}}},
			},
		},
	}
	if err := ValidateReadiness("rescan", cfg1); err != nil {
		t.Errorf("customized non-empty roots should be ready: %v", err)
	}

	// Explicitly disabled env source (even if it still has example data in the YAML)
	// is a substantive user choice. bw-only or "P1 intentionally off" is supported.
	cfg2 := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env":       {Enabled: false, Options: map[string]any{"project_roots": []string{"~/projects", "~/work"}}},
				"bitwarden": {Enabled: true, Options: map[string]any{}},
			},
		},
	}
	if err := ValidateReadiness("duplicates", cfg2); err != nil {
		t.Errorf("disabled env + enabled bw should be ready for P1 cmd: %v", err)
	}

	// Empty list + env enabled is the "not yet configured" case (see previous test).
	// Non-empty is what makes it substantive.
}

func TestValidateReadiness_ValidateCmdAndLenientCmds(t *testing.T) {
	// "Virgin" for P1 now means: env enabled + empty project_roots (what the initial template writes).
	virgin := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{}}},
			},
		},
	}
	// Full validate should surface error for the incomplete P1 data.
	if err := ValidateReadiness("validate", virgin); err == nil {
		t.Error("validate cmd on incomplete P1 (empty roots) should surface error")
	}

	// Lenient commands never gate on readiness.
	if err := ValidateReadiness("help", virgin); err != nil {
		t.Error("help should be lenient")
	}
	if err := ValidateReadiness("config", virgin); err != nil {
		t.Error("config should be lenient")
	}
	if err := ValidateReadiness("logs", virgin); err != nil {
		t.Error("logs should be lenient")
	}
}

// -----------------------------------------------------------------------------
// Additional low-hanging coverage for validate.go
// -----------------------------------------------------------------------------

func TestValidateReadiness_NilConfig(t *testing.T) {
	err := ValidateReadiness("rescan", nil)
	if err == nil || !strings.Contains(err.Error(), "no configuration loaded") {
		t.Errorf(`expected error containing "no configuration loaded", got: %v`, err)
	}
}

func TestValidateReadiness_UnknownOrLenientCommand(t *testing.T) {
	cfg := &Config{} // minimal; lenient path ignores content
	for _, cmd := range []string{"", "help", "config", "logs", "stop", "halt", "foo", "unknown-cmd"} {
		if err := ValidateReadiness(cmd, cfg); err != nil {
			t.Errorf("command %q should be lenient (return nil), got: %v", cmd, err)
		}
	}
}

func TestValidateReadiness_P2Disabled(t *testing.T) {
	cfg := &Config{
		Pillar2: Pillar2Config{Enabled: false},
	}
	err := ValidateReadiness("crumbs", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 2 (crumbs) is disabled") {
		t.Errorf("expected Pillar 2 disabled error for 'crumbs', got: %v", err)
	}

	// Full validate should also surface it (first failing pillar)
	err = ValidateReadiness("validate", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 2 (crumbs) is disabled") {
		t.Errorf("validate should surface p2 disabled error, got: %v", err)
	}
}

func TestValidateReadiness_P3Disabled(t *testing.T) {
	cfg := &Config{Pillar3: Pillar3Config{Enabled: false}}

	err := ValidateReadiness("scrub-history", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 3 (history hygiene) is disabled") {
		t.Errorf("expected p3 disabled error, got: %v", err)
	}

	err = ValidateReadiness("scrub_history", cfg) // alias
	if err == nil || !strings.Contains(err.Error(), "Pillar 3 (history hygiene) is disabled") {
		t.Errorf("scrub_history alias should trigger same error, got: %v", err)
	}
}

func TestValidateReadiness_P5Disabled(t *testing.T) {
	cfg := &Config{Pillar5: Pillar5Config{Enabled: false}}

	err := ValidateReadiness("clipboard", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 5 (clipboard hygiene) is disabled") {
		t.Errorf("expected p5 disabled error, got: %v", err)
	}
}

func TestValidateReadiness_InitAndStarBehaveLikeValidate(t *testing.T) {
	virgin := &Config{
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{}}},
			},
		},
	}

	if err := ValidateReadiness("init", virgin); err == nil {
		t.Error("'init' should require full pillar readiness like 'validate'")
	}
	if err := ValidateReadiness("*", virgin); err == nil {
		t.Error("'*' should require full pillar readiness like 'validate'")
	}
}

func TestValidateReadiness_P4Disabled(t *testing.T) {
	// p4 has no dedicated single-pillar command, so we test it via "validate"/"init".
	// We must make p1 + p2 + p3 + p5 ready, otherwise we hit an earlier pillar's error.
	cfg := &Config{
		Pillar4: Pillar4Config{Enabled: false},
		// p1 ready
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{"/tmp"}}},
			},
		},
		// p2/p3/p5 ready (so we actually reach the p4 check)
		Pillar2: Pillar2Config{Enabled: true},
		Pillar3: Pillar3Config{Enabled: true},
		Pillar5: Pillar5Config{Enabled: true},
	}

	err := ValidateReadiness("validate", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 4 is disabled in config") {
		t.Errorf("expected p4 disabled error via validate, got: %v", err)
	}

	err = ValidateReadiness("init", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 4 is disabled in config") {
		t.Errorf("init should also require p4, got: %v", err)
	}
}

func TestValidateReadiness_P4EnabledButNoUsableCommands(t *testing.T) {
	// Same pattern: make other pillars ready so we reach the p4 "no usable commands" check
	cfg := &Config{
		Pillar4: Pillar4Config{
			Enabled:  true,
			Commands: nil, // hits !hasUsable
		},
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{"/tmp"}}},
			},
		},
		Pillar2: Pillar2Config{Enabled: true},
		Pillar3: Pillar3Config{Enabled: true},
		Pillar5: Pillar5Config{Enabled: true},
	}

	err := ValidateReadiness("validate", cfg)
	if err == nil || !strings.Contains(err.Error(), "Pillar 4 is enabled but has no usable commands") {
		t.Errorf("expected p4 'no usable commands' error, got: %v", err)
	}
}

func TestValidateReadiness_P4EnabledWithCommandOK(t *testing.T) {
	cfg := &Config{
		Pillar4: Pillar4Config{
			Enabled:  true,
			Commands: []RuntimeCommand{{Cmd: "printenv"}},
		},
		// Make all other pillars ready so validate only exercises the p4 happy path
		Pillar1: Pillar1Config{
			Sources: map[string]SourceConfig{
				"env": {Enabled: true, Options: map[string]any{"project_roots": []string{"/tmp"}}},
			},
		},
		Pillar2: Pillar2Config{Enabled: true},
		Pillar3: Pillar3Config{Enabled: true},
		Pillar5: Pillar5Config{Enabled: true},
	}

	if err := ValidateReadiness("validate", cfg); err != nil {
		t.Errorf("p4 enabled + has usable command should allow validate to pass: %v", err)
	}
}

func TestCheckPillarReadiness_UnknownPillar(t *testing.T) {
	// This hits the final `return nil` after the switch in checkPillarReadiness
	// (defensive path for an unexpected pillar name).
	cfg := &Config{}
	if err := checkPillarReadiness("p99", cfg, "validate"); err != nil {
		t.Errorf("unknown pillar name should return nil, got: %v", err)
	}
}
