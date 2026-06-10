package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// runValidateAndCapture redirects stdout/stderr for the duration of RunValidate
// so we can assert on emitted messages without polluting test output.
// It restores originals via defer. osExit is already no-op from resetTestOverrides.
func runValidateAndCapture(t *testing.T, tail []string) (stdout, stderr string) {
	t.Helper()

	oldOut := os.Stdout
	oldErr := os.Stderr
	defer func() {
		os.Stdout = oldOut
		os.Stderr = oldErr
	}()

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	RunValidate(tail)

	_ = wOut.Close()
	_ = wErr.Close()

	var bufOut, bufErr bytes.Buffer
	_, _ = io.Copy(&bufOut, rOut)
	_, _ = io.Copy(&bufErr, rErr)
	return bufOut.String(), bufErr.String()
}

// newTestConfig returns a fresh copy of the hermetic default used by resetTestOverrides.
func newTestConfig() config.Config {
	return defaultTestConfig()
}

// configWithP1EnvEmptyRoots returns cfg where env source is explicitly enabled
// but project_roots will be empty (triggers the ACTION REQUIRED + issues++ path).
func configWithP1EnvEmptyRoots() config.Config {
	c := newTestConfig()
	if c.Pillar1.Sources == nil {
		c.Pillar1.Sources = make(map[string]config.SourceConfig)
	}
	c.Pillar1.Sources["env"] = config.SourceConfig{Enabled: true}
	// If GetEnvOptions() internally reads from Sources["env"].Options (map or struct),
	// it will still see empty roots here -> issues path. Adjust Options if your
	// GetEnvOptions implementation requires it for the positive-roots test below.
	return c
}

// configWithP1EnvAndRoots returns cfg exercising the happy "X project root(s) configured" branch.
func configWithP1EnvAndRoots() config.Config {
	c := newTestConfig()
	if c.Pillar1.Sources == nil {
		c.Pillar1.Sources = make(map[string]config.SourceConfig)
	}
	c.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		// Provide Options in the shape your GetEnvOptions expects (common patterns:
		// map[string]any{"project_roots": []any{"/real/proj", "/another"}} or a typed struct).
		// If GetEnvOptions always returns empty for unit tests, the len>0 branch
		// may need a GetEnvOptions seam or real toml roundtrip in integration test.
		Options: map[string]any{
			"project_roots": []any{"/home/user/src", "/work/project"},
		},
	}
	return c
}

// configWithBitwardenEnabled exercises the bitwarden "enabled" print (no issues impact).
func configWithBitwardenEnabled() config.Config {
	c := newTestConfig()
	if c.Pillar1.Sources == nil {
		c.Pillar1.Sources = make(map[string]config.SourceConfig)
	}
	c.Pillar1.Sources["bitwarden"] = config.SourceConfig{Enabled: true}
	return c
}

// configWithP2Enabled exercises Pillar2 enabled branch.
func configWithP2Enabled() config.Config {
	c := newTestConfig()
	c.Pillar2.Enabled = true
	return c
}

// configWithP3Enabled exercises Pillar3 enabled + mode print.
func configWithP3Enabled() config.Config {
	c := newTestConfig()
	c.Pillar3.Enabled = true
	c.Pillar3.Mode = "scrub"
	return c
}

// configWithP4Disabled exercises the P4 disabled message.
func configWithP4Disabled() config.Config {
	c := newTestConfig()
	c.Pillar4.Enabled = false
	return c
}

// configWithP5Disabled exercises the P5 disabled (long) message.
func configWithP5Disabled() config.Config {
	c := newTestConfig()
	c.Pillar5.Enabled = false
	return c
}

func TestRunValidate(t *testing.T) {
	t.Run("default_hermetic_config_issues0_success_footer_P4_P5_enabled_others_disabled", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }

		out, errOut := runValidateAndCapture(t, nil)

		if !strings.Contains(out, "Blast Radius — Configuration Validation (all pillars)") {
			t.Errorf("missing header in output:\n%s", out)
		}
		if !strings.Contains(out, "Pillar 1 (env): disabled (or not explicitly enabled)") {
			t.Error("P1 env disabled branch not taken")
		}
		if !strings.Contains(out, "Pillar 2 (crumbs): disabled in initial template") {
			t.Error("P2 disabled branch not taken")
		}
		if !strings.Contains(out, "Pillar 3 (history): disabled in initial template") {
			t.Error("P3 disabled branch not taken")
		}
		if !strings.Contains(out, "Pillar 4 (env): enabled, 0 command(s) configured.") {
			t.Error("P4 enabled (0 cmds) branch not taken")
		}
		if !strings.Contains(out, "Pillar 5 (clipboard): enabled, monitor=false, alerts=false.") {
			t.Error("P5 enabled branch not taken")
		}
		if strings.Contains(errOut, "Warning") || strings.Contains(errOut, "Failed") {
			t.Errorf("unexpected stderr: %s", errOut)
		}
		if strings.Contains(out, "ACTION REQUIRED") || strings.Contains(out, "Some pillars still have virgin") {
			t.Error("issues>0 path incorrectly taken on default config")
		}
		if !strings.Contains(out, "All checked pillars have substantive content or are deliberately disabled.") {
			t.Error("success footer missing")
		}
		if !strings.Contains(out, "You can now use the commands whose pillars you have configured.") {
			t.Error("final usage hint missing")
		}
	})

	t.Run("ensureConfig_created_true_prints_created_msg", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		ensureConfig = func() (string, bool, error) {
			return "/tmp/blast-radius-config.toml", true, nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Created initial config template at /tmp/blast-radius-config.toml") {
			t.Errorf("created message not printed:\n%s", out)
		}
	})

	t.Run("ensureConfig_not_created_but_p_nonempty_prints_Config_path", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		ensureConfig = func() (string, bool, error) {
			return "/home/gildedpleb/.config/blast-radius/config.toml", false, nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Config: /home/gildedpleb/.config/blast-radius/config.toml") {
			t.Errorf("config path message not printed:\n%s", out)
		}
	})

	t.Run("configLoad_returns_error_with_nil_cfg_prints_warning_but_still_success_footer", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			return nil, "", fmt.Errorf("toml parse error at line 42")
		}

		out, errOut := runValidateAndCapture(t, nil)
		if !strings.Contains(errOut, "Warning: config load error: toml parse error at line 42") {
			t.Errorf("load error warning missing in stderr:\n%s", errOut)
		}
		// cfg==nil so no pillar lines, but code still reaches success path
		if !strings.Contains(out, "All checked pillars have substantive content or are deliberately disabled.") {
			t.Error("success footer should still print after load warning")
		}
	})

	t.Run("configLoad_returns_error_but_non_nil_cfg_still_reports_available_pillars", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		cfgWithP4 := newTestConfig()
		cfgWithP4.Pillar4.Enabled = true
		configLoad = func() (*config.Config, string, error) {
			return &cfgWithP4, "", fmt.Errorf("partial load")
		}

		out, errOut := runValidateAndCapture(t, nil)
		if !strings.Contains(errOut, "Warning: config load error: partial load") {
			t.Error("warning should be emitted even with partial cfg")
		}
		if !strings.Contains(out, "Pillar 4 (env): enabled, 0 command(s) configured.") {
			t.Error("pillar report should still happen for non-nil cfg returned with err")
		}
	})

	t.Run("reset_flag_success_calls_removeConfigFile_prints_reset_msg_then_full_report", func(t *testing.T) {
		resetTestOverrides(t)
		called := false
		removeConfigFile = func() error {
			called = true
			return nil
		}

		out, _ := runValidateAndCapture(t, []string{"--reset"})
		if !called {
			t.Error("removeConfigFile was not invoked for --reset")
		}
		if !strings.Contains(out, "Config reset. A fresh initial template will be created on next command.") {
			t.Error("reset success message missing")
		}
		if !strings.Contains(out, "Blast Radius — Configuration Validation (all pillars)") {
			t.Error("validation report should still run after successful reset")
		}
	})

	t.Run("reset_flag_error_path_prints_to_stderr_calls_osExit1_and_returns_early_no_report", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error {
			return fmt.Errorf("permission denied on ~/.config/blast-radius/config.toml")
		}

		out, errOut := runValidateAndCapture(t, []string{"--reset"})
		if !strings.Contains(errOut, "Failed to reset config: permission denied on ~/.config/blast-radius/config.toml") {
			t.Errorf("reset error message missing:\n%s", errOut)
		}
		if strings.Contains(out, "Blast Radius — Configuration Validation") {
			t.Error("should not have printed validation header after reset error (early return)")
		}
	})

	t.Run("P1_env_enabled_empty_roots_triggers_issues_ACTION_and_fail_footer_osExit1", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP1EnvEmptyRoots()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 1 (env): ACTION REQUIRED — project_roots is empty.") {
			t.Error("ACTION REQUIRED for empty project_roots not printed")
		}
		if !strings.Contains(out, "Edit pillar1.sources.env.options.project_roots and add real directories.") {
			t.Error("guidance for fixing project_roots missing")
		}
		if !strings.Contains(out, "Some pillars still have virgin template data for sections they expose.") {
			t.Error("issues>0 summary message missing")
		}
		if !strings.Contains(out, "Fix the items above, then re-run 'blastradius validate'") {
			t.Error("re-run hint for issues path missing")
		}
	})

	t.Run("P1_env_enabled_with_roots_prints_count_no_issues", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP1EnvAndRoots()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 1 (env): 2 project root(s) configured.") {
			t.Errorf("happy path count for project_roots not printed (check GetEnvOptions impl vs Options shape):\n%s", out)
		}
		if strings.Contains(out, "ACTION REQUIRED") {
			t.Error("should not be in issues path when roots provided")
		}
	})

	t.Run("P1_bitwarden_enabled_prints_runtime_check_note", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithBitwardenEnabled()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 1 (bitwarden): enabled — runtime checks (bw in PATH + unlocked) happen on first use/rescan.") {
			t.Error("bitwarden enabled message missing")
		}
	})

	t.Run("P2_enabled_prints_using_configured_dirs", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP2Enabled()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 2 (crumbs): enabled — using configured dirs[]. (P1 authority still enforced at scan time.)") {
			t.Error("P2 enabled message missing")
		}
	})

	t.Run("P3_enabled_prints_mode", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP3Enabled()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 3 (history): enabled, mode=scrub — ready.") {
			t.Error("P3 enabled+mode message missing")
		}
	})

	t.Run("P4_disabled_prints_set_enabled_true_guidance", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP4Disabled()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 4 (env): disabled in initial template. Set enabled: true under pillar4 to use 'blastradius env'.") {
			t.Error("P4 disabled guidance missing")
		}
	})

	t.Run("P5_disabled_prints_master_switch_warning", func(t *testing.T) {
		resetTestOverrides(t)
		removeConfigFile = func() error { return nil }
		configLoad = func() (*config.Config, string, error) {
			c := configWithP5Disabled()
			return &c, "", nil
		}

		out, _ := runValidateAndCapture(t, nil)
		if !strings.Contains(out, "Pillar 5 (clipboard): disabled in initial template. Set enabled: true under pillar5 if you want any clipboard hygiene") {
			t.Error("P5 disabled master-switch message missing")
		}
	})

	t.Run("tail_with_extra_args_and_reset_still_detects_reset", func(t *testing.T) {
		resetTestOverrides(t)
		called := false
		removeConfigFile = func() error { called = true; return nil }
		ensureConfig = func() (string, bool, error) { return "", false, nil }

		_, _ = runValidateAndCapture(t, []string{"foo", "--reset", "bar"})
		if !called {
			t.Error("--reset should be detected even when not first arg")
		}
	})
}
