package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// execBw is the hook used to invoke the Bitwarden CLI.
// It is overridable in tests so we never require a real `bw` binary.
// Production default resolves "bw" via LookPath to an absolute path (reduces PATH
// hijacking surface for this external collector) before exec. Tests override the
// entire func and are unaffected.
var execBw = func(args ...string) ([]byte, error) {
	// Resolve via shared helper (defense-in-depth LookPath to absolute for the
	// hard-coded P1 collector). Falls back to bare name (exec will error anyway).
	// Resolve on every call (cheap); Validate already asserted presence for the
	// enabled path.
	p := util.ResolveCommand("bw")
	return exec.Command(p, args...).CombinedOutput()
}

// BitwardenCollector implements Collector for the Bitwarden vault using the
// official `bw` CLI. All interaction is hard-coded and owned by the project.
type BitwardenCollector struct {
	cfg *config.Config
}

// NewBitwardenCollector creates a BitwardenCollector.
func NewBitwardenCollector(cfg *config.Config) *BitwardenCollector {
	return &BitwardenCollector{cfg: cfg}
}

func (b *BitwardenCollector) Name() string {
	return "bitwarden"
}

func (b *BitwardenCollector) Enabled() bool {
	if b.cfg == nil {
		return false
	}
	src, ok := b.cfg.Pillar1.Sources["bitwarden"]
	return ok && src.Enabled
}

// Validate implements the required prerequisite / IO check flow for Bitwarden:
//
// 1. Is the source enabled?
// 2. Is the `bw` binary available in PATH?
// 3. Can we get a usable status / session from `bw`?
//
// Each step produces a clear, actionable error message.
func (b *BitwardenCollector) Validate() error {
	if b.cfg == nil {
		return errors.New("no configuration loaded")
	}

	src, ok := b.cfg.Pillar1.Sources["bitwarden"]
	if !ok || !src.Enabled {
		return errors.New("bitwarden source is not enabled")
	}

	// Step 1: Does the bw binary exist? Use the shared resolver so a successful
	// LookPath yields an absolute path (defense-in-depth) and we have a single
	// implementation. Resolve returns the bare name on failure.
	if util.ResolveCommand("bw") == "bw" {
		return errors.New("bitwarden CLI ('bw') not found in PATH. Please install it and ensure it is available")
	}

	// Step 2: Can we talk to bw and get a status?
	// We use a lightweight status check. Real collection will do more work.
	output, err := execBw("status")
	if err != nil {
		logging.Printf("bitwarden Validate: bw status failed: %v (output len=%d; details in log only)", err, len(output))
		return errors.New("failed to communicate with Bitwarden CLI (see daemon log for details)")
	}

	// Check that we got a usable status. A very lightweight check for now.
	// We accept "unlocked" or "locked" as usable states. Anything else (e.g. unauthenticated)
	// means the user needs to authenticate.
	//
	// status output is small non-sensitive metadata only (auth state + identity; no
	// vault items, passwords, or secret material). We materialize it here solely for
	// the substring check. Contrast with Collect which must never leak raw "list items"
	// output (containing secrets) into errors or logs.
	statusStr := string(output)
	if !strings.Contains(statusStr, `"status":"unlocked"`) && !strings.Contains(statusStr, `"status":"locked"`) {
		return errors.New("Bitwarden CLI is not unlocked. Run 'bw unlock' (or set BW_SESSION) and try again.")
	}

	return nil
}

// Collect runs `bw list items` and extracts plausible secret values
// (passwords, notes, custom fields). This is a first implementation for Push 2.
func (b *BitwardenCollector) Collect() ([]registry.SecretHash, error) {
	output, err := execBw("list", "items")
	if err != nil {
		logging.Printf("bitwarden Collect: bw list items failed: %v (output len=%d; details in log only)", err, len(output))
		return nil, fmt.Errorf("bitwarden collect failed: %w (see daemon log for details)", err)
	}

	var items []map[string]any
	if err := json.Unmarshal(output, &items); err != nil {
		return nil, fmt.Errorf("failed to parse bw output: %w", err)
	}

	var hashes []registry.SecretHash
	ignore := b.getIgnorePatterns()

	for _, item := range items {
		// login.password
		if login, ok := item["login"].(map[string]any); ok {
			if pw, ok := login["password"].(string); ok && pw != "" {
				if !shouldIgnoreValue(pw, ignore) {
					hashes = append(hashes, registry.HashValue([]byte(pw)))
				}
			}
		}

		// notes (secure notes or login notes)
		if notes, ok := item["notes"].(string); ok && len(notes) > 8 {
			if !shouldIgnoreValue(notes, ignore) {
				hashes = append(hashes, registry.HashValue([]byte(notes)))
			}
		}

		// custom fields (all types)
		if fields, ok := item["fields"].([]any); ok {
			for _, f := range fields {
				if field, ok := f.(map[string]any); ok {
					if val, ok := field["value"].(string); ok && val != "" {
						if !shouldIgnoreValue(val, ignore) {
							hashes = append(hashes, registry.HashValue([]byte(val)))
						}
					}
				}
			}
		}

		// Also check top-level "password" for some item types
		if pw, ok := item["password"].(string); ok && pw != "" {
			if !shouldIgnoreValue(pw, ignore) {
				hashes = append(hashes, registry.HashValue([]byte(pw)))
			}
		}
	}

	return hashes, nil
}

func (b *BitwardenCollector) getIgnorePatterns() []string {
	if b.cfg == nil {
		return nil
	}
	return b.cfg.GetSourceIgnorePatterns("bitwarden")
}

// Simple ignore helper (can be enhanced later).
func shouldIgnoreValue(val string, patterns []string) bool {
	for _, p := range patterns {
		if p != "" && strings.Contains(val, p) { // very loose for now
			return true
		}
	}
	return false
}
