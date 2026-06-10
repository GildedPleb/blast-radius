package sources

import (
	"errors"
	"os"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// EnvCollector implements Collector for .env* files (the original Pillar 1 source).
type EnvCollector struct {
	cfg      *config.Config
	scanFunc func() ([]registry.SecretHash, error)
}

// NewEnvCollector creates an EnvCollector.
func NewEnvCollector(cfg *config.Config) *EnvCollector {
	return &EnvCollector{cfg: cfg}
}

// SetScanFunc allows the Manager to inject the actual scanning implementation
// (avoids import cycles while letting EnvCollector participate in the collector model).
func (e *EnvCollector) SetScanFunc(fn func() ([]registry.SecretHash, error)) {
	e.scanFunc = fn
}

func (e *EnvCollector) Name() string {
	return "env"
}

func (e *EnvCollector) Enabled() bool {
	if e.cfg == nil {
		return false
	}
	src, ok := e.cfg.Pillar1.Sources["env"]
	return ok && src.Enabled
}

// Validate implements the prerequisite check flow for the ENV source as requested:
// - Is the source enabled? (already gated by caller in many paths)
// - Are project roots configured (via the Pillar 1 logical layer under pillar1.sources.env.options)?
func (e *EnvCollector) Validate() error {
	if e.cfg == nil {
		return errors.New("no configuration loaded")
	}

	src, ok := e.cfg.Pillar1.Sources["env"]
	if !ok || !src.Enabled {
		return errors.New("env source is not enabled")
	}

	roots := e.cfg.GetEnvOptions().ProjectRoots
	if len(roots) == 0 {
		return errors.New("env source has no project_roots configured (this should have been caught by ValidateReadiness; run `blastradius validate` to diagnose and fix)")
	}

	// Do a basic existence/readability check on the configured roots.
	for _, r := range roots {
		expanded := expandForValidation(r)
		if _, err := os.Stat(expanded); err != nil {
			if os.IsNotExist(err) {
				return errors.New("configured project root does not exist: " + r)
			}
			return errors.New("cannot access configured project root: " + r)
		}
	}

	return nil
}

// Collect performs .env* discovery using the injected scan function (provided by the Manager).
func (e *EnvCollector) Collect() ([]registry.SecretHash, error) {
	if e.scanFunc == nil {
		return nil, nil // no scan function provided yet
	}
	return e.scanFunc()
}

// GetIgnorePatterns returns the configured ignore patterns for this source.
func (e *EnvCollector) GetIgnorePatterns() []string {
	if e.cfg == nil {
		return nil
	}
	return e.cfg.GetSourceIgnorePatterns("env")
}

// expandForValidation is a minimal ~ expander for validation purposes only.
func expandForValidation(p string) string {
	if p == "~" || p == "~/" {
		if h := os.Getenv("HOME"); h != "" {
			return h
		}
	}
	if len(p) > 2 && p[:2] == "~/" {
		if h := os.Getenv("HOME"); h != "" {
			return h + p[1:]
		}
	}
	return p
}
