package policy

import (
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// filepathAbs is overridable in tests so we can force the error path
// in isClaimedByP1Env without deleting cwd or using subprocesses.
var filepathAbs = filepath.Abs

// Classifier is the internal authority engine for Pillar 1 vs Pillar 2 coordination.
// Its primary responsibility is to enforce the hard rule:
//
//	"Pillar 1 has authority and priority over Pillar 2."
//
// Any path that matches an active P1 env source's project_roots + env_file_patterns
// is considered claimed by P1. Pillar 2 (residue scanning) must never treat such a
// path as a crumb, even if the path falls under a P2 dirs[].files[] surface.
//
// The Classifier is purely internal. It performs no user-visible reporting or
// status augmentation in this increment (per explicit scope constraints).
type Classifier struct {
	cfg *config.Config
}

// New creates a Classifier bound to the given configuration.
// The cfg must be the one loaded for the running daemon (or test equivalent).
func New(cfg *config.Config) *Classifier {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Classifier{cfg: cfg}
}

// ShouldTreatFileAsCrumb is the central gate called by Pillar 2 scanning logic
// (and potentially future materialization surfaces).
//
// It returns (false, reason) immediately if the path is claimed by any active
// Pillar 1 "env" source (the P1 authority check). This implements the three
// supported P2 interactions and the "P1 overrides P2" rule.
//
// Only if the path is NOT P1-claimed does it consider whether the path falls
// under a configured P2 surface and whether the caller should proceed with
// secret candidate extraction for crumb reporting.
func (c *Classifier) ShouldTreatFileAsCrumb(absPath string) (bool, string) {
	if c == nil || c.cfg == nil {
		return false, "no classifier or config"
	}

	// === 1. P1 authority check (MUST BE FIRST — this is the non-negotiable rule) ===
	if c.isClaimedByP1Env(absPath) {
		return false, "P1 authority: path claimed by active env source env_file_patterns"
	}

	// === 2. Is this path under any P2-configured surface? ===
	// Only the dirs[] + per-dir files[] shape is supported (per-surface control).
	surfaceReason := c.underP2Surface(absPath)
	if surfaceReason == "" {
		// Not under any P2 hunting surface → nothing for P2 to do.
		return false, "not under any configured P2 surface"
	}

	// === 3. The path is under a P2 surface and not claimed by P1.
	// The caller (residue manager/detector) will now decide based on filename
	// heuristics + actual secret content (via internal/detection).
	// We simply green-light further examination.
	return true, surfaceReason
}

// isClaimedByP1Env returns true if absPath lives under one of the active
// "env" Pillar 1 source's project roots AND its basename matches one of that
// source's env_file_patterns (defaults to [".env*"] when EnvFilePatterns is
// empty after normalization).
func (c *Classifier) isClaimedByP1Env(absPath string) bool {
	// Respect the Enabled flag on the env source (if env is disabled,
	// P1 makes no authority claims and P2 can hunt the surface).
	envSrc, ok := c.cfg.Pillar1.Sources["env"]
	if !ok || !envSrc.Enabled {
		return false
	}

	envOpts := c.cfg.GetEnvOptions()
	if len(envOpts.ProjectRoots) == 0 {
		return false
	}

	// Determine effective patterns (empty → conventional [".env*"] default)
	patterns := envOpts.EnvFilePatterns
	if len(patterns) == 0 {
		patterns = []string{".env*"}
	}

	base := filepath.Base(absPath)

	for _, root := range envOpts.ProjectRoots {
		expandedRoot := util.ExpandPath(root)
		absRoot, err := filepathAbs(expandedRoot) // was: filepath.Abs(...)
		if err != nil {
			continue
		}
		// Check if absPath is under this root
		rel, err := filepath.Rel(absRoot, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		// Check basename against any of the env_file_patterns
		for _, pat := range patterns {
			if util.MatchesGlobPattern(base, pat) {
				return true
			}
		}
	}
	return false
}

// underP2Surface returns a non-empty reason string if absPath falls under
// at least one configured P2 dir (dirs[] + per-dir files[] shape).
// The reason is human-useful for logging inside the residue manager.
//
// Special patterns "**/*", "**", or empty files[] mean "everything
// under this dir is a potential P2 surface" (subject only to P1 gate).
func (c *Classifier) underP2Surface(absPath string) string {
	p2 := c.cfg.Pillar2

	for _, d := range p2.Dirs {
		if d.Path == "" {
			continue
		}
		expanded := util.ExpandPath(d.Path)
		absDir, err := filepathAbs(expanded)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(absDir, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		// Path is physically under this configured dir root.
		// Now apply the files[] filter for this specific surface.
		if isBroadP2Surface(d.Files) || util.MatchesAnyGlobPattern(filepath.Base(absPath), d.Files) || util.MatchesAnyGlobPattern(rel, d.Files) {
			return "under P2 dir " + d.Path
		}
	}
	return ""
}

// isBroadP2Surface returns true for patterns that mean "consider every file
// under the dir as a potential crumb surface" (user's "**/*" or "everything"
// intent for Downloads-style locations).
func isBroadP2Surface(patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || p == "**" || p == "**/*" || p == "*" {
			return true
		}
	}
	return false
}
