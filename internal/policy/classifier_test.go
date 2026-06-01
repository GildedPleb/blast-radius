package policy

import (
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/util"
)

func TestClassifier_P1AuthorityWins(t *testing.T) {
	cfg := config.DefaultConfig()
	// Set up a P1 env claim on a synthetic dev dir, narrow patterns
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{
			"project_roots":     []string{"/tmp/test-dev"},
			"env_file_patterns": []string{".env.local", ".env.*.local"},
		},
	}

	// P2 surface that overlaps the same dir, broad files
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: "/tmp/test-dev", Files: []string{"**/*"}},
	}

	c := New(cfg)

	// Case 1: .env.local under the root → P1 claims it, P2 must NOT treat as crumb
	claimed := "/tmp/test-dev/.env.local"
	treat, reason := c.ShouldTreatFileAsCrumb(claimed)
	if treat {
		t.Errorf("expected P1 authority to block crumb for %s, got treat=true (%s)", claimed, reason)
	}
	if !contains(reason, "P1 authority") {
		t.Errorf("expected P1 authority reason, got %q", reason)
	}

	// Case 2: plain .env (NOT in the narrow patterns) → not claimed by P1, under P2 surface → treat as crumb candidate
	plain := "/tmp/test-dev/.env"
	treat, reason = c.ShouldTreatFileAsCrumb(plain)
	if !treat {
		t.Errorf("expected non-approved .env under P2 surface to be crumb candidate, got treat=false (%s)", reason)
	}

	// Case 3: source file with secret → should be candidate (P1 did not claim .js)
	js := "/tmp/test-dev/src/app.js"
	treat, _ = c.ShouldTreatFileAsCrumb(js)
	if !treat {
		t.Errorf("expected source file under broad P2 surface (not P1-claimed) to be crumb candidate")
	}
}

func TestClassifier_IndependentSurfaces_NoConflict(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{
			"project_roots":     []string{"/tmp/isolated"},
			"env_file_patterns": []string{".env*"},
		},
	}
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: "/tmp/downloads", Files: []string{"**/*"}},
	}

	c := New(cfg)

	// File in P1-only area
	treat, _ := c.ShouldTreatFileAsCrumb("/tmp/isolated/.env")
	if treat {
		t.Error("P1-only .env should never be treated as P2 crumb")
	}

	// File in P2-only area
	treat, _ = c.ShouldTreatFileAsCrumb("/tmp/downloads/bitwarden_export.json")
	if !treat {
		t.Error("Downloads export should be P2 crumb candidate")
	}
}

func TestClassifier_P1Disabled_P2OwnsEverything(t *testing.T) {
	cfg := config.DefaultConfig()
	// Env source disabled
	cfg.Pillar1.Sources["env"] = config.SourceConfig{Enabled: false}

	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: "/tmp/dev", Files: []string{"**/*"}},
	}

	c := New(cfg)

	// Any file under the P2 surface (including .env files) should be candidate
	for _, p := range []string{"/tmp/dev/.env", "/tmp/dev/src/secret.js", "/tmp/dev/debug.log"} {
		treat, _ := c.ShouldTreatFileAsCrumb(p)
		if !treat {
			t.Errorf("when P1 env disabled, everything under P2 surface should be crumb candidate: %s", p)
		}
	}
}

func TestClassifier_DirsShape_Only(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{"project_roots": []string{"/tmp/p1-claimed"}},
	}
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: "/tmp/p2-surface", Files: []string{"**/*"}},
	}

	c := New(cfg)

	// P1 claimed area must be protected even if someone puts it in a P2 dir
	treat, _ := c.ShouldTreatFileAsCrumb("/tmp/p1-claimed/.env.local")
	if treat {
		t.Error("P1 claim must win over any P2 surface")
	}

	// Normal P2 surface works
	treat, _ = c.ShouldTreatFileAsCrumb("/tmp/p2-surface/creds.txt")
	if !treat {
		t.Error("files under a P2 dirs[] entry should be candidates (unless P1 claimed them)")
	}
}

// contains is a tiny helper (stdlib has no strings.Contains in some contexts we care about here)
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(sub) > 0 && search(s, sub)))
}

func search(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMatchesAnyPattern(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{".env.local", []string{".env.local"}, true},
		{".env", []string{".env*"}, true},
		// Note: full ** glob support is intentionally minimal here.
		// The isBroadP2Surface + under-dir check in the Classifier handles
		// the common "**/*" / "everything under this dir" case for P2 surfaces.
		// With the **/ stripping improvement for surgical patterns, these now match
		// (the desired behavior for the documented "hunt specific residue anywhere" use case).
		{"app.js", []string{"**/*"}, true},
		{"debug_creds.json", []string{"**/debug*"}, true},
		{"normal.txt", []string{"**/*secret*"}, false}, // still no match
		{".env.production", []string{".env.local", ".env.*.local"}, false},
		{"mysecret.txt", []string{"*secret*"}, true}, // basic * works via filepath.Match
	}
	for _, tc := range cases {
		got := util.MatchesAnyGlobPattern(tc.name, tc.patterns)
		if got != tc.want {
			t.Errorf("matchesAnyPattern(%q, %v) = %v, want %v", tc.name, tc.patterns, got, tc.want)
		}
	}
}

// Test that Classifier handles ~ expansion and absolute paths gracefully.
func TestClassifier_ExpandAndAbs(t *testing.T) {
	cfg := config.DefaultConfig()
	home := t.TempDir() // use a real temp dir as fake $HOME
	t.Setenv("HOME", home)

	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{
			"project_roots":     []string{"~/myproject"},
			"env_file_patterns": []string{".env*"},
		},
	}
	cfg.Pillar2.Dirs = []config.Pillar2Dir{{Path: "~/myproject", Files: []string{"**/*"}}}

	c := New(cfg)

	claimed := filepath.Join(home, "myproject", ".env")
	treat, _ := c.ShouldTreatFileAsCrumb(claimed)
	if treat {
		t.Error("~ expansion + P1 claim should still block crumb")
	}
}
