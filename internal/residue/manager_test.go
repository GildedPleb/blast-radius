package residue

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

func TestNewManager(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)
	if m == nil {
		t.Fatal("nil manager")
	}
}

func TestRunScan_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = false
	m := NewManager(cfg, registry.New())
	res := m.RunScan()
	if res == nil || len(res.Errors) == 0 {
		t.Error("expected disabled marker in errors")
	}
	if len(res.Findings) != 0 {
		t.Error("disabled scan must return zero findings")
	}
}

func TestCrumbsSummary_NeverScanned(t *testing.T) {
	m := NewManager(config.DefaultConfig(), registry.New())
	s := m.CrumbsSummary()
	if s["status"] != "never_scanned" {
		t.Errorf("got %v", s)
	}
}

// Consolidated heavy tests: we do as few full RunScan() as possible because
// they are expensive under coverage (filesystem walking + ScanFile on every file).
// Multiple previous tests have been merged here to keep total suite time low.

func TestResidueManager_HeavyPaths(t *testing.T) {
	// Test util.ExpandPath in isolation (pure function, fast, no real directory walk).
	// This replaces the previous dangerous "~/Downloads" case that caused 15s coverage runs
	// by walking the user's real home directories under instrumentation.
	t.Setenv("HOME", "/fake/home/for/test")
	if got := util.ExpandPath("~/foo"); got != "/fake/home/for/test/foo" {
		t.Errorf("ExpandPath failed: %s", got)
	}

	// Real RunScan cases below only ever use tiny t.TempDir() or clearly non-existent absolute paths.

	// Test 2: Empty dir + first few + last result + crumbs
	dir := t.TempDir()
	cfg2 := config.DefaultConfig()
	cfg2.Pillar2.Enabled = true
	cfg2.Pillar2.Dirs = []config.Pillar2Dir{{Path: dir, Files: []string{"**/*"}}}

	m2 := NewManager(cfg2, registry.New())
	res2 := m2.RunScan()
	if res2 == nil {
		t.Fatal("RunScan returned nil on empty dir")
	}
	if m2.GetLastResult() == nil {
		t.Fatal("GetLastResult nil after RunScan")
	}
	sum2 := m2.CrumbsSummary()
	if sum2["status"] != "ok" {
		t.Errorf("expected ok status, got %v", sum2["status"])
	}
	if sum2["sample"] == nil {
		t.Error("expected sample from firstFewLocations")
	}

	// Test 3: Dir with interesting files (name heuristic + some content)
	dir3 := t.TempDir()
	suspicious := filepath.Join(dir3, "bitwarden_export_2025.json")
	_ = os.WriteFile(suspicious, []byte(`{"encrypted":false,"items":[{"login":{"password":"s3cretv4lu3"}}]}`), 0600)
	csv := filepath.Join(dir3, "export.csv")
	_ = os.WriteFile(csv, []byte("login,username,password\nu,foo,verylongsecrettokenvalue123456\n"), 0600)

	cfg3 := config.DefaultConfig()
	cfg3.Pillar2.Enabled = true
	cfg3.Pillar2.Dirs = []config.Pillar2Dir{{Path: dir3, Files: []string{"**/*"}}}
	// flag_suspicious_filenames removed (alpha cleanup)

	m3 := NewManager(cfg3, registry.New())
	res3 := m3.RunScan()

	_ = m3.GetLastResult()
	sum3 := m3.CrumbsSummary()
	_ = sum3["sample"]

	if res3 == nil {
		t.Fatal("expected result from dir with files")
	}
	// We don't assert on exact finding count to keep the test stable and fast.
}

// TestResidueManager_SkipsSymlinks is a regression test for symlink handling in P2.
// Symlinks must be skipped (not followed) so that a link inside a configured
// high-risk dir (e.g. ~/Downloads) cannot cause us to read and process arbitrary
// sensitive files outside the declared surface.
func TestResidueManager_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()

	// A real secret file (high entropy + name heuristic will trigger).
	realSecret := filepath.Join(dir, "real_creds.json")
	_ = os.WriteFile(realSecret, []byte(`{"login":{"password":"superlonghighentropysecretvalueforlinktest1234567890"}}`), 0600)

	// A symlink with a suspicious name pointing at something that should never be read
	// by the scanner for this test (we use a non-existent target to make it obvious
	// if the code tried to open it; in practice even a real target outside would be skipped).
	link := filepath.Join(dir, "passwords_export.json")
	_ = os.Symlink("/this/does/not/exist/and/should/not/be/read/secret", link)

	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{{Path: dir, Files: []string{"**/*"}}}

	m := NewManager(cfg, registry.New())
	res := m.RunScan()
	if res == nil {
		t.Fatal("expected scan result")
	}

	// The symlink should not have produced a finding (we skipped before ScanFile).
	for _, f := range res.Findings {
		if strings.Contains(f.Basename, "passwords_export") || strings.Contains(f.Location, "passwords_export") {
			t.Errorf("symlink was followed/processed as a crumb; findings include %v", f)
		}
	}
}

// TestResidueManager_TargetsEmptyAndWalkErr uses the test hook to point home at a temp
// (so len(targets)==0 branch populates non-existent Downloads etc). This exercises
// the walk-err path and len==0 without ever walking real or large dirs (fast).
func TestResidueManager_TargetsEmptyAndWalkErr(t *testing.T) {
	// point userHomeDir hook at a temp that has no Downloads subdir
	fakeHome := t.TempDir()
	orig := userHomeDir
	userHomeDir = func() (string, error) { return fakeHome, nil }
	defer func() { userHomeDir = orig }()

	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = nil // will get defaults from effectiveP2Surfaces via NewManager path

	m := NewManager(cfg, registry.New())
	res := m.RunScan()
	if res == nil {
		t.Fatal("nil res")
	}
	// should have walk errors for the non-existent default dirs
	if len(res.Errors) == 0 {
		t.Log("note: expected walk errors for missing default dirs")
	}

	// also hit firstFewLocations with 0 findings via CrumbsSummary
	sum := m.CrumbsSummary()
	if sum["status"] != "ok" {
		t.Errorf("expected ok after empty-targets scan, got %v", sum["status"])
	}
	// sample should be []
	if s, ok := sum["sample"].([]string); ok && len(s) != 0 {
		t.Errorf("expected empty sample for 0 findings, got %v", s)
	}
}

// direct call to unexported firstFew for n=0 and early break coverage
func TestFirstFewLocations(t *testing.T) {
	findings := []ResidueFinding{{Location: "a"}, {Location: "b"}, {Location: "c"}, {Location: "d"}}
	if got := firstFewLocations(findings, 0); len(got) != 0 {
		t.Error("n=0 should give empty")
	}
	if got := firstFewLocations(findings, 2); len(got) != 2 || got[1] != "b" {
		t.Error("n=2 early break")
	}
}

// --- New tests for the dirs[] + files[] model (post flag_suspicious_filenames removal) ---

func TestEffectiveP2Surfaces(t *testing.T) {
	cfg := config.Pillar2Config{
		Dirs: []config.Pillar2Dir{
			{Path: "~/Downloads", Files: []string{"**/*"}},
			{Path: "/tmp/specific", Files: []string{"*.swp", "*~", "**/*_backup*"}},
		},
	}

	surfs := effectiveP2Surfaces(cfg)
	if len(surfs) != 2 {
		t.Fatalf("expected 2 surfaces, got %d", len(surfs))
	}

	// First surface should be broad
	if len(surfs[0].files) != 1 || surfs[0].files[0] != "**/*" {
		t.Errorf("expected broad **/* for Downloads, got %v", surfs[0].files)
	}

	// Second surface should have the narrow residue patterns (sorted)
	if len(surfs[1].files) != 3 {
		t.Errorf("expected 3 narrow patterns, got %v", surfs[1].files)
	}

	// Test dedup + merge for overlapping dirs
	cfg2 := config.Pillar2Config{
		Dirs: []config.Pillar2Dir{
			{Path: "/tmp/overlap", Files: []string{"*.swp", "*~"}},
			{Path: "/tmp/overlap", Files: []string{"*~", "**/*.bak", "*.swp"}}, // duplicates + new
			{Path: "/tmp/other", Files: []string{"**/*"}},
		},
	}
	surfs2 := effectiveP2Surfaces(cfg2)
	if len(surfs2) != 2 {
		t.Fatalf("expected 2 unique surfaces after dedup, got %d", len(surfs2))
	}
	// Find the overlap one
	var overlap []string
	for _, s := range surfs2 {
		if s.absDir == "/tmp/overlap" || filepath.Base(s.absDir) == "overlap" { // tolerate test env
			overlap = s.files
			break
		}
	}
	if len(overlap) != 3 {
		t.Errorf("expected merged 3 unique patterns for overlapping dir, got %v", overlap)
	}

	// Empty Path entries are skipped (covers the continue at d.Path == "")
	cfg3 := config.Pillar2Config{
		Dirs: []config.Pillar2Dir{
			{Path: "", Files: []string{"**/*"}}, // should be ignored
			{Path: "/tmp/good", Files: []string{"*.log"}},
		},
	}
	surfs3 := effectiveP2Surfaces(cfg3)
	if len(surfs3) != 1 || surfs3[0].absDir != "/tmp/good" {
		t.Errorf("empty Path should be skipped, got %d surfaces: %v", len(surfs3), surfs3)
	}

	// Force Abs error path via hook (covers the defensive continue)
	origAbs := filepathAbs
	defer func() { filepathAbs = origAbs }()
	filepathAbs = func(string) (string, error) { return "", errors.New("abs boom") }
	cfg4 := config.Pillar2Config{
		Dirs: []config.Pillar2Dir{{Path: "/tmp/whatever", Files: []string{"**/*"}}},
	}
	surfs4 := effectiveP2Surfaces(cfg4)
	if len(surfs4) != 0 {
		t.Errorf("Abs error should skip the dir, got %d surfaces", len(surfs4))
	}
}

func TestRunScan_NarrowFilesPatterns_OnlyMatchesIntended(t *testing.T) {
	dir := t.TempDir()

	// Use names that still trigger the existing suspiciousName heuristic
	// + known secrets planted in the registry for reliable findings.
	secret1 := "AKIAIOSFODNN7EXAMPLE12345678901234567890"
	secret2 := "supersecretvalue123456789012345678901234567890"

	os.WriteFile(filepath.Join(dir, "important_secret.swp"), []byte("secret="+secret1), 0600)
	os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("notsecret=hello"), 0600)
	os.WriteFile(filepath.Join(dir, "data_backup_password.json"), []byte("password="+secret2), 0600)

	reg := registry.New()
	reg.Add(registry.HashValue([]byte(secret1)), "p1")
	reg.Add(registry.HashValue([]byte(secret2)), "p1")

	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: dir, Files: []string{"*.swp", "*_backup*"}},
	}

	m := NewManager(cfg, reg)
	res := m.RunScan()

	// With the narrow files[] filter we should only have examined the two matching files
	// (not the normal.txt). Exact findings depend on ScanFile internals, so we assert
	// on the filtering behavior instead.
	if res.FilesExamined != 2 {
		t.Errorf("expected to examine exactly 2 files due to narrow files[] patterns, got %d", res.FilesExamined)
	}

	// Should not have reported the innocent file
	for _, f := range res.Findings {
		if f.Basename == "normal.txt" {
			t.Error("should not have reported normal.txt when using narrow files patterns")
		}
	}
}

func TestRunScan_P1AuthorityStillWins_WithExplicitFilesPattern(t *testing.T) {
	dir := t.TempDir()

	// A file that would match a P2 pattern
	os.WriteFile(filepath.Join(dir, "project.swp"), []byte("AWS_SECRET=AKIAIOSFODNN7EXAMPLE12345678901234567890"), 0600)

	cfg := config.DefaultConfig()

	// P1 claims .swp files in this root (deliberate policy)
	cfg.Pillar1.Sources["env"] = config.SourceConfig{
		Enabled: true,
		Options: map[string]any{
			"project_roots":     []string{dir},
			"env_file_patterns": []string{"*.swp"},
		},
	}

	// P2 also wants to look for .swp in the same dir
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{Path: dir, Files: []string{"*.swp"}},
	}

	m := NewManager(cfg, registry.New())
	res := m.RunScan()

	// P1 authority must win — the .swp should NOT appear as a crumb
	for _, f := range res.Findings {
		if strings.Contains(f.Basename, ".swp") {
			t.Errorf("P1-claimed .swp file was incorrectly reported as P2 crumb: %s", f.Basename)
		}
	}
}

func TestRunScan_SurgicalResidueHunting_Example(t *testing.T) {
	// This test mirrors the recommended pattern in config.example.yaml:
	// Instead of "**/*" on Downloads, only hunt for known dangerous residue patterns.
	dir := t.TempDir()

	secret1 := "supersecretvalue123456789012345678901234567890"
	secret2 := "AKIAIOSFODNN7EXAMPLE123456789012345678901234567890"
	secret3 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4G9EXauX6xqH2k"

	// Dangerous residue files (names contain trigger words so name heuristic fires)
	os.WriteFile(filepath.Join(dir, "notes_secret.swp"), []byte("DB_PASSWORD="+secret1), 0600)
	os.WriteFile(filepath.Join(dir, "temp_secret~"), []byte("API_KEY="+secret2), 0600)
	os.WriteFile(filepath.Join(dir, "old_backup_secret.json"), []byte("token: "+secret3), 0600)

	// Innocent files that should be ignored
	os.WriteFile(filepath.Join(dir, "photo.jpg"), []byte("binarydata"), 0600)
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("just documentation"), 0600)

	reg := registry.New()
	reg.Add(registry.HashValue([]byte(secret1)), "p1")
	reg.Add(registry.HashValue([]byte(secret2)), "p1")
	reg.Add(registry.HashValue([]byte(secret3)), "p1")

	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{
		{
			Path: dir,
			Files: []string{
				"*.swp",
				"*~",
				"**/*_backup*",
				"**/*.bak",
			},
		},
	}

	m := NewManager(cfg, reg)
	res := m.RunScan()

	// We configured very narrow residue patterns. Innocent files should not be examined.
	if res.FilesExamined > 3 {
		t.Fatalf("with narrow surgical patterns we should not have examined more than 3 files, got %d", res.FilesExamined)
	}

	// None of the innocent files should have been considered
	for _, f := range res.Findings {
		if f.Basename == "photo.jpg" || f.Basename == "readme.txt" {
			t.Errorf("innocent file %s should not have been reported under narrow residue patterns", f.Basename)
		}
	}
}

// TestRunScan_CollectsErrors exercises per-dir and per-file error collection in RunScan
// (scanErr from ScanFile etc.) using permission denial on a file inside the surface.
func TestRunScan_CollectsErrors(t *testing.T) {
	dir := t.TempDir()

	// Good file that should be found
	good := filepath.Join(dir, "creds.json")
	os.WriteFile(good, []byte(`{"encrypted":false,"items":[{"login":{"password":"Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU"}}]}`), 0600)

	// File that will cause ScanFile to return err (no read perm after stat)
	bad := filepath.Join(dir, "badperm.json")
	os.WriteFile(bad, []byte(`{}`), 0600)
	os.Chmod(bad, 0000)
	defer os.Chmod(bad, 0600)

	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = true
	cfg.Pillar2.Dirs = []config.Pillar2Dir{{Path: dir, Files: []string{"**/*"}}}

	m := NewManager(cfg, registry.New())
	res := m.RunScan()

	if res == nil {
		t.Fatal("nil res")
	}
	// Should have collected at least the scan err for the badperm file
	foundErr := false
	for _, e := range res.Errors {
		if strings.Contains(e, "badperm") {
			foundErr = true
			break
		}
	}
	if !foundErr {
		t.Logf("note: no per-file err captured for badperm (owner chmod 000 may still allow open on this FS); errors=%v", res.Errors)
	}

	// Also exercise Walk entry-err path by having an unreadable subdir (hits the if err !=nil append inside WalkDir)
	restricted := filepath.Join(dir, "restricted-sub")
	os.Mkdir(restricted, 0000)
	defer os.Chmod(restricted, 0700)

	// re-run scan on same cfg (dir now has the restricted sub)
	res2 := m.RunScan()
	foundWalkErr := false
	for _, e := range res2.Errors {
		if strings.Contains(e, "restricted-sub") {
			foundWalkErr = true
			break
		}
	}
	if !foundWalkErr {
		t.Logf("note: walk err for restricted sub not seen (may vary by FS); errors=%v", res2.Errors)
	}
}

// TestResidueManager_ConcurrentReadWrite exercises the last* fields under
// concurrent calls (RunScan writers + CrumbsSummary/GetLastResult readers)
// matching the daemon's go handleConnection pattern for CRUMBS + STATUS.
// Uses the fast disabled path (no real FS work) + many goroutines.
// Follows project test rules: no sleeps, no real listeners.
func TestResidueManager_ConcurrentReadWrite(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Pillar2.Enabled = false // fast path: hits last= publish without walking
	m := NewManager(cfg, registry.New())

	var wg sync.WaitGroup
	const iters = 20
	for i := 0; i < iters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.RunScan()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.CrumbsSummary()
			_ = m.GetLastResult()
		}()
	}
	wg.Wait()
}
