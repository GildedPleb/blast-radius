package discovery

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
	"github.com/GildedPleb/blast-radius/internal/util"
)

// Scanner discovers files matching the Pillar 1 env source's configured
// env_file_patterns (positive include list declaring "these are my authoritative
// secret containers"), parses them, and populates the registry.
// When no patterns are specified the conventional default [".env*"] is used.
type Scanner struct {
	registry  *registry.Registry
	cfg       *config.Config
	ignores   map[string]*IgnoreMatcher // per-root ignore matchers
	ignoresMu sync.RWMutex              // protects ignores map (bg scan vs concurrent rescan/status)

	// onProjectDiscovered is called when we find a new project root during scan.
	// This allows the Manager to capture display names without the Registry seeing paths.
	onProjectDiscovered func(opaqueID registry.ProjectID, displayName string)
}

// NewScanner creates a new Scanner.
func NewScanner(cfg *config.Config, reg *registry.Registry) *Scanner {
	return &Scanner{
		registry: reg,
		cfg:      cfg,
		ignores:  make(map[string]*IgnoreMatcher),
	}
}

// visitEnvFiles encapsulates the duplicated absRoot + ignore/skip setup +
// Walk + early SkipDir + ignore + matchesEnvFile logic (previously duplicated
// between ScanDirectory and collectHashesInDir).
//
// Calls onFile exactly once per matching regular env file (after all filters).
// Per-file errors must be handled inside onFile (logged + swallowed); the
// callback should return nil to continue the walk (matching prior behavior
// in both paths). Returns the error from filepath.Walk (if any).
func (s *Scanner) visitEnvFiles(root string, onFile func(path string) error) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}

	// Determine which ignore files to load (from config, with safe defaults)
	envOpts := s.cfg.GetEnvOptions()
	ignoreFiles := envOpts.IgnoreFiles
	if len(ignoreFiles) == 0 {
		ignoreFiles = []string{".gitignore", ".blastradiusignore"}
	}

	// Create or reuse ignore matcher for this root.
	// Brief write lock only for the map mutation; the matcher itself is then
	// used without the lock (walks are CPU/IO bound; concurrent walks for
	// different roots are fine).
	s.ignoresMu.Lock()
	if _, ok := s.ignores[absRoot]; !ok {
		s.ignores[absRoot] = NewIgnoreMatcher(absRoot, ignoreFiles)
	}
	ignore := s.ignores[absRoot]
	s.ignoresMu.Unlock()

	// Build skipDirs set from config (user can extend/override via config)
	skipDirs := make(map[string]bool)
	for _, d := range envOpts.SkipDirs {
		skipDirs[d] = true
	}

	// Fast path: skip known heavy/noisy directories early (structure from original ScanDirectory)
	return filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip problematic paths
		}

		if info.Mode()&os.ModeSymlink != 0 {
			// Never follow symlinks during P1 discovery. This prevents:
			// - escaping the declared project_roots via symlink components
			// - reading sensitive files that happen to be linked inside a scanned tree
			// (e.g. a .env* symlink pointing outside the root or at a high-value target).
			// P2 does the same (see residue/manager.go and detector.go). Declared roots +
			// Rel+.. guards in Classifier + env_file_patterns authority remain the primary
			// containment; symlink skip is belt-and-suspenders.
			//
			// Note on semantics: info comes from filepath.Walk (Lstat under the hood).
			// For a symlink, info.Mode() has ModeSymlink and info.IsDir() is always false
			// (the link itself is not a dir). Walk never descends into symlinked directories
			// regardless, so we simply return nil to skip the entry (no onFile/collect).
			// An explicit SkipDir inside this block would be unreachable.
			//
			// TOCTOU note: the walk-time decision (this Lstat info) and later open in
			// collectHashesFromFile have a narrow race window where a local writer could
			// replace the entry with a symlink. Primary containment is the declared roots +
			// patterns + Classifier. See matching note in residue/detector.go. Documented
			// in CURRENT_STATE.md + config.example.yaml.
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			if skipDirs[base] {
				return filepath.SkipDir
			}
		}

		// Skip ignored paths (from configured ignore files)
		if ignore.ShouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process regular files that match the configured env file patterns
		// (Pillar 1 authority declaration). Default is [".env*"].
		if info.Mode().IsRegular() && s.matchesEnvFile(filepath.Base(path)) {
			if err := onFile(path); err != nil {
				// onFile is responsible for any logging; we continue
				// (do not return err here) to match prior Scan+collect behavior.
			}
		}
		return nil
	})
}

// ScanDirectory recursively scans a directory for .env* files and populates the registry.
func (s *Scanner) ScanDirectory(root string) error {
	return s.visitEnvFiles(root, func(path string) error {
		projectDir := filepath.Dir(path)
		projectID := makeOpaqueProjectID(projectDir)
		displayName := computeDisplayName(projectDir)

		if s.onProjectDiscovered != nil {
			s.onProjectDiscovered(projectID, displayName)
		}

		if err := s.processEnvFile(path, projectID); err != nil {
			logging.Printf("Warning: failed to process %s: %v", path, err)
		}
		return nil
	})
}

func (s *Scanner) processEnvFile(path string, projectID registry.ProjectID) error {
	hashes, err := s.collectHashesFromFile(path)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		s.registry.Add(h, projectID)
	}
	return nil
}

// CollectEnvHashes performs discovery of files matching the Pillar 1 env
// source's env_file_patterns for the given roots and returns only the hashes
// (no registration). Used by the logical layer (EnvCollector).
func (s *Scanner) CollectEnvHashes(roots []string) ([]registry.SecretHash, error) {
	var allHashes []registry.SecretHash

	for _, root := range roots {
		expanded := expandPath(root) // reuse existing helper (same package)
		hashes, err := s.collectHashesInDir(expanded)
		if err != nil {
			return nil, err
		}
		allHashes = append(allHashes, hashes...)
	}

	return allHashes, nil
}

func (s *Scanner) collectHashesInDir(root string) ([]registry.SecretHash, error) {
	var hashes []registry.SecretHash
	err := s.visitEnvFiles(root, func(path string) error {
		fileHashes, err := s.collectHashesFromFile(path)
		if err != nil {
			logging.Printf("Warning: failed to process %s: %v", path, err)
			return nil
		}
		hashes = append(hashes, fileHashes...)
		return nil
	})
	return hashes, err
}

func (s *Scanner) collectHashesFromFile(path string) ([]registry.SecretHash, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []registry.SecretHash
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		if value == "" {
			continue
		}

		if s.shouldIgnoreKey(key) {
			continue
		}

		hash := registry.HashValue([]byte(value))
		hashes = append(hashes, hash)
	}
	return hashes, scanner.Err()
}

// shouldIgnoreKey returns true if the given .env key should not be treated as a secret.
// It consults the "env" Pillar 1 source's ignore_patterns (supports exact match and
// simple * suffix/prefix globs for practicality in v1).
func (s *Scanner) shouldIgnoreKey(key string) bool {
	if s.cfg == nil {
		return false
	}
	patterns := s.cfg.GetSourceIgnorePatterns("env")
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if matchIgnorePattern(key, p) {
			return true
		}
	}
	return false
}

// matchIgnorePattern supports exact match and simple * wildcards.
// Supported forms in v1 (KISS):
//   - exact: "LOG_LEVEL"
//   - prefix*: "AWS_*"
//   - *suffix: "*_NONSECRET"
//   - prefix*suffix: "AWS_*_KEY_ID" (single internal wildcard)
func matchIgnorePattern(key, pattern string) bool {
	if pattern == key {
		return true
	}
	// prefix*
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if prefix != "" && strings.HasPrefix(key, prefix) {
			return true
		}
	}
	// *suffix
	if strings.HasPrefix(pattern, "*") && !strings.Contains(pattern[1:], "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		if suffix != "" && strings.HasSuffix(key, suffix) {
			return true
		}
	}
	// prefix*suffix (exactly one *)
	if strings.Count(pattern, "*") == 1 {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			pre, suf := parts[0], parts[1]
			if (pre == "" || strings.HasPrefix(key, pre)) && (suf == "" || strings.HasSuffix(key, suf)) {
				return true
			}
		}
	}
	return false
}

// makeOpaqueProjectID creates a stable opaque identifier from a directory path.
// This is the single place that decides what ProjectID looks like.
func makeOpaqueProjectID(absDir string) registry.ProjectID {
	h := sha256.Sum256([]byte(absDir))
	return registry.ProjectID(hex.EncodeToString(h[:8]))
}

// computeDisplayName creates a privacy-friendly name from the real path
// at discovery time. We capture this once and throw the full path away.
func computeDisplayName(absDir string) string {
	absDir = strings.TrimSuffix(absDir, "/")
	parts := strings.Split(absDir, "/")
	if len(parts) == 0 {
		return "unknown"
	}
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return parts[len(parts)-1]
}

// matchesEnvFile returns whether the given basename matches any of the
// configured env file patterns for the Pillar 1 "env" source (or the
// conventional default [".env*"] when none are specified).
//
// The patterns come from pillar1.sources.env.options.env_file_patterns —
// the positive declaration of which on-disk containers are legitimate
// secret sources (P1 authority).
func (s *Scanner) matchesEnvFile(base string) bool {
	if s.cfg == nil {
		return strings.HasPrefix(base, ".env") // ultra-safe fallback
	}
	pats := s.cfg.GetEnvOptions().EnvFilePatterns
	if len(pats) == 0 {
		pats = []string{".env*"}
	}
	return util.MatchesAnyGlobPattern(base, pats)
}
