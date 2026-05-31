package discovery

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Scanner discovers .env* files, parses them, and populates the registry.
type Scanner struct {
	registry    *registry.Registry
	cfg         *config.Config
	ignores     map[string]*IgnoreMatcher // per-root ignore matchers

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

// ScanDirectory recursively scans a directory for .env* files and populates the registry.
func (s *Scanner) ScanDirectory(root string) error {
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

	// Create or reuse ignore matcher for this root
	if _, ok := s.ignores[absRoot]; !ok {
		s.ignores[absRoot] = NewIgnoreMatcher(absRoot, ignoreFiles)
	}
	ignore := s.ignores[absRoot]

	// Build skipDirs set from config (user can extend/override via config)
	skipDirs := make(map[string]bool)
	for _, d := range envOpts.SkipDirs {
		skipDirs[d] = true
	}

	return filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip problematic paths
		}

		// Fast path: skip known heavy/noisy directories early
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

		// Only process regular files starting with .env
		if info.Mode().IsRegular() && strings.HasPrefix(filepath.Base(path), ".env") {
			projectDir := filepath.Dir(path)
			projectID := makeOpaqueProjectID(projectDir)
			displayName := computeDisplayName(projectDir)

			if s.onProjectDiscovered != nil {
				s.onProjectDiscovered(projectID, displayName)
			}

			if err := s.processEnvFile(path, projectID); err != nil {
				logging.Printf("Warning: failed to process %s: %v", path, err)
			}
		}
		return nil
	})
}

func (s *Scanner) processEnvFile(path string, projectID registry.ProjectID) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '=' only
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Remove surrounding quotes if present
		value = strings.Trim(value, `"'`)

		if value == "" {
			continue
		}

		// Phase 1 key filtering (Pillar 1 logical layer). Patterns come from the
		// "env" source options (or legacy top-level until full migration).
		// This is the same engine that will serve bitwarden and future sources.
		if s.shouldIgnoreKey(key) {
			continue
		}

		hash := registry.HashValue([]byte(value))
		s.registry.Add(hash, projectID)
	}

	return scanner.Err()
}

// CollectEnvHashes performs .env* discovery for the given roots and returns
// only the hashes (no registration). Used by the logical layer (EnvCollector).
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
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// Reuse ignore + skip logic from ScanDirectory
	envOpts := s.cfg.GetEnvOptions()
	ignoreFiles := envOpts.IgnoreFiles
	if len(ignoreFiles) == 0 {
		ignoreFiles = []string{".gitignore", ".blastradiusignore"}
	}

	if _, ok := s.ignores[absRoot]; !ok {
		s.ignores[absRoot] = NewIgnoreMatcher(absRoot, ignoreFiles)
	}
	ignore := s.ignores[absRoot]

	skipDirs := make(map[string]bool)
	for _, d := range envOpts.SkipDirs {
		skipDirs[d] = true
	}

	var hashes []registry.SecretHash

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			if skipDirs[base] {
				return filepath.SkipDir
			}
			if ignore.ShouldIgnore(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if ignore.ShouldIgnore(path) {
			return nil
		}

		if info.Mode().IsRegular() && strings.HasPrefix(filepath.Base(path), ".env") {
			fileHashes, err := s.collectHashesFromFile(path)
			if err != nil {
				logging.Printf("Warning: failed to process %s: %v", path, err)
				return nil
			}
			hashes = append(hashes, fileHashes...)
		}
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