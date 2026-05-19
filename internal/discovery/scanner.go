package discovery

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Scanner discovers .env* files, parses them, and populates the registry.
type Scanner struct {
	registry    *registry.Registry
	cfg         *config.Config
	ignores     map[string]*IgnoreMatcher // per-root ignore matchers
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
	ignoreFiles := s.cfg.IgnoreFiles
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
	for _, d := range s.cfg.SkipDirs {
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
			projectID := registry.ProjectID(filepath.Dir(path))
			if err := s.processEnvFile(path, projectID); err != nil {
				log.Printf("Warning: failed to process %s: %v", path, err)
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

		value := strings.TrimSpace(parts[1])
		// Remove surrounding quotes if present
		value = strings.Trim(value, `"'`)

		if value == "" {
			continue
		}

		hash := registry.HashValue([]byte(value))
		s.registry.Add(hash, projectID)
	}

	return scanner.Err()
}