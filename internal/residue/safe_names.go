package residue

import (
	"os"
	"path/filepath"
	"strings"
)

// SafeLocation returns a privacy-friendly location string for a residue finding.
// Examples: "Downloads/bitwarden_export_2024.json", "Documents/creds.json"
// Never emits the full home directory path.
func SafeLocation(absPath string) string {
	home := os.Getenv("HOME")
	if home != "" && strings.HasPrefix(absPath, home) {
		rel := strings.TrimPrefix(absPath, home)
		rel = strings.TrimPrefix(rel, string(filepath.Separator))
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) >= 2 {
			// First component (Downloads, Documents, ...) + basename
			return filepath.Join(parts[0], parts[len(parts)-1])
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return filepath.Base(absPath)
	}
	// Fallback for non-home paths (mounted volumes etc.)
	if strings.HasPrefix(absPath, "/") {
		parts := strings.Split(strings.TrimPrefix(absPath, "/"), string(filepath.Separator))
		if len(parts) > 2 {
			return filepath.Join(parts[0], parts[len(parts)-1])
		}
	}
	return filepath.Base(absPath)
}
