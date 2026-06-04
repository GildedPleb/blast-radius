package residue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GildedPleb/blast-radius/internal/detection"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

// FilenameHeuristic returns true + a format hint if the basename strongly suggests
// a dangerous secret dump. This is the always-on name heuristic for high-risk
// export and credential dump filenames.
func FilenameHeuristic(name string) (bool, string) {
	lower := strings.ToLower(name)
	suspicious := []string{
		"bitwarden", "bw_export", "bwexport",
		"dashlane", "dashlane_export",
		"1password", "1pif", "1p_export",
		"password", "passwords", "secrets", "creds", "credentials",
		"env_export", "vault_export", "secret_dump", "key_dump",
		"export.json", "export.csv", ".env.backup", ".env.bak",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			// crude format hint
			if strings.HasSuffix(lower, ".json") {
				return true, FormatBitwardenJSON // could be generic too; caller decides
			}
			if strings.HasSuffix(lower, ".csv") {
				return true, FormatBitwardenCSV
			}
			if strings.HasSuffix(lower, ".1pif") {
				return true, FormatOnePassword
			}
			return true, FormatSuspiciousName
		}
	}
	return false, ""
}

// DetectBitwardenJSON returns (hits, isExport) where hits is count of high-entropy secret values found.
func DetectBitwardenJSON(data []byte) (int, bool) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, false
	}
	// Common Bitwarden export shape: "encrypted": false, "items": [...]
	if enc, ok := doc["encrypted"].(bool); ok && enc {
		return 0, false // we don't attempt to parse encrypted exports
	}
	items, _ := doc["items"].([]any)
	if len(items) == 0 {
		// could still be a login export or other shape — fall back to generic entropy later
		_, hasFolders := doc["folders"]
		_, hasCollections := doc["collections"]
		if hasFolders || hasCollections {
			return 0, true // looks like BW structure even if empty
		}
		return 0, false
	}

	hits := 0
	for _, it := range items {
		item, ok := it.(map[string]any)
		if !ok {
			continue
		}
		// login
		if login, ok := item["login"].(map[string]any); ok {
			for _, k := range []string{"password", "totp", "username"} {
				if v, ok := login[k].(string); ok && len(v) >= 8 && detection.ComputeEntropy(v) >= 4.0 {
					hits++
				}
			}
		}
		// fields
		if fields, ok := item["fields"].([]any); ok {
			for _, f := range fields {
				if fm, ok := f.(map[string]any); ok {
					if v, ok := fm["value"].(string); ok && len(v) >= 8 && detection.ComputeEntropy(v) >= 4.0 {
						hits++
					}
				}
			}
		}
		// notes
		if notes, ok := item["notes"].(string); ok && len(notes) > 0 {
			hits += detection.ExtractHighEntropyStrings([]byte(notes), 16, 4.0)
		}
	}
	isExport := len(items) > 0 || doc["encrypted"] != nil
	return hits, isExport
}

// DetectBitwardenCSV looks for common BW CSV column headers + entropy in password cells.
func DetectBitwardenCSV(data []byte) (int, bool) {
	text := string(data)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "password") || !strings.Contains(lower, "login") {
		return 0, false
	}
	hits := detection.ExtractHighEntropyStrings(data, 12, 4.0)
	return hits, hits > 0 || strings.Contains(lower, "bitwarden")
}

// DetectDashlane tries to recognize Dashlane export shapes (JSON or CSV-ish).
func DetectDashlane(data []byte) (int, bool) {
	text := strings.ToLower(string(data))
	if strings.Contains(text, "dashlane") || strings.Contains(text, `"username"`) && strings.Contains(text, `"password"`) {
		hits := detection.ExtractHighEntropyStrings(data, 12, 4.0)
		return hits, hits > 0 || strings.Contains(text, "dashlane")
	}
	return 0, false
}

// DetectOnePassword1pif is best-effort (1pif can be complex JSON lines).
func DetectOnePassword1pif(data []byte) (int, bool) {
	text := string(data)
	if strings.Contains(text, ".1pif") || strings.Contains(strings.ToLower(text), "onepassword") || strings.Contains(text, `"password"`) {
		hits := detection.ExtractHighEntropyStrings(data, 12, 4.0)
		return hits, hits > 0
	}
	return 0, false
}

// ScanFile performs size gate, read, heuristic + format detection + registry known-match check.
// Returns a finding only if it crosses internal thresholds (suspicious name OR format match OR >= min entropy hits).
// All secret candidate hashing uses the provided registry (hash-only, never stores plaintext).
func ScanFile(path string, reg *registry.Registry) (*ResidueFinding, error) {
	// Explicitly skip symlinks (do not follow or process their targets). This mirrors
	// the walk-time skips in P1/P2 and prevents slurping sensitive files via links
	// placed in P2 surfaces (or passed via --file etc.). Lstat reports the link itself.
	if linfo, lerr := os.Lstat(path); lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}

	// TOCTOU note: between the Lstat symlink check (and the walk's de.Type() check
	// in manager) and the Stat/Open/ReadFile below, a local actor with write access
	// to the surface could swap the path for a symlink. Subsequent reads would then
	// follow. The window is narrow; declared P2 surfaces + Classifier (P1 authority)
	// + ignore patterns are the primary containment. We accept this (alpha, local
	// attacker model) rather than complicating with O_NOFOLLOW (portability) or
	// extra fstat-after-open checks. P1 has an analogous (walk decision vs. later
	// Open in collectHashesFromFile) window. Documented in CURRENT_STATE.md and
	// config.example.yaml.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}
	size := info.Size()
	if size == 0 || size > maxFileSizeBytes {
		return nil, nil
	}

	// quick binary-ish skip for obvious media/db (magic bytes)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 16)
	_, _ = f.Read(header)
	if isLikelyBinary(header) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	base := filepath.Base(path)
	suspiciousName, nameFormat := FilenameHeuristic(base)

	// Run detectors in priority order (specific first)
	var format string
	var entropyHits int
	var known int

	// Try specific
	if strings.HasSuffix(strings.ToLower(base), ".json") {
		if h, is := DetectBitwardenJSON(data); is || h > 0 {
			format = FormatBitwardenJSON
			entropyHits = h
		}
	}
	if format == "" && strings.HasSuffix(strings.ToLower(base), ".csv") {
		if h, is := DetectBitwardenCSV(data); is || h > 0 {
			format = FormatBitwardenCSV
			entropyHits = h
		} else if h, is := DetectDashlane(data); is || h > 0 {
			format = FormatDashlane
			entropyHits = h
		}
	}
	if format == "" && strings.HasSuffix(strings.ToLower(base), ".1pif") {
		if h, is := DetectOnePassword1pif(data); is || h > 0 {
			format = FormatOnePassword
			entropyHits = h
		}
	}

	// Generic high-entropy pass + Dashlane/others fallback
	if format == "" {
		entropyHits = detection.ExtractHighEntropyStrings(data, 12, 4.0)
		if entropyHits >= minHighEntropyHitsForGeneric {
			format = FormatGenericHighEnt
		} else if suspiciousName {
			format = nameFormat
		}
	}

	// If we have a format from name heuristic but no entropy yet, still count generic entropy
	if format == "" && suspiciousName {
		entropyHits = detection.ExtractHighEntropyStrings(data, 12, 4.0)
		format = nameFormat
	}

	if format == "" {
		// nothing interesting
		return nil, nil
	}

	// Use the shared detection package for candidate secret extraction + known count.
	_, known = detection.NewDetector().ExtractAndCountKnown(data, reg)

	// Decision gate: keep only if we have signal
	keep := false
	if known > 0 {
		keep = true
	} else if format == FormatBitwardenJSON || format == FormatBitwardenCSV || format == FormatDashlane || format == FormatOnePassword {
		keep = true
	} else if entropyHits >= minHighEntropyHitsForGeneric || suspiciousName {
		keep = true
	}

	if !keep {
		return nil, nil
	}

	conf := ConfMedium
	if known > 0 || (format != FormatGenericHighEnt && format != FormatSuspiciousName) {
		conf = ConfHigh
	}
	if entropyHits == 0 && known == 0 {
		conf = ConfLow
	}

	return &ResidueFinding{
		Location:     SafeLocation(path),
		Basename:     base,
		LastMod:      info.ModTime().UTC().Truncate(time.Second),
		Format:       format,
		Confidence:   conf,
		KnownMatches: known,
		EntropyHits:  entropyHits,
		Size:         size,
	}, nil
}

func isLikelyBinary(hdr []byte) bool {
	// very rough: null bytes or common binary magic
	if len(hdr) == 0 {
		return false
	}
	if hdr[0] == 0x00 || (len(hdr) > 3 && hdr[0] == 0x89 && hdr[1] == 0x50 && hdr[2] == 0x4e && hdr[3] == 0x47) { // png
		return true
	}
	if len(hdr) > 2 && hdr[0] == 0xff && hdr[1] == 0xd8 { // jpeg
		return true
	}
	// sqlite, zip, etc.
	if strings.HasPrefix(string(hdr), "SQLite") || (len(hdr) > 3 && hdr[0] == 0x50 && hdr[1] == 0x4b) {
		return true
	}
	// count nulls
	nulls := 0
	for _, b := range hdr {
		if b == 0 {
			nulls++
		}
	}
	return nulls > 2
}

// Note: SafeLocation is implemented in safe_names.go to keep concerns separated.
