package residue

import (
	"os"
	"path/filepath"
)

// =============================================================================
// TEST HOOKS
// All test-only overrides live here so manager.go and scan.go stay clean.
// These are unexported and only used within the package (including _test.go).
// =============================================================================

// test hook to control UserHomeDir for fast coverage of len(targets)==0 without walking real home.
var userHomeDir = os.UserHomeDir

// test hook for filepath.Abs (used in effectiveP2Surfaces) to cover the error-continue path.
var filepathAbs = filepath.Abs

// test hook to cover the os.ReadFile error path inside ScanFile (the line after header inspection).
// This gives deterministic coverage of the `return nil, err` without TOCTOU races or root permission quirks.
var readFile = os.ReadFile

// test hook for DetectOnePassword1pif so we can deterministically cover
// the .1pif branch (the detector can be strict on real exports).
var detectOnePassword1pif = DetectOnePassword1pif

// test hook to control the final keep decision in ScanFile.
// This lets us deterministically hit the `if !keep { return nil, nil }` path.
var decideKeep = func(known int, format string, entropyHits int, suspiciousName bool) bool {
	if known > 0 {
		return true
	}
	if format == FormatBitwardenJSON || format == FormatBitwardenCSV || format == FormatDashlane || format == FormatOnePassword {
		return true
	}
	if entropyHits >= minHighEntropyHitsForGeneric || suspiciousName {
		return true
	}
	return false
}

// test hook to force the "suspicious name but no format yet" fallback path.
// This guarantees we execute the ExtractHighEntropyStrings + format = nameFormat lines.
var getSuspiciousNameResult = func(base string) (suspicious bool, nameFormat string) {
	return false, ""
}

var walkDir = filepath.WalkDir
