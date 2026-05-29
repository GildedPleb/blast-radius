package detection

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

// Default thresholds (hard-coded for v1 per plan + residue precedent).
// These can be made configurable via Options in later slices if needed.
const (
	defaultMinLen     = 8
	defaultMinEntropy = 4.0
)

// High-entropy regexes for common secret shapes (ported + kept from residue).
// These act as high-precision seeds before full entropy gating.
var (
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)
	reHex    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	reLong   = regexp.MustCompile(`[A-Za-z0-9._-]{24,}`)
)

// Options controls candidate extraction behavior.
type Options struct {
	MinLen     int
	MinEntropy float64
}

// Detector is the single logical unit for secret detection from arbitrary data.
// It is used by Pillars 2-5 (and future surfaces) to turn raw text into
// plausible secret value candidates that can then be hashed and checked
// against the registry.
type Detector struct {
	opts Options
}

// NewDetector returns a Detector with the provided options (or sensible defaults).
func NewDetector(opt ...Options) *Detector {
	d := &Detector{
		opts: Options{
			MinLen:     defaultMinLen,
			MinEntropy: defaultMinEntropy,
		},
	}
	if len(opt) > 0 {
		o := opt[0]
		if o.MinLen > 0 {
			d.opts.MinLen = o.MinLen
		}
		if o.MinEntropy > 0 {
			d.opts.MinEntropy = o.MinEntropy
		}
	}
	return d
}

// ComputeEntropy returns the Shannon entropy of s in bits per character.
// Ported from residue/detector.go with minor cleanup for clarity.
func ComputeEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	ent := 0.0
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// ExtractHighEntropyStrings finds distinct long strings matching common
// high-entropy secret shapes (base64, hex, long alphanum) that also meet
// the length + entropy gates. Used as a building block for both known
// and unknown-residue paths.
func ExtractHighEntropyStrings(data []byte, minLen int, minEntropy float64) int {
	text := string(data)
	cands := map[string]bool{}

	for _, re := range []*regexp.Regexp{reBase64, reHex, reLong} {
		for _, m := range re.FindAllString(text, -1) {
			if len(m) >= minLen && ComputeEntropy(m) >= minEntropy {
				cands[m] = true
			}
		}
	}
	return len(cands)
}

// ExtractCandidates returns a deduplicated list of strings from the input
// data that are plausible secret values (after applying wrapper stripping,
// assignment parsing, length + entropy filtering, and high-entropy regexes).
//
// This is the core primitive for all hygiene pillars. It deliberately
// focuses on *values*, not keys, and mirrors the normalization P1 uses
// when populating the registry (first = split + outer quote trim).
//
// It does NOT perform any registry lookups — that is the caller's
// responsibility (via FindKnownIn in later slices or direct hashing + Has).
//
// LRU caching of candidate extraction results (or repeated hash lookups)
// was considered for very large inputs (long history files, etc.), but is
// explicitly punted to V2 per review feedback. Current implementation is
// fast enough for realistic data sizes.
func (d *Detector) ExtractCandidates(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	text := string(data)
	cands := map[string]struct{}{}

	// 1. High-entropy regex seeds (strong signal shapes)
	for _, re := range []*regexp.Regexp{reBase64, reHex, reLong} {
		for _, m := range re.FindAllString(text, -1) {
			c := d.normalizeCandidate(m)
			// Regexes can match across "KEY=longvalue" when the whole thing looks like
			// a base64/hex blob (common with no spaces). Prefer the value side.
			c = d.extractValueSide(c)
			if d.isPlausibleSecret(c) {
				cands[c] = struct{}{}
			}
		}
	}

	// 2. Line-aware + delimiter-based extraction with wrapper handling.
	// This is the heart of robust detection for env output, history,
	// clipboard, exports, etc.
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle common command/output patterns explicitly (per taxonomy)
		// e.g. Authorization: Bearer <token>, token=..., --token=...
		for _, prefix := range []string{"Bearer ", "token=", "key=", "secret=", "api_key=", "--token=", "-t "} {
			if idx := strings.Index(line, prefix); idx != -1 {
				rest := line[idx+len(prefix):]
				// cut at next whitespace or common delimiter
				for i, r := range rest {
					if unicode.IsSpace(r) || r == '"' || r == '\'' || r == ',' || r == ';' {
						rest = rest[:i]
						break
					}
				}
				c := d.normalizeCandidate(rest)
				c = d.extractValueSide(c)
				if d.isPlausibleSecret(c) {
					cands[c] = struct{}{}
				}
			}
		}

		// Primary assignment / env / shell parsing (handles KEY=val, export KEY=val, etc.)
		// Use first '=' only to match P1 discovery behavior for values containing '='.
		if eq := strings.Index(line, "="); eq != -1 {
			rhs := strings.TrimSpace(line[eq+1:])
			c := d.normalizeCandidate(rhs)
			// NOTE: Do NOT call extractValueSide here. The RHS we just took after the
			// *first* = on the original line is already the value (P1 contract).
			// Calling it again would incorrectly chop values that legitimately contain =.
			if d.isPlausibleSecret(c) {
				cands[c] = struct{}{}
			}
		}

		// Fallback broad tokenization on the line for free-form text (clipboard, notes, etc.)
		// Guard: skip any token that still contains '=' — it should have been handled
		// by the primary assignment branch above (prevents full "KEY=val" from leaking
		// as a candidate, which would never match P1's value-only hashes).
		tokens := regexp.MustCompile(`[\s"'=,:\[\]{}|;]+`).Split(line, -1)
		for _, t := range tokens {
			if strings.Contains(t, "=") {
				continue
			}
			c := d.normalizeCandidate(t)
			if d.isPlausibleSecret(c) {
				cands[c] = struct{}{}
			}
		}
	}

	// Thorough plain-text word extraction (user feedback: be smart *and* thorough).
	// Split the entire input on whitespace and treat any reasonable-length "word"
	// as a candidate (subject to the same entropy/length/noise gates).
	// This catches bare secrets that appear as standalone tokens in logs, notes,
	// pasted terminal output, history lines without clear structure, etc.
	// We do this *after* the smarter context-aware passes so we get the best of
	// both worlds without excessive noise from the broad net.
	for _, word := range strings.Fields(text) {
		// Guard: same as the per-line fallback — full "KEY=val" forms should have
		// been handled (or rejected) by earlier logic.
		if strings.Contains(word, "=") {
			continue
		}
		// Further split on a few common punctuation characters that frequently
		// act as token boundaries in plain text / logs even without whitespace.
		for _, sub := range regexp.MustCompile(`[,:;]+`).Split(word, -1) {
			c := d.normalizeCandidate(sub)
			if d.isPlausibleSecret(c) {
				cands[c] = struct{}{}
			}
		}
	}

	// Structured data extraction (JSON etc.) — especially valuable for Pillar 2
	// residue scanning of vault exports. We walk the structure and pull actual
	// string values rather than doing crude text splitting that can fragment JSON.
	d.extractStructuredCandidates(text, cands)

	// Convert to sorted slice for deterministic output (nice for tests)
	out := make([]string, 0, len(cands))
	for c := range cands {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// normalizeCandidate applies the common wrapper stripping that makes
// matching against P1-populated hashes reliable.
func (d *Detector) normalizeCandidate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Repeatedly strip common outer quote pairs
	for {
		trimmed := false
		if len(s) >= 2 {
			first, last := s[0], s[len(s)-1]
			if (first == '"' && last == '"') ||
				(first == '\'' && last == '\'') ||
				(first == '`' && last == '`') {
				s = s[1 : len(s)-1]
				trimmed = true
			}
		}
		if !trimmed {
			break
		}
	}

	return strings.TrimSpace(s)
}

// extractValueSide is a helper for cases where a regex or other broad match
// captured a full "KEY=longsecretvalue" or "token=..." blob because the
// characters were in the allowed regex class. It prefers the portion after
// the first '=' (matching P1 discovery) and re-normalizes.
func (d *Detector) extractValueSide(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	// Take after the first = (same policy as P1 .env parsing)
	if idx := strings.Index(s, "="); idx != -1 {
		rhs := strings.TrimSpace(s[idx+1:])
		return d.normalizeCandidate(rhs)
	}
	return s
}

// isPlausibleSecret applies length + entropy gate (the core filter).
// This is deliberately simple and strict in foundation slice.
func (d *Detector) isPlausibleSecret(s string) bool {
	if len(s) < d.opts.MinLen {
		return false
	}
	// Reject obvious non-secrets early
	if isCommonNoise(s) {
		return false
	}
	return ComputeEntropy(s) >= d.opts.MinEntropy
}

// isCommonNoise filters out very common low-value strings that survive
// entropy gates in practice (e.g. repeated chars, common placeholders).
// This is a small, conservative starting allow/deny set per lessons section.
func isCommonNoise(s string) bool {
	lower := strings.ToLower(s)
	noise := []string{
		"password", "secret", "changeme", "your_api_key", "example",
		"test", "demo", "placeholder", "insert", "here",
	}
	for _, n := range noise {
		if lower == n || strings.Contains(lower, n) && len(s) < 20 {
			return true
		}
	}
	// Reject strings that are just the same char repeated
	if len(s) > 0 {
		first := s[0]
		allSame := true
		for i := 1; i < len(s); i++ {
			if s[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// extractStructuredCandidates attempts to parse the text as JSON (or other
// structured formats in the future) and extracts plausible secret values
// from the actual data structures rather than raw text splitting.
// This is particularly useful for Bitwarden-style exports and similar
// credential dumps.
func (d *Detector) extractStructuredCandidates(text string, cands map[string]struct{}) {
	// Try JSON first — common for vault exports
	var root any
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		return
	}

	// Collect string values, with awareness of the parent key name.
	collectJSONStrings(root, "", func(value string, key string) {
		c := d.normalizeCandidate(value)
		c = d.extractValueSide(c)

		// If this value came from a known secret-related key, be more lenient
		// (lower the bar for acceptance). This is a major quality improvement
		// for structured credential data.
		if isHighValueKey(key) {
			if len(c) >= d.opts.MinLen && !isCommonNoise(c) {
				cands[c] = struct{}{}
				return
			}
		}

		if d.isPlausibleSecret(c) {
			cands[c] = struct{}{}
		}
	})
}

// highValueKeys are field names that strongly indicate the associated value
// is likely a secret. Values under these keys get preferential treatment.
var highValueKeys = map[string]bool{
	"password": true, "secret": true, "token": true, "credential": true,
	"api_key": true, "apikey": true, "private_key": true, "privatekey": true,
	"access_token": true, "accesstoken": true, "auth_token": true,
	"client_secret": true, "clientsecret": true,
}

// isHighValueKey returns true if the given key name suggests the value is a secret.
func isHighValueKey(key string) bool {
	if key == "" {
		return false
	}
	lower := strings.ToLower(key)
	if highValueKeys[lower] {
		return true
	}
	// Also catch common patterns like "my_password", "aws_secret_key", etc.
	for k := range highValueKeys {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// collectJSONStrings walks a JSON structure and calls the collector with
// the string value + the name of the key it was found under (if any).
func collectJSONStrings(v any, currentKey string, collect func(value string, key string)) {
	switch val := v.(type) {
	case string:
		collect(val, currentKey)
	case []any:
		for _, item := range val {
			collectJSONStrings(item, "", collect) // array elements have no key
		}
	case map[string]any:
		for k, item := range val {
			collectJSONStrings(item, k, collect)
		}
	}
}

// FindKnownIn extracts candidates from data, hashes each, and returns the
// SecretHashes that the provided lookup function says are known in the registry.
//
// The lookup func lets this package stay decoupled from any particular
// registry instance (CLI can use it with CHECK_HASH responses; daemon code
// can pass reg.Has directly).
func (d *Detector) FindKnownIn(data []byte, lookup func(registry.SecretHash) bool) []registry.SecretHash {
	if lookup == nil {
		return nil
	}
	cands := d.ExtractCandidates(data)
	var hits []registry.SecretHash
	seen := map[registry.SecretHash]bool{}
	for _, c := range cands {
		h := registry.HashValue([]byte(c))
		if lookup(h) && !seen[h] {
			seen[h] = true
			hits = append(hits, h)
		}
	}
	return hits
}

// CountKnownIn is a convenience for daemon-side callers that already have a *Registry.
func (d *Detector) CountKnownIn(data []byte, reg *registry.Registry) int {
	if reg == nil {
		return 0
	}
	return len(d.FindKnownIn(data, reg.Has))
}

// ExtractAndCountKnown extracts plausible secret candidates and counts how many
// of them are present in the given registry. This is a convenience helper that
// reduces boilerplate in daemon-side pillars (P2 residue and P3 history scrub).
func (d *Detector) ExtractAndCountKnown(data []byte, reg *registry.Registry) (candidates []string, knownCount int) {
	if reg == nil {
		return nil, 0
	}
	cands := d.ExtractCandidates(data)
	known := 0
	for _, c := range cands {
		h := registry.HashValue([]byte(c))
		if reg.Has(h) {
			known++
		}
	}
	return cands, known
}
