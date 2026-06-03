package detection

import (
	"sort"
	"strings"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestComputeEntropy(t *testing.T) {
	tests := []struct {
		s    string
		want float64 // lower bound (we use loose check like original residue tests)
	}{
		{"", 0},
		{"aaaa", 0},
		{"abcd", 2.0},
		{"password123", 3.0},
		{"AKIAIOSFODNN7EXAMPLE", 3.5},
		{"super-long-high-entropy-value-ABCDEF1234567890", 4.5},
	}
	for _, tc := range tests {
		got := ComputeEntropy(tc.s)
		if got < tc.want-0.6 {
			t.Errorf("ComputeEntropy(%q) = %.2f, want >= %.1f", tc.s, got, tc.want)
		}
	}
}

func TestExtractHighEntropyStrings(t *testing.T) {
	data := []byte(`password=AKIAIOSFODNN7EXAMPLESECRETKEY
token: 0123456789abcdef0123456789abcdef01234567
normal text here and some base64 ZmFrZVRva2VuVmFsdWVPZlZlcnlMb25nU2VjcmV0S2V5MTIzNDU2Nzg=`)
	cnt := ExtractHighEntropyStrings(data, 12, 4.0)
	if cnt < 1 {
		t.Errorf("expected >=1 high entropy hits, got %d", cnt)
	}
}

func TestDetector_ExtractCandidates_WrappersAndContext(t *testing.T) {
	d := NewDetector()

	// This table encodes the taxonomy from the plan (the part the user loved).
	// Each case tests realistic ways secrets appear in P3/P4/P5/P2 surfaces.
	cases := []struct {
		name     string
		input    string
		contains []string // candidates we expect to be extracted (after normalization)
		absent   []string // things that should NOT appear as candidates
	}{
		{
			name:     "bare high entropy value",
			input:    "superlonghighentropysecretvalue1234567890ABCDEF",
			contains: []string{"superlonghighentropysecretvalue1234567890ABCDEF"},
		},
		{
			name:     "env style KEY=val (unquoted)",
			input:    "TEST_SECRET=super-long-high-entropy-value-ABCDEF1234567890",
			contains: []string{"super-long-high-entropy-value-ABCDEF1234567890"},
		},
		{
			name:     "env style with double quotes (P1 normalization must match)",
			input:    `DATABASE_URL="postgres://user:super-long-high-entropy-value-ABCDEF1234567890@host/db"`,
			contains: []string{"postgres://user:super-long-high-entropy-value-ABCDEF1234567890@host/db"},
		},
		{
			name:     "env style with single quotes",
			input:    "API_KEY='sk-1234567890abcdefABCDEF1234567890abcdef1234'",
			contains: []string{"sk-1234567890abcdefABCDEF1234567890abcdef1234"},
		},
		{
			name:     "export statement (history + shell)",
			input:    "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLESECRETKEY1234567",
			contains: []string{"AKIAIOSFODNN7EXAMPLESECRETKEY1234567"},
		},
		{
			name:     "command line flag --token=",
			input:    "curl -H \"Authorization: Bearer sk-live-1234567890abcdefABCDEF1234567890\" https://api.example.com",
			contains: []string{"sk-live-1234567890abcdefABCDEF1234567890"},
		},
		{
			name:     "Authorization Bearer header (clipboard or history)",
			input:    "Authorization: Bearer ghp_1234567890abcdefABCDEF1234567890abcdef",
			contains: []string{"ghp_1234567890abcdefABCDEF1234567890abcdef"},
		},
		{
			name:     "JSON password field (residue / clipboard paste)",
			input:    `{"login":{"username":"u","password":"supersecretvalue1234567890ABCDEF"}}`,
			contains: []string{"supersecretvalue1234567890ABCDEF"},
		},
		{
			name:     "value with embedded equals (P1 behavior: after first =)",
			input:    "COMPLEX=part1=part2=super-long-secret-ABCDEF1234567890",
			contains: []string{"part1=part2=super-long-secret-ABCDEF1234567890"},
		},
		{
			name:   "low entropy noise is filtered",
			input:  "password=aaaaaaaaaaaaaaa\nnormal=lowentropyvalue",
			absent: []string{"aaaaaaaaaaaaaaa", "lowentropyvalue"},
		},
		{
			name:   "common placeholder noise filtered",
			input:  "API_KEY=your_api_key_here\nTOKEN=changeme1234567890",
			absent: []string{"your_api_key_here", "changeme1234567890"},
		},
		{
			name:  "multiple candidates in one blob (printenv-like + history mix)",
			input: "FOO=short\nREAL_SECRET=super-long-high-entropy-value-ABCDEF1234567890\nTOKEN=anotherHIGHENTROPYTOKENTHATISLONGENOUGH123",
			contains: []string{
				"super-long-high-entropy-value-ABCDEF1234567890",
				"anotherHIGHENTROPYTOKENTHATISLONGENOUGH123",
			},
		},
		{
			name:     "clipboard multi-line config paste",
			input:    "# some config\nexport DB_PASS='db-pass-1234567890ABCDEFghijklmnop'\nDEBUG=false",
			contains: []string{"db-pass-1234567890ABCDEFghijklmnop"},
		},
		{
			name:     "plain whitespace-separated word (thorough fallback)",
			input:    "some log line here with a bare secret abcdef1234567890GHIJKLmnopqrstuvwxyz1234 in the middle of text",
			contains: []string{"abcdef1234567890GHIJKLmnopqrstuvwxyz1234"},
		},
		{
			name:     "plain text with punctuation boundaries",
			input:    "error: token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDEF failed",
			contains: []string{"ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.ExtractCandidates([]byte(tc.input))

			for _, want := range tc.contains {
				found := false
				for _, c := range got {
					if c == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ExtractCandidates(%q) missing expected candidate %q\ngot: %v", tc.input, want, got)
				}
			}

			for _, bad := range tc.absent {
				for _, c := range got {
					if c == bad {
						t.Errorf("ExtractCandidates(%q) should not have produced noise candidate %q", tc.input, bad)
					}
				}
			}
		})
	}
}

func TestDetector_ExtractCandidates_DedupAndOrdering(t *testing.T) {
	d := NewDetector()
	input := "SECRET=abc123def456ghi789jkl012mno345pqr678\nTOKEN=abc123def456ghi789jkl012mno345pqr678\nOTHER=abc123def456ghi789jkl012mno345pqr678"
	got := d.ExtractCandidates([]byte(input))

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 deduped candidate, got %d: %v", len(got), got)
	}
	if got[0] != "abc123def456ghi789jkl012mno345pqr678" {
		t.Errorf("unexpected candidate: %s", got[0])
	}
}

func TestDetector_CustomOptions(t *testing.T) {
	// Use a very high-entropy value to survive strict gates reliably in foundation.
	// Real secret-like strings (mixed case, no repeats, good charset) pass easily.
	highEntropy := "Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU8iO3pL5kJ7hG2fD4sA"

	dLoose := NewDetector() // defaults
	dStrict := NewDetector(Options{MinLen: 30, MinEntropy: 5.5})

	input := "SHORT=abc123def456\nLONG=" + highEntropy

	gotLoose := dLoose.ExtractCandidates([]byte(input))
	gotStrict := dStrict.ExtractCandidates([]byte(input))

	// Loose settings should surface the long high-entropy value
	foundLoose := false
	for _, c := range gotLoose {
		if c == highEntropy {
			foundLoose = true
		}
	}
	if !foundLoose {
		t.Errorf("default detector should surface high-entropy value, got: %v", gotLoose)
	}

	// Strict settings may return 0 or the value; the important property is it never
	// returns the short low-entropy noise.
	for _, c := range gotStrict {
		if c == "abc123def456" || len(c) < 30 {
			t.Errorf("strict detector should not have returned low-value candidate %q", c)
		}
	}
}

func TestDetector_EmptyAndBinaryish(t *testing.T) {
	d := NewDetector()

	if len(d.ExtractCandidates(nil)) != 0 {
		t.Error("nil input should yield no candidates")
	}
	if len(d.ExtractCandidates([]byte{})) != 0 {
		t.Error("empty input should yield no candidates")
	}
	// Binary-ish content should still be processed as text (binary gate lives in residue for now)
	bin := []byte{0x00, 0x89, 0x50, 0x4e, 0x47, 0x00}
	// We don't aggressively drop here in foundation; just ensure it doesn't panic
	_ = d.ExtractCandidates(bin)
}

// Helper to make golden-style assertions easier in future slices
func sortedCandidates(c []string) []string {
	cp := append([]string(nil), c...)
	sort.Strings(cp)
	return cp
}

func TestDetector_FindKnownIn_And_CountKnownIn(t *testing.T) {
	reg := registry.New()
	secret1 := "super-long-high-entropy-value-ABCDEF1234567890"
	secret2 := "anotherHIGHENTROPYTOKENTHATISLONGENOUGH1234567"
	reg.Add(registry.HashValue([]byte(secret1)), "proj1")
	reg.Add(registry.HashValue([]byte(secret2)), "proj2")

	d := NewDetector()

	// Mixed content that should yield exactly the two known secrets
	input := `printenv output:
FOO=not-a-secret
REAL_SECRET=` + secret1 + `
TOKEN=` + secret2 + `
OTHER=lowentropy

Also in clipboard:
export AWS_SECRET=` + secret1

	hits := d.FindKnownIn([]byte(input), reg.Has)
	if len(hits) != 2 {
		t.Fatalf("expected 2 known hits, got %d: %v", len(hits), hits)
	}

	count := d.CountKnownIn([]byte(input), reg)
	if count != 2 {
		t.Errorf("CountKnownIn = %d, want 2", count)
	}

	// No false positives on noise
	noiseInput := "password=changeme\nDEBUG=false\nshort=abc"
	if c := d.CountKnownIn([]byte(noiseInput), reg); c != 0 {
		t.Errorf("CountKnownIn on pure noise returned %d, want 0", c)
	}

	// Nil registry path for CountKnownIn
	if c := d.CountKnownIn([]byte("some data"), nil); c != 0 {
		t.Errorf("CountKnownIn with nil registry should return 0, got %d", c)
	}

	// Nil lookup path for FindKnownIn
	if hits := d.FindKnownIn([]byte("some data with a value"), nil); len(hits) != 0 {
		t.Errorf("FindKnownIn with nil lookup should return empty, got %d hits", len(hits))
	}
}

func TestDetector_ExtractAndCountKnown(t *testing.T) {
	reg := registry.New()
	secret := "Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU8iO3pL5kJ7hG2fD4sA"
	reg.Add(registry.HashValue([]byte(secret)), "proj1")

	d := NewDetector()

	input := `{"password":"` + secret + `","normal":"foo"}`

	cands, known := d.ExtractAndCountKnown([]byte(input), reg)
	if len(cands) == 0 {
		t.Error("expected some candidates from JSON input")
	}
	if known != 1 {
		t.Errorf("expected 1 known secret, got %d", known)
	}

	// Nil registry case
	_, k := d.ExtractAndCountKnown([]byte("data"), nil)
	if k != 0 {
		t.Errorf("expected 0 known with nil registry, got %d", k)
	}
}

func TestDetector_KeyAwareJSONExtraction(t *testing.T) {
	d := NewDetector()

	// A value under a high-value key that would normally be filtered by entropy
	lowEntropySecret := "password123456789012345" // contains "password", reasonably long

	input := `{
		"normal_field": "short",
		"password": "` + lowEntropySecret + `",
		"api_key": "anotherlowentropybutacceptablevalue123"
	}`

	cands := d.ExtractCandidates([]byte(input))

	foundPassword := false
	foundApiKey := false
	for _, c := range cands {
		if c == lowEntropySecret {
			foundPassword = true
		}
		if strings.Contains(c, "anotherlowentropybutacceptablevalue") {
			foundApiKey = true
		}
	}

	if !foundPassword {
		t.Error("expected value under 'password' key to be extracted via key-aware logic")
	}
	if !foundApiKey {
		t.Error("expected value under 'api_key' key to be extracted via key-aware logic")
	}

	// Test that isHighValueKey works for common patterns (indirectly exercised above)
	// We can also directly test the helper since it's same package
	if !isHighValueKey("my_secret_key") {
		t.Error("expected 'my_secret_key' to be recognized as high value key")
	}
	if isHighValueKey("normal_field") {
		t.Error("'normal_field' should not be treated as high value key")
	}

	// Exercise more of the JSON walker (arrays + nested objects)
	arrayInput := `["normal", {"secret": "Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU"}]`
	cands = d.ExtractCandidates([]byte(arrayInput))
	found := false
	for _, c := range cands {
		if strings.Contains(c, "Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU") {
			found = true
		}
	}
	if !found {
		t.Error("expected to extract secret value from within a JSON array/nested object")
	}

	// Non-high-value key with plausible secret value: exercises the isPlausibleSecret
	// path inside extractStructuredCandidates (previously unreachable; high-value keys
	// take the early-return branch).
	plainKeyInput := `{"normal_field":"Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU8iO3pL5kJ7hG2fD4sA","other":"short"}`
	cands = d.ExtractCandidates([]byte(plainKeyInput))
	foundPlain := false
	for _, c := range cands {
		if strings.Contains(c, "Kx7pQ9mR2vL8nT4wY6zX3cV5bN1mJ0hGfD9sA7pQ4rW2eT6yU8iO3pL5kJ7hG2fD4sA") {
			foundPlain = true
		}
	}
	if !foundPlain {
		t.Error("expected to extract plausible secret from non-high-value JSON key via isPlausibleSecret path")
	}
}

// TestDetector_extractValueSide exercises the helper that recovers values
// when broad regexes over-capture "KEY=secret" strings.
func TestDetector_extractValueSide(t *testing.T) {
	d := NewDetector()

	cases := []struct {
		input    string
		expected string
	}{
		{"SECRET=realvalue1234567890", "realvalue1234567890"},
		{"token=ghp_abcdefghijklmnopqrstuvwxyz123456", "ghp_abcdefghijklmnopqrstuvwxyz123456"},
		{"noequals", "noequals"}, // should be unchanged
		{"KEY=val=with=equals1234567890", "val=with=equals1234567890"},
		{"=onlyequals", "onlyequals"}, // after stripping leading = via normalization
		{"  SPACED =  valwithspaces1234567890  ", "valwithspaces1234567890"}, // exercises trim + side
	}

	for _, tc := range cases {
		got := d.extractValueSide(tc.input) // note: this is unexported, but same package so ok for white-box test
		if got != tc.expected {
			t.Errorf("extractValueSide(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
