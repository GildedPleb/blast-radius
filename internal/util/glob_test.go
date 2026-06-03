package util

import (
	"testing"
)

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		home string
		want string
	}{
		{"empty", "", "", ""},
		{"absolute", "/foo/bar", "", "/foo/bar"},
		{"relative", "foo/bar", "", "foo/bar"},
		{"tilde alone", "~", "/home/user", "/home/user"},
		{"tilde slash", "~/", "/home/user", "/home/user"},
		{"tilde with path", "~/foo/bar", "/home/user", "/home/user/foo/bar"},
		{"tilde no home", "~/foo", "", "~/foo"},
		{"just tilde no home", "~", "", "~"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.home != "" {
				t.Setenv("HOME", tc.home)
			} else {
				t.Setenv("HOME", "")
			}
			got := ExpandPath(tc.in)
			if got != tc.want {
				t.Errorf("ExpandPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMatchesGlobPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"empty pattern", "", "anything", false},
		{"exact match", ".env", ".env", true},
		{"exact mismatch", ".env", ".env.local", false},
		{"star suffix", ".env*", ".env.local", true},
		{"star suffix no match", ".env*", "config.env", false},
		{"star prefix", "*_secret", "db_secret", true},
		{"star prefix no match", "*_secret", "secret_db", false},
		{"internal star", "foo*bar", "foo123bar", true},
		{"double star anywhere", "**/*_backup*", "deep/nested/creds_backup.json", true},
		{"double star prefix stripped", "**/*.bak", "file.bak", true},
		{"base name matching", "foo.log", "dir/sub/foo.log", true}, // via Base fallback
		// Explicit clean==name after **/ or ** strip (previously 0 block at the direct match after trim)
		{"double star exact after strip", "**/foo", "foo", true},
		{"double star bare exact", "**bar", "bar", true},
		// Cases crafted to miss filepath.Match (special chars like [ : make it strict) and hit pragmatic suffix/prefix + count==1
		{"pragmatic suffix special char", "AWS_*", "AWS_FOO:bar", true},
		{"pragmatic prefix special char", "*_end", "foo[bar_end", true},
		{"internal * with special (count1 path)", "pre*suf", "preX:suf", true},
		// Force pragmatic suf return by using [ that makes filepath.Match reject while HasPrefix logic accepts
		{"pragmatic suf [ bypass", "foo[*", "foo[bar", true},
		{"pragmatic pre [ bypass", "*]bar", "foo]bar", true},
		// Force count==1 and pre return blocks (Match+base miss due to [ in pattern)
		{"count1 [ bypass", "pre[*]suf", "pre[XX]suf", true},
		{"count1 ] [ bypass", "a]*[c", "a]b[c", true},
		// Force the HasPrefix(clean,"*") / pre pragmatic return (bypass Match+base with [ )
		{"pragmatic pre [ bypass2", "*[xSECRET", "foo[xSECRET", true},
		{"pragmatic pre [ dir bypass", "*[yy", "dir/xx[yy", true},
		{"complex internal", "prefix*suffix", "prefix-middle-suffix", true},
		// Additional cases to hit pragmatic fallback and internal-* logic (previously 0 blocks)
		{"pragmatic suffix after ** strip", "*_secret", "dir/creds_secret", true},
		{"internal star empty pre (suffix only)", "*bar", "123bar", true},
		{"internal star empty suf (prefix only)", "foo*", "foo123", true},
		{"pragmatic prefix on cleaned", "AWS_*", "AWS_FOO", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesGlobPattern(tc.input, tc.pattern)
			if got != tc.want {
				t.Errorf("MatchesGlobPattern(%q, %q) = %v, want %v", tc.input, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMatchesAnyGlobPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		patterns []string
		want     bool
	}{
		{"no patterns", "foo", nil, false},
		{"empty patterns", "foo", []string{}, false},
		{"one match", ".env.local", []string{".env*"}, true},
		{"one of many matches", "debug_creds.json", []string{"*.log", "**/debug*", "*.bak"}, true},
		{"none match", "normal.txt", []string{"*.log", "**/*secret*"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesAnyGlobPattern(tc.input, tc.patterns)
			if got != tc.want {
				t.Errorf("MatchesAnyGlobPattern(%q, %v) = %v, want %v", tc.input, tc.patterns, got, tc.want)
			}
		})
	}
}
