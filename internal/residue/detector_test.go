package residue

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestComputeEntropy(t *testing.T) {
	tests := []struct {
		s    string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"abcd", 2.0}, // exactly 2 for 4 distinct
		{"password123", 3.0}, // approximate; just > low
		{"AKIAIOSFODNN7EXAMPLE", 3.5}, // high enough for our threshold
	}
	for _, tc := range tests {
		got := ComputeEntropy(tc.s)
		if got < tc.want-0.6 { // loose for float
			t.Errorf("ComputeEntropy(%q) = %.2f, want >= %.1f", tc.s, got, tc.want)
		}
	}
}

func TestFilenameHeuristic(t *testing.T) {
	cfg := config.ResidueHunterConfig{FlagSuspiciousFilenames: true}
	cases := []struct {
		name string
		want bool
	}{
		{"bitwarden_export_2025-01-01.json", true},
		{"my_passwords.csv", true},
		{"secrets.txt", true},
		{"cat.jpg", false},
		{"report.pdf", false},
		{"vimrc.swp", true},
		{".zshrc~", true},
	}
	for _, c := range cases {
		got, _ := FilenameHeuristic(c.name, cfg)
		if got != c.want {
			t.Errorf("FilenameHeuristic(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExtractHighEntropyStrings(t *testing.T) {
	data := []byte(`password=AKIAIOSFODNN7EXAMPLESECRETKEY
token: 0123456789abcdef0123456789abcdef01234567
normal text here and some base64 ZmFrZVRva2VuVmFsdWVPZlZlcnlMb25nU2VjcmV0S2V5MTIzNDU2Nzg=`)
	cnt := ExtractHighEntropyStrings(data, 12)
	if cnt < 1 {
		t.Errorf("expected >=1 high entropy hits, got %d", cnt)
	}
}

func TestDetectBitwardenJSON(t *testing.T) {
	bw := []byte(`{
		"encrypted": false,
		"items": [
			{"login": {"username": "u", "password": "supersecretvalue123456"}},
			{"fields": [{"value": "anotherHIGHENTROPYTOKENTHATISLONG"}]}
		]
	}`)
	hits, isExport := DetectBitwardenJSON(bw)
	if !isExport || hits < 1 {
		t.Errorf("DetectBitwardenJSON failed: hits=%d isExport=%v", hits, isExport)
	}
}

func TestSafeLocation(t *testing.T) {
	// We can't easily mock HOME in all envs; just exercise the function
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME")
	}
	p := filepath.Join(home, "Downloads", "bitwarden_export_2024.json")
	loc := SafeLocation(p)
	if loc != "Downloads/bitwarden_export_2024.json" {
		t.Errorf("SafeLocation gave %q", loc)
	}
}

func TestScanFile_Synthetic(t *testing.T) {
	reg := registry.New()
	// Plant a known secret
	reg.Add(registry.HashValue([]byte("supersecretvalue123456")), "p1")

	dir := t.TempDir()
	f := filepath.Join(dir, "bitwarden_export_test.json")
	content := `{"encrypted":false,"items":[{"login":{"password":"supersecretvalue123456"}}]}`
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.ResidueHunterConfig{Enabled: true, FlagSuspiciousFilenames: true}
	finding, err := ScanFile(f, cfg, reg)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil {
		t.Fatal("expected finding for synthetic export")
	}
	if finding.KnownMatches != 1 {
		t.Errorf("expected 1 known match, got %d", finding.KnownMatches)
	}
	if finding.Format != FormatBitwardenJSON {
		t.Errorf("format = %s", finding.Format)
	}
	if finding.Confidence != ConfHigh {
		t.Errorf("conf = %s", finding.Confidence)
	}
}

func TestScanFile_IgnoresLargeBinary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big.bin")
	data := make([]byte, 20*1024*1024) // > max
	if err := os.WriteFile(f, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ResidueHunterConfig{Enabled: true}
	finding, _ := ScanFile(f, cfg, registry.New())
	if finding != nil {
		t.Error("should skip large file")
	}
}

func TestScanFile_RespectsModTimeAndSize(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "creds.json")
	os.WriteFile(f, []byte(`{"password":"x"}`), 0600)
	cfg := config.ResidueHunterConfig{Enabled: true, FlagSuspiciousFilenames: true}
	finding, _ := ScanFile(f, cfg, registry.New())
	if finding == nil {
		t.Fatal("expected at least name-based hit")
	}
	if finding.Size == 0 || finding.LastMod.IsZero() {
		t.Error("metadata missing")
	}
	// LastMod should be recent
	if time.Since(finding.LastMod) > 5*time.Minute {
		t.Error("last_mod too old for fresh test file")
	}
}
