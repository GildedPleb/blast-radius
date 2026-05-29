package residue

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestNewManager(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)
	if m == nil {
		t.Fatal("nil manager")
	}
}

func TestRunScan_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ResidueHunter.Enabled = false
	m := NewManager(cfg, registry.New())
	res := m.RunScan()
	if res == nil || len(res.Errors) == 0 {
		t.Error("expected disabled marker in errors")
	}
	if len(res.Findings) != 0 {
		t.Error("disabled scan must return zero findings")
	}
}

func TestCrumbsSummary_NeverScanned(t *testing.T) {
	m := NewManager(config.DefaultConfig(), registry.New())
	s := m.CrumbsSummary()
	if s["status"] != "never_scanned" {
		t.Errorf("got %v", s)
	}
}

func TestExpandPath(t *testing.T) {
	// indirect via RunScan with ~ paths (no crash)
	cfg := config.DefaultConfig()
	cfg.ResidueHunter.Enabled = true
	cfg.ResidueHunter.TargetDirs = []string{"~/Downloads", "~/tmp/does-not-exist-xyz"}
	m := NewManager(cfg, registry.New())
	_ = m.RunScan() // should not panic, just collect errors for missing dirs
}
