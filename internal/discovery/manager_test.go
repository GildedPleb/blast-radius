package discovery

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestNewScanner(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	s := NewScanner(cfg, reg)
	if s == nil {
		t.Error("scanner nil")
	}
}

func TestNewManager(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	m := NewManager(cfg, reg)
	if m == nil {
		t.Error("manager nil")
	}
}