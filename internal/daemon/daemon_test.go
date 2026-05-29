package daemon

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestNewDaemon(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)
	if d == nil || d.registry == nil || d.discovery == nil || d.residue == nil {
		t.Error("daemon not initialized (missing residue manager)")
	}
}

func TestDaemon_Run_Errors(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SocketPath = "/root/no-permission.sock"
	reg := registry.New()
	d := New(cfg, reg)
	err := d.Run()
	if err == nil {
		t.Error("expected error on bad socket path")
	}
}

func TestDaemon_Close(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)
	d.Close()
}