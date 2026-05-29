package config

import "testing"

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SocketPath == "" || len(cfg.SkipDirs) == 0 || len(cfg.Pillar5Commands) == 0 {
		t.Error("defaults missing required fields")
	}
}

func TestLoad(t *testing.T) {
	_, _, _ = Load()
}

func TestSave(t *testing.T) {
	cfg := DefaultConfig()
	_ = cfg.Save()
}

func TestSave_ErrorPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SocketPath = string([]byte{0})
	_ = cfg.Save()
}