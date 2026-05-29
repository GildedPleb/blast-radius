package cli

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestPrintHelp(t *testing.T) {
	restore := silenceOutput()
	defer restore()
	PrintHelp()
}

func TestPrintHelp_NilCfgAndEmptyRoots(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// nil cfg path
	configLoad = func() (*config.Config, string, error) { return nil, "", nil }
	PrintHelp()

	// empty roots path
	configLoad = func() (*config.Config, string, error) {
		return &config.Config{ProjectRoots: []string{}}, "/p", nil
	}
	PrintHelp()
}
