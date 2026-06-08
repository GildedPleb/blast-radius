package cli

import (
	"errors"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
)

func TestRunConfig(t *testing.T) {
	t.Run("no_args_and_unknown_subcommand", func(t *testing.T) {
		defer resetTestOverrides(t)
		restore := silenceOutput()
		defer restore()

		RunConfig(nil)
		RunConfig([]string{"unknown"})
	})

	t.Run("load_error_and_nil_cfg", func(t *testing.T) {
		defer resetTestOverrides(t)
		restore := silenceOutput()
		defer restore()

		// Override the var that resetTestOverrides sets
		configLoad = func() (*config.Config, string, error) {
			return nil, "", errors.New("forced load error for coverage")
		}

		RunConfig(nil)
		// This hits both:
		//   if cfg == nil { cfg = &config.Config{} }
		//   if loadErr != nil { print the Note line }
	})

	t.Run("pillar1_roots_present", func(t *testing.T) {
		defer resetTestOverrides(t)
		restore := silenceOutput()
		defer restore()

		cfgWithRoots := &config.Config{
			Pillar1: config.Pillar1Config{
				Sources: map[string]config.SourceConfig{
					"env": {
						Options: map[string]any{
							"project_roots": []string{"/tmp/testproj"},
						},
					},
				},
			},
		}

		configLoad = func() (*config.Config, string, error) {
			return cfgWithRoots, "/tmp/fake.yaml", nil
		}

		RunConfig(nil)
		// This hits the `if len(envOpts.ProjectRoots) > 0` branch
	})
}
