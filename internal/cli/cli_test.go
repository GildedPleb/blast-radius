package cli

import "testing"

func TestCLI_PackageLoads(t *testing.T) {
	// Smoke test that the package and DI vars initialize
	_ = configLoad
	_ = netDialTimeout
}