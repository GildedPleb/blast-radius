package cli

import "testing"

func TestCLI_PackageLoads(t *testing.T) {
	// Smoke test that the package and DI vars initialize
	_ = configLoad
	_ = netDialTimeout
}

func TestRunRedact_GuardFailsCleanly(t *testing.T) {
	resetTestOverrides()
	// In test env there is normally no recorder socket for the synthetic TTY.
	// RunRedact should hit ProtectionModeGuard and call osExit(1) which is no-op in tests.
	// We just ensure it does not panic.
	RunRedact(nil)
	RunRedact([]string{"2"})
}

// Note: full happy-path testing of RunRedact (clear + streaming replay) requires a live
// recorder socket at the TTY-derived path and is covered by integration / manual tests in Phase E.
// The guard-failure path and basic wiring are exercised above. The mock sender is registered
// for future deeper tests that synthesize the socket path.
