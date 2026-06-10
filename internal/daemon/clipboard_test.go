package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

type fakeTicker struct {
	ch chan time.Time
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		cfg: &config.Config{
			Pillar5: config.Pillar5Config{
				Enabled:                 true, // enable the pillar so monitor/scan logic runs in tests
				MonitorEnabled:          true,
				RedactPlaceholder:       "[REDACTED]",
				RedactTimeoutSeconds:    0,
				FullClearTimeoutSeconds: 0,
			},
		},
		registry: registry.New(),
		shutdown: make(chan struct{}),
	}
}

func newTestDaemonWithSecret(t *testing.T, planted string) (*Daemon, string, string) {
	t.Helper()
	d := newTestDaemon(t)
	if planted == "" {
		planted = "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	}
	content, epoch := setupSecretEpoch(d, planted)
	return d, content, epoch
}

func setupDaemonWithSecretAndPbpaste(t *testing.T) (*Daemon, string, string) {
	t.Helper()
	d, content, epoch := newTestDaemonWithSecret(t, "")
	overrideClipboardSeams(t,
		func() ([]byte, error) { return []byte(content), nil },
		nil,
	)
	return d, content, epoch
}

func setClipboardState(d *Daemon, lastHash string, lastChange time.Time, secretCount int, redacted, cleared bool) {
	d.clipboardMu.Lock()
	d.clipboardLastHash = lastHash
	d.clipboardLastChange = lastChange
	d.clipboardSecretCount = secretCount
	d.clipboardRedacted = redacted
	d.clipboardCleared = cleared
	d.clipboardMu.Unlock()
}

func overrideSeams(
	t *testing.T,
	pbpaste func() ([]byte, error),
	pbcopy func([]byte) error,
	osascript func(string) error,
	afplay func() error,
) {
	t.Helper()
	origPaste := pbpasteFunc
	origCopy := pbcopyFunc
	origScript := osascriptFunc
	origPlay := afplayFunc

	if pbpaste != nil {
		pbpasteFunc = pbpaste
	}
	if pbcopy != nil {
		pbcopyFunc = pbcopy
	}
	if osascript != nil {
		osascriptFunc = osascript
	}
	if afplay != nil {
		afplayFunc = afplay
	}

	t.Cleanup(func() {
		pbpasteFunc = origPaste
		pbcopyFunc = origCopy
		osascriptFunc = origScript
		afplayFunc = origPlay
	})
}

func overrideClipboardSeams(t *testing.T, pbpaste func() ([]byte, error), pbcopy func([]byte) error) {
	overrideSeams(t, pbpaste, pbcopy, nil, nil)
}

func overridePbpaste(t *testing.T, fn func() ([]byte, error)) {
	overrideClipboardSeams(t, fn, nil)
}

func overridePbcopy(t *testing.T, fn func([]byte) error) {
	overrideClipboardSeams(t, nil, fn)
}

func overrideAlertSeams(t *testing.T, osascript func(string) error, afplay func() error) {
	overrideSeams(t, nil, nil, osascript, afplay)
}

func overrideExtractCandidates(t *testing.T, f func([]byte) []string) {
	t.Helper()
	orig := extractCandidatesFunc
	if f != nil {
		extractCandidatesFunc = f
	}
	t.Cleanup(func() {
		extractCandidatesFunc = orig
	})
}

func overrideRuntimeGOOS(t *testing.T, goos string) {
	t.Helper()
	orig := runtimeGOOS
	runtimeGOOS = goos
	t.Cleanup(func() {
		runtimeGOOS = orig
	})
}

type pbpasteResult struct {
	content []byte
	err     error
}

func withPbpasteSequence(t *testing.T, results ...pbpasteResult) {
	t.Helper()
	if len(results) == 0 {
		return
	}
	call := 0
	orig := pbpasteFunc
	pbpasteFunc = func() ([]byte, error) {
		idx := call
		if idx >= len(results) {
			idx = len(results) - 1
		}
		call++
		return results[idx].content, results[idx].err
	}
	t.Cleanup(func() { pbpasteFunc = orig })
}

func assertClipboardState(t *testing.T, d *Daemon, wantCount int, wantRedacted, wantCleared bool) {
	t.Helper()
	d.clipboardMu.Lock()
	defer d.clipboardMu.Unlock()
	if d.clipboardSecretCount != wantCount {
		t.Errorf("clipboardSecretCount = %d, want %d", d.clipboardSecretCount, wantCount)
	}
	if d.clipboardRedacted != wantRedacted {
		t.Errorf("clipboardRedacted = %v, want %v", d.clipboardRedacted, wantRedacted)
	}
	if d.clipboardCleared != wantCleared {
		t.Errorf("clipboardCleared = %v, want %v", d.clipboardCleared, wantCleared)
	}
}

func driveMonitor(t *testing.T, d *Daemon) (tickCh chan<- time.Time, monDone <-chan struct{}) {
	tickChInternal := make(chan time.Time, 1)
	ready := make(chan struct{})

	origNew := newMonitorTicker
	newMonitorTicker = func(time.Duration) monitorTicker {
		ft := &fakeTicker{ch: tickChInternal}
		close(ready)
		return ft
	}
	t.Cleanup(func() { newMonitorTicker = origNew })

	monDoneCh := make(chan struct{})
	go func() {
		d.runClipboardMonitor()
		close(monDoneCh)
	}()

	<-ready
	return tickChInternal, monDoneCh
}

func setupSecretEpoch(d *Daemon, planted string) (content, epoch string) {
	if planted == "" {
		planted = "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	}
	h := registry.HashValue([]byte(planted))
	d.registry.Add(h, "test")

	content = "export FOO=" + planted + "\nBAR=baz"
	hsum := sha256.Sum256([]byte(content))
	epoch = hex.EncodeToString(hsum[:])

	setClipboardState(d, epoch, time.Now(), 1, false, false)
	return content, epoch
}

// -----------------------------------------------------------------------------
// Early Return Test Helper
// -----------------------------------------------------------------------------

func overridePbpasteEarlyReturn(t *testing.T, returnValue []byte, returnErr error) {
	overridePbpaste(t, func() ([]byte, error) {
		return returnValue, returnErr
	})
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestShouldLogPbpasteErr(t *testing.T) {
	now := time.Now()
	logIt, t1 := shouldLogPbpasteErr(time.Time{}, now)
	if !logIt || !t1.Equal(now) {
		t.Error("first error should log and return now")
	}

	recent := now.Add(-10 * time.Second)
	logIt, t2 := shouldLogPbpasteErr(now, recent)
	if logIt || !t2.Equal(now) {
		t.Error("recent error should not log")
	}

	lastOld := now.Add(-40 * time.Second)
	logIt, t3 := shouldLogPbpasteErr(lastOld, now)
	if !logIt || !t3.Equal(now) {
		t.Error("old error should log and update ts")
	}
}

func TestPillar5PerformAutoRedactRespectsPillar5Placeholder(t *testing.T) {
	d, _, epoch := setupDaemonWithSecretAndPbpaste(t)
	planted := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"

	d.cfg.Pillar5.RedactPlaceholder = "[P5-PLACEHOLDER]"
	d.cfg.Pillar3.RedactPlaceholder = "[P3-SHOULD-NOT-USE]"

	var gotRedacted []byte
	overridePbcopy(t, func(data []byte) error { gotRedacted = data; return nil })

	d.performAutoRedact(epoch)

	if !bytes.Contains(gotRedacted, []byte("[P5-PLACEHOLDER]")) {
		t.Errorf("performAutoRedact did not use Pillar5 placeholder; got: %s", gotRedacted)
	}
	if bytes.Contains(gotRedacted, []byte(planted)) {
		t.Error("secret value was not redacted away")
	}
	if bytes.Contains(gotRedacted, []byte("[P3-SHOULD-NOT-USE]")) {
		t.Error("fell back to P3 placeholder instead of P5")
	}
}

func TestPillar5MonitorSeams(t *testing.T) {
	overrideClipboardSeams(t,
		func() ([]byte, error) { return []byte("test=secret"), nil },
		func([]byte) error { return nil },
	)

	data, err := pbpasteFunc()
	if err != nil || string(data) != "test=secret" {
		t.Error("pbpasteFunc seam not working")
	}
	if err := pbcopyFunc([]byte("redacted")); err != nil {
		t.Error("pbcopyFunc seam")
	}
}

func TestPillar5FireAlertSeams(t *testing.T) {
	d := newTestDaemon(t)

	called := 0
	overrideAlertSeams(t,
		func(msg string) error {
			called++
			if !strings.Contains(msg, "secret detected") {
				t.Errorf("unexpected alert msg: %s", msg)
			}
			return nil
		},
		func() error { called++; return nil },
	)

	d.fireClipboardAlert()

	if called != 2 {
		t.Errorf("expected both alert funcs called, got %d", called)
	}

	overrideAlertSeams(t,
		func(string) error { return fmt.Errorf("no osascript") },
		func() error { return fmt.Errorf("no afplay") },
	)
	d.fireClipboardAlert()
}

func TestPillar5AutoRedactThenCleanOverwriteResetsFlags(t *testing.T) {
	d, _, dirtyEpoch := setupDaemonWithSecretAndPbpaste(t)

	cleanContent := "just normal text, no secrets here\n"
	cleanH := sha256.Sum256([]byte(cleanContent))
	cleanEpoch := hex.EncodeToString(cleanH[:])

	pbcopyCalled := false
	overridePbcopy(t, func(data []byte) error {
		pbcopyCalled = true
		return nil
	})

	d.performAutoRedact(dirtyEpoch)
	if !pbcopyCalled {
		t.Error("performAutoRedact did not call pbcopy")
	}

	assertClipboardState(t, d, 0, true, false)

	p5 := config.Pillar5Config{RedactTimeoutSeconds: 30}
	d.scanAndActOnClipboard([]byte(cleanContent), cleanEpoch, p5)

	status := d.Pillar5ClipboardStatus()
	if red, _ := status["redacted"].(bool); red {
		t.Error("after clean overwrite following auto-redact: redacted flag still true (stale)")
	}
	if clr, _ := status["cleared"].(bool); clr {
		t.Error("after clean overwrite: cleared unexpectedly true")
	}
	if cnt, _ := status["secret_count"].(int); cnt != 0 {
		t.Errorf("after clean: secret_count=%d want 0", cnt)
	}
	if last, _ := status["last_change"].(string); last == "never" {
		t.Error("last_change should be set for the clean epoch")
	}
}

func TestPillar5PerformAutoRedactSkipsWriteOnConcurrentMutation(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte("USER_OVERWROTE_MEANWHILE with new stuff")},
	)

	pbcopyCalls := 0
	overridePbcopy(t, func(data []byte) error {
		pbcopyCalls++
		return nil
	})

	d.performAutoRedact(epoch)

	if pbcopyCalls != 0 {
		t.Errorf("expected pbcopy skipped on mutation, but got %d calls", pbcopyCalls)
	}

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoFullClear(t *testing.T) {
	d, _, epoch := setupDaemonWithSecretAndPbpaste(t)

	overridePbcopy(t, func(data []byte) error {
		if data != nil && len(data) != 0 {
			t.Error("full clear should pbcopy nil/empty")
		}
		return nil
	})

	d.performAutoFullClear(epoch)

	assertClipboardState(t, d, 0, false, true)
}

func TestPillar5ScanAndActHitsMoreBranches(t *testing.T) {
	d := &Daemon{
		cfg:      &config.Config{},
		registry: registry.New(),
	}

	d.scanAndActOnClipboard(nil, "hash0", config.Pillar5Config{})
	assertClipboardState(t, d, 0, false, false)

	d.scanAndActOnClipboard([]byte("just normal text with no secrets"), "hash1", config.Pillar5Config{})
	assertClipboardState(t, d, 0, false, false)

	planted := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	h := registry.HashValue([]byte(planted))
	d.registry.Add(h, "p")

	blob := "export SECRET=" + planted + "\n"
	hsum := sha256.Sum256([]byte(blob))
	epoch := hex.EncodeToString(hsum[:])

	d.clipboardMu.Lock()
	d.clipboardRedacted = true
	d.clipboardCleared = true
	d.clipboardLastChange = time.Time{}
	d.clipboardMu.Unlock()

	d.scanAndActOnClipboard([]byte(blob), epoch, config.Pillar5Config{AlertsEnabled: false})

	assertClipboardState(t, d, 1, false, false)
	if d.clipboardLastChange.IsZero() {
		t.Error("lastChange should have been set on first secret")
	}
}

func TestDaemon_RunClipboardMonitor_NonDarwinEarlyReturn(t *testing.T) {
	overrideRuntimeGOOS(t, "linux")

	called := false
	origNew := newMonitorTicker
	newMonitorTicker = func(time.Duration) monitorTicker {
		called = true
		return &fakeTicker{ch: make(chan time.Time)}
	}
	defer func() { newMonitorTicker = origNew }()

	d := &Daemon{
		cfg: &config.Config{
			Pillar5: config.Pillar5Config{
				Enabled:        true,
				MonitorEnabled: true,
			},
		},
		shutdown: make(chan struct{}),
	}
	d.runClipboardMonitor()
	if called {
		t.Error("newMonitorTicker should not be called on non-darwin early return")
	}
}

func TestDaemon_RunClipboardMonitor_TickPath(t *testing.T) {
	overrideRuntimeGOOS(t, "darwin")

	d, _, _ := newTestDaemonWithSecret(t, "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890")

	planted := "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"
	h := registry.HashValue([]byte(planted))
	d.registry.Add(h, "proj-tick")

	overridePbpaste(t, func() ([]byte, error) {
		return []byte("export FOO=" + planted + "\n"), nil
	})

	overrideAlertSeams(t,
		func(string) error { return nil },
		func() error { return nil },
	)

	tickCh, monDone := driveMonitor(t, d)

	tickCh <- time.Now()
	runtime.Gosched()

	for i := 0; i < 1000; i++ {
		d.clipboardMu.Lock()
		cnt := d.clipboardSecretCount
		d.clipboardMu.Unlock()
		if cnt == 1 {
			break
		}
		runtime.Gosched()
	}

	tickCh <- time.Now()
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond)

	close(d.shutdown)
	<-monDone

	assertClipboardState(t, d, 1, false, false)
	if d.clipboardLastHash == "" {
		t.Error("tick path: lastHash should be set")
	}
	if d.clipboardLastChange.IsZero() {
		t.Error("tick path: lastChange should be set on first secret")
	}
}

func TestDaemon_RunClipboardMonitor_PbpasteErrInTick(t *testing.T) {
	overrideRuntimeGOOS(t, "darwin")

	overridePbpaste(t, func() ([]byte, error) { return nil, fmt.Errorf("pbpaste temp fail") })

	d := &Daemon{
		cfg: &config.Config{
			Pillar5: config.Pillar5Config{
				Enabled:        true,
				MonitorEnabled: true,
			},
		},
		shutdown: make(chan struct{}),
	}

	tickCh, monDone := driveMonitor(t, d)

	tickCh <- time.Now()
	runtime.Gosched()

	for i := 0; i < 1000; i++ {
		if !d.lastPbpasteErrLog.IsZero() {
			break
		}
		runtime.Gosched()
	}

	close(d.shutdown)
	<-monDone

	if d.lastPbpasteErrLog.IsZero() {
		t.Error("pbpaste err in tick should have updated lastPbpasteErrLog (for rate limiting)")
	}
}

func TestPillar5RunClipboardMonitorResetsPbpasteErrLogOnSuccess(t *testing.T) {
	overrideRuntimeGOOS(t, "darwin")

	overridePbpaste(t, func() ([]byte, error) { return []byte("clean content"), nil })

	d := &Daemon{
		cfg: &config.Config{
			Pillar5: config.Pillar5Config{
				Enabled:        true, // master flag must be on for background monitoring to occur
				MonitorEnabled: true,
			},
		},
		shutdown: make(chan struct{}),
	}
	d.lastPbpasteErrLog = time.Now()

	tickCh, monDone := driveMonitor(t, d)

	tickCh <- time.Now()
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond) // give monitor time to process success path and reset lastPbpasteErrLog

	close(d.shutdown)
	<-monDone

	if !d.lastPbpasteErrLog.IsZero() {
		t.Error("lastPbpasteErrLog should have been reset to zero on successful pbpaste")
	}
}

func TestDaemon_RunClipboardMonitor_CfgNilEarlyReturn(t *testing.T) {
	called := false
	origNew := newMonitorTicker
	newMonitorTicker = func(time.Duration) monitorTicker {
		called = true
		return &fakeTicker{ch: make(chan time.Time)}
	}
	defer func() { newMonitorTicker = origNew }()

	d := &Daemon{
		cfg:      nil,
		shutdown: make(chan struct{}),
	}
	d.runClipboardMonitor()
	if called {
		t.Error("newMonitorTicker should not be called when cfg == nil")
	}
}

// TestDaemon_RunClipboardMonitor_Pillar5DisabledEarlyReturn confirms that the
// master pillar5.enabled flag (when false) completely prevents the background
// copy-paste monitor from doing any polling or ticker work. This is the
// explicit "do not let the daemon read my clipboard" control.
func TestDaemon_RunClipboardMonitor_Pillar5DisabledEarlyReturn(t *testing.T) {
	called := false
	origNew := newMonitorTicker
	newMonitorTicker = func(time.Duration) monitorTicker {
		called = true
		return &fakeTicker{ch: make(chan time.Time)}
	}
	defer func() { newMonitorTicker = origNew }()

	d := &Daemon{
		cfg: &config.Config{
			Pillar5: config.Pillar5Config{
				Enabled:        false, // the flag under test
				MonitorEnabled: true,  // even if this is true, the pillar master wins
			},
		},
		shutdown: make(chan struct{}),
	}
	d.runClipboardMonitor()
	if called {
		t.Error("newMonitorTicker must not be called when pillar5.enabled=false")
	}
}

func TestPillar5ScanAndActFiresAlertWhenEnabled(t *testing.T) {
	d, content, epoch := newTestDaemonWithSecret(t, "")

	called := 0
	overrideAlertSeams(t,
		func(string) error { called++; return nil },
		func() error { called++; return nil },
	)

	p5 := config.Pillar5Config{AlertsEnabled: true}
	d.scanAndActOnClipboard([]byte(content), epoch, p5)

	for i := 0; i < 100; i++ {
		runtime.Gosched()
	}

	if called != 2 {
		t.Errorf("expected AlertsEnabled path to call both alert seams, got %d", called)
	}
	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5MaybeFireAutoActionEarlyReturns(t *testing.T) {
	d1 := newTestDaemon(t)
	setClipboardState(d1, "abc123", time.Now(), 0, false, false)
	d1.maybeFireAutoAction("abc123")

	d2 := newTestDaemon(t)
	setClipboardState(d2, "oldhash", time.Now().Add(-10*time.Second), 1, false, false)
	d2.maybeFireAutoAction("newhash")

	d3 := &Daemon{cfg: nil}
	setClipboardState(d3, "h", time.Now().Add(-1*time.Hour), 1, false, false)
	d3.maybeFireAutoAction("h")
}

func TestPillar5PerformAutoRedactPbcopyError(t *testing.T) {
	d, _, epoch := setupDaemonWithSecretAndPbpaste(t)

	overridePbcopy(t, func([]byte) error { return fmt.Errorf("simulated pbcopy failure") })

	d.performAutoRedact(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoRedactPostCheckPbpasteError(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{err: fmt.Errorf("post-check pbpaste failed")},
	)

	d.performAutoRedact(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoFullClearPbcopyError(t *testing.T) {
	d, _, epoch := setupDaemonWithSecretAndPbpaste(t)

	overridePbcopy(t, func([]byte) error { return fmt.Errorf("pbcopy failed on clear") })

	d.performAutoFullClear(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5CoverDefaultSeamBodies(t *testing.T) {
	forceCoverDefaultSeams()
}

func TestPillar5ClipboardStateTransitions(t *testing.T) {
	t.Run("still dirty after update", func(t *testing.T) {
		d := &Daemon{cfg: &config.Config{}}

		d.clipboardMu.Lock()
		d.clipboardSecretCount = 2
		d.clipboardMu.Unlock()

		d.updateClipboardState("still-dirty-hash", 3)

		assertClipboardState(t, d, 3, false, false)
	})

	t.Run("now clean after update", func(t *testing.T) {
		d := &Daemon{cfg: &config.Config{}}

		d.clipboardMu.Lock()
		d.clipboardSecretCount = 2
		d.clipboardRedacted = true
		d.clipboardCleared = true
		d.clipboardMu.Unlock()

		d.updateClipboardState("now-clean-hash", 0)

		assertClipboardState(t, d, 0, false, false)
	})
}

func TestPillar5ScanAndActSkipsWhitespaceOnlyCandidates(t *testing.T) {
	d := &Daemon{
		cfg:      &config.Config{},
		registry: registry.New(),
	}

	overrideExtractCandidates(t, func([]byte) []string {
		return []string{"   ", "", "\t\n", "looks-like-a-secret-but-is-not-in-registry"}
	})

	hsum := sha256.Sum256([]byte("arbitrary content"))
	epoch := hex.EncodeToString(hsum[:])

	d.scanAndActOnClipboard([]byte("arbitrary content"), epoch, config.Pillar5Config{})

	assertClipboardState(t, d, 0, false, false)
}

func TestPillar5PerformAutoRedactSkipsWhitespaceAndNonRegistered(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	overrideExtractCandidates(t, func([]byte) []string {
		return []string{"   ", "", "\t", "AKIAFAKE1234567890EXAMPLEFAKEKEY", "not-a-real-secret"}
	})

	overridePbpaste(t, func() ([]byte, error) { return []byte(content), nil })

	d.performAutoRedact(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoRedactSkipsOnPostScrubMutation(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte("USER_CHANGED_IT_AFTER_SCRUB")},
	)

	pbcopyCalls := 0
	overridePbcopy(t, func([]byte) error {
		pbcopyCalls++
		return nil
	})

	d.performAutoRedact(epoch)

	if pbcopyCalls != 0 {
		t.Error("pbcopy should have been skipped due to post-scrub mutation")
	}
	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoRedactWhitespaceAndNoMatchingSecrets(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	overrideExtractCandidates(t, func([]byte) []string {
		return []string{"   ", "", "\t", "ghp_FAKE1234567890FAKEFAKEFAKEFAKEFAKEFAKE", "not-registered"}
	})

	overridePbpaste(t, func() ([]byte, error) { return []byte(content), nil })

	d.performAutoRedact(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoRedactFinalStabilityCheckBeforeWrite(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte("user overwrote it")},
	)

	pbcopyCalls := 0
	overridePbcopy(t, func([]byte) error {
		pbcopyCalls++
		return nil
	})

	d.performAutoRedact(epoch)

	if pbcopyCalls != 0 {
		t.Error("pbcopy should have been skipped by the final stability check")
	}
	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoRedactFinalStabilityCheckBeforePbcopy(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte("USER_OVERWROTE_AFTER_SCRUBBING")},
	)

	pbcopyCalled := false
	overridePbcopy(t, func([]byte) error {
		pbcopyCalled = true
		return nil
	})

	d.performAutoRedact(epoch)

	if pbcopyCalled {
		t.Error("pbcopy must not be called when the final stability check fails")
	}
	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoFullClearPbpasteError(t *testing.T) {
	d, _, epoch := setupDaemonWithSecretAndPbpaste(t)

	overridePbpaste(t, func() ([]byte, error) {
		return nil, fmt.Errorf("simulated pbpaste failure inside full clear")
	})

	d.performAutoFullClear(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoFullClearSecondStabilityCheckFails(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte(content)},
		pbpasteResult{content: []byte("user changed clipboard after we read it")},
	)

	cleared := false
	overridePbcopy(t, func([]byte) error {
		cleared = true
		return nil
	})

	d.performAutoFullClear(epoch)

	if cleared {
		t.Error("pbcopy(nil) should not have been called")
	}
	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5PerformAutoFullClearPbpasteErrorAfterFirstCheck(t *testing.T) {
	d, content, epoch := setupDaemonWithSecretAndPbpaste(t)

	withPbpasteSequence(t,
		pbpasteResult{content: []byte(content)},
		pbpasteResult{err: fmt.Errorf("pbpaste failed on explicit read inside full clear")},
	)

	d.performAutoFullClear(epoch)

	assertClipboardState(t, d, 1, false, false)
}

func TestPillar5MaybeFireAutoAction(t *testing.T) {
	d, content, epoch := newTestDaemonWithSecret(t, "")

	d.cfg.Pillar5.RedactTimeoutSeconds = 1
	d.cfg.Pillar5.FullClearTimeoutSeconds = 2

	setClipboardState(d, epoch, time.Now().Add(-3*time.Second), 1, false, false)

	overridePbpaste(t, func() ([]byte, error) { return []byte(content), nil })

	overrideExtractCandidates(t, func([]byte) []string {
		return []string{"AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"}
	})

	d.maybeFireAutoAction(epoch)
}

func TestDaemon_PerformAutoEarlyReturns(t *testing.T) {
	d := newTestDaemon(t)

	overridePbpasteEarlyReturn(t, nil, fmt.Errorf("paste err"))
	d.performAutoRedact("deadbeef")
	d.performAutoFullClear("deadbeef")

	overridePbpasteEarlyReturn(t, []byte("some content"), nil)
	d.performAutoRedact("not-the-hash-of-above")
	d.performAutoFullClear("not-the-hash-of-above")

	overridePbpasteEarlyReturn(t, []byte("just normal text here"), nil)
	d.performAutoRedact("anyhash")

	overridePbpasteEarlyReturn(t, []byte("AKIAFAKE1234567890EXAMPLEFAKEKEY"), nil)
	d.performAutoRedact("anyhash")

	normal := []byte("just normal text here with no detectable secrets at all")
	normalSum := sha256.Sum256(normal)
	normalEpoch := hex.EncodeToString(normalSum[:])

	overridePbpasteEarlyReturn(t, normal, nil)
	overrideExtractCandidates(t, func([]byte) []string { return nil })

	d.performAutoRedact(normalEpoch)
}
