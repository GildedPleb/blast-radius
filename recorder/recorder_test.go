package recorder

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRecorder_Windows(t *testing.T) {
	r, _ := NewRecorder()
	r.StartNewWindow()
	time.Sleep(10 * time.Millisecond)
	r.FlushCurrentWindow()
	if len(r.recent) == 0 {
		t.Error("window not flushed")
	}
	r.Stop()
}

func TestRecorder_Errors(t *testing.T) {
	r, _ := NewRecorder()
	_, err := r.FlushCurrentWindow()
	if err == nil {
		t.Error("no current")
	}
	r.Stop()
}

func TestMightContain(t *testing.T) {
	mightContainSecret("foo")
}

func TestNewRecorder_Error(t *testing.T) {
	r, err := NewRecorder()
	if err != nil || r == nil {
		t.Error("new recorder")
	}
}

// --- Retention / Sealing tests (Phase A) ---

func TestEnforceBufferRetention_DefaultKeepsLastOne(t *testing.T) {
	// Simulate windows with secrets; default buffer=1 from config
	r := &Recorder{
		recent: []*Window{
			{
				Command:   "echo first",
				HasSecret: true,
				Lines: []Line{
					{Raw: []byte("password=AKIAIOSFODNN7EXAMPLE"), Secrets: []SecretSpan{{Hash: "h1", Start: 9, Length: 20}}},
				},
			},
			{
				Command: "echo second",
				Lines:   []Line{{Raw: []byte("normal output")}},
			},
			{
				Command:   "echo third",
				HasSecret: true,
				Lines: []Line{
					{Raw: []byte("token=ghp_1234567890"), Secrets: []SecretSpan{{Hash: "h2", Start: 6, Length: 14}}},
				},
			},
		},
	}

	r.enforceBufferRetention()

	if len(r.recent) != 3 {
		t.Fatalf("unexpected len: %d", len(r.recent))
	}
	// buf=1 => only last window (index 2) keeps raw; 0 and 1 sealed
	if len(r.recent[0].Lines) != 0 || len(r.recent[0].RedactedLines) == 0 {
		t.Error("oldest window should be sealed")
	}
	if len(r.recent[1].Lines) != 0 || len(r.recent[1].RedactedLines) == 0 {
		t.Error("middle window should be sealed")
	}
	if len(r.recent[2].Lines) == 0 {
		t.Error("most recent window must retain raw Lines")
	}
	// Original secret bytes must not be reachable in sealed windows' remaining data
	// (Redacted contains replacement, not the original value)
	sealed0 := ""
	for _, s := range r.recent[0].RedactedLines {
		sealed0 += s
	}
	if strings.Contains(sealed0, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("sealed window must not contain original secret plaintext")
	}
}

func TestSealWindow_IdempotentAndDiscardsRaw(t *testing.T) {
	w := &Window{
		Command:   "cmd with secret",
		HasSecret: true,
		Lines: []Line{
			{Raw: []byte("foo=supersecretvalue123"), Secrets: []SecretSpan{{Start: 4, Length: 19}}},
		},
	}

	r := &Recorder{}
	r.sealWindow(w)

	if len(w.Lines) != 0 {
		t.Error("Lines must be nil after seal")
	}
	if len(w.RedactedLines) == 0 {
		t.Error("RedactedLines must be populated")
	}
	if !strings.Contains(w.RedactedLines[0], "REDACTED") {
		t.Error("redacted output should contain replacement marker")
	}
	// calling again is safe
	r.sealWindow(w)
	if len(w.RedactedLines) != 1 {
		t.Error("idempotent seal should not duplicate")
	}
}

func TestEnforceBufferRetention_ZeroAggressiveSealsAll(t *testing.T) {
	// For buffer=0 behavior we exercise sealWindow directly (enforce reads live config default=1)
	// This verifies the aggressive path logic in seal.
	r := &Recorder{
		recent: []*Window{
			{Command: "c1", Lines: []Line{{Raw: []byte("s=secretone")}}},
			{Command: "c2", Lines: []Line{{Raw: []byte("s=secrettwo")}}},
		},
	}
	// Directly seal all to simulate buffer=0 path
	for i := range r.recent {
		r.sealWindow(r.recent[i])
	}
	for i, win := range r.recent {
		if len(win.Lines) != 0 {
			t.Errorf("window %d not sealed under aggressive", i)
		}
		if len(win.RedactedLines) == 0 {
			t.Errorf("window %d missing redacted form", i)
		}
	}
}

// TestHandleReplayRedacted_MixedN verifies the core mixed replay logic:
// when N>0, only the most recent min(N, buffer) windows that still have raw
// Lines emit their original secret-containing content; older emit sealed redacted.
func TestHandleReplayRedacted_MixedN(t *testing.T) {
	secretOld := "OLDSECRET12345678"
	secretNew := "NEWSECRET87654321"
	r := &Recorder{
		recent: []*Window{
			{
				Command:   "cmd-old",
				HasSecret: true,
				Lines:     []Line{{Raw: []byte("output containing " + secretOld), Secrets: []SecretSpan{{Start: 18, Length: 17}}}},
			},
			{
				Command:   "cmd-new",
				HasSecret: true,
				Lines:     []Line{{Raw: []byte("output containing " + secretNew), Secrets: []SecretSpan{{Start: 18, Length: 17}}}},
			},
		},
	}
	// Simulate that the first window has aged out of buffer (sealed).
	r.sealWindow(r.recent[0])

	// Request N=1 (should only get raw for the newest)
	var buf bytes.Buffer
	r.handleReplayRedacted(&buf, 1, "replace", "[REDACTED]", true)
	out := buf.String()

	if !strings.Contains(out, secretNew) {
		t.Errorf("expected raw secret for window within N: %s", secretNew)
	}
	if strings.Contains(out, secretOld) {
		t.Errorf("old secret must not appear in mixed replay output: %s", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Error("expected redacted marker for the sealed older window")
	}
	if !strings.HasSuffix(out, "OK\n") {
		t.Error("replay must end with OK")
	}

	// Also verify N=0 (or larger than available raw) behaves as full redaction
	buf.Reset()
	r.handleReplayRedacted(&buf, 0, "replace", "[REDACTED]", true)
	out = buf.String()
	if strings.Contains(out, secretNew) || strings.Contains(out, secretOld) {
		t.Error("N=0 must produce fully redacted output with no raw secrets")
	}
}

func TestIsClearResetCommand_DefaultsAndConfig(t *testing.T) {
	r := &Recorder{}

	// Core mandatory commands must always work (even with arguments)
	coreCases := []string{
		"clear",
		"clear -x",
		"clear --quiet",
		"reset",
		"reset -Q",
		"tput clear",
		"tput clear -T xterm-256color",
		"tput reset",
		"tput reset -Q",
		// tput [options] <cap> forms
		"tput -T xterm clear",
		"tput --quiet reset",
		"tput -T screen-256color clear -x",
		"tput -T xterm reset -Q",
	}
	for _, c := range coreCases {
		if !r.isClearResetCommand(c) {
			t.Errorf("core command %q must trigger history reset", c)
		}
	}

	// Non-clear commands must not match
	if r.isClearResetCommand("ls") ||
		r.isClearResetCommand("echo hi") ||
		r.isClearResetCommand("tput cols") ||
		r.isClearResetCommand("tput") {
		t.Error("non-clearing commands must not match")
	}

	// tput clear must be treated as a core clearer (not just "tput")
	if !r.isClearResetCommand("tput clear") {
		t.Error("tput clear must be recognized as a mandatory clearer")
	}
}

func TestFlushAfterClearResetsHistory(t *testing.T) {
	r := &Recorder{
		recent: make([]*Window, 0),
		Current: &RecordingWindow{
			Buffer: &bytes.Buffer{},
		},
	}

	// Seed some history
	r.recent = append(r.recent, &Window{Command: "secret-echo", HasSecret: true})
	r.pendingCommand = "clear"

	// Simulate the flush that would happen for the "clear" command
	// (we call the internal path after manually setting up a window)
	r.Current.mu.Lock()
	r.Current.Buffer.Write([]byte("screen cleared\n"))
	r.Current.mu.Unlock()

	data, err := r.FlushCurrentWindow()
	if err != nil {
		t.Fatalf("flush failed: %v", err)
	}
	_ = data

	// Because the flushed command was "clear", recent must have been reset to nil
	if len(r.recent) != 0 {
		t.Errorf("expected protected history to be cleared after 'clear' command, got %d windows", len(r.recent))
	}
}


