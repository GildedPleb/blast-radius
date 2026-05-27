// recorder/recorder.go
//
// Architecture note: The Go Recorder runs as a long-lived PTY middleman.
// Outer Zsh → Go PTY (this recorder) → inner Zsh.  The recorder owns all
// protected-mode capture state (Window buffers + redaction logic).  Zsh is
// the broker and display layer.
package recorder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/recorder/handlers"
	"github.com/creack/pty"
)

type Recorder struct {
	PTY            *os.File
	TTY            *os.File
	Cmd            *exec.Cmd
	Current        *RecordingWindow
	recent            []*Window
	pendingCommand    string
	historyLength     int
	mu                sync.Mutex
	active            bool
	shutdown          chan struct{}
}

func NewRecorder() (*Recorder, error) {
	// Initialize separate recorder log
	_ = logging.InitRecorder(logging.DefaultRecorderLogPath())

	logging.RecorderPrintln("NewRecorder: starting PTY recorder")

	r := &Recorder{
		recent:   make([]*Window, 0),
		shutdown: make(chan struct{}),
	}

	cmd := exec.Command("zsh")
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, err
	}

	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	cmd.Env = append(os.Environ(), "BR_INSIDE_RECORDER=1")

	if err := cmd.Start(); err != nil {
		ptmx.Close()
		tty.Close()
		return nil, err
	}

	r.PTY = ptmx
	r.TTY = tty
	r.Cmd = cmd
	r.active = true

	logging.RecorderPrintf("NewRecorder: PTY started, PID=%d", cmd.Process.Pid)

	// Start capturing in background
	go r.captureLoop()

	return r, nil
}

func (r *Recorder) captureLoop() {
	logging.RecorderPrintln("captureLoop: started")
	buf := make([]byte, 4096)
	for r.active {
		n, err := r.PTY.Read(buf)
		if err != nil {
			logging.RecorderPrintf("captureLoop: read error: %v", err)
			break
		}
		if n > 0 && r.Current != nil {
			r.Current.mu.Lock()
			r.Current.Buffer.Write(buf[:n])
			r.Current.mu.Unlock()
		}
	}
	logging.RecorderPrintln("captureLoop: exited")
}

func (r *Recorder) StartNewWindow() {
	r.StartNewWindowWithCommand("")
}

func (r *Recorder) StartNewWindowWithCommand(cmd string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Current = &RecordingWindow{
		StartTime: time.Now(),
		Buffer:    &bytes.Buffer{},
	}
	// If we are starting a fresh window after a flush, we can attach the command
	// to the *next* window. For simplicity we store it on the recorder and
	// apply it when the next Flush happens. A more robust approach would be
	// to keep a pending command, but this is sufficient for MVP.
	if cmd != "" {
		r.pendingCommand = cmd
	}
	logging.RecorderPrintln("StartNewWindow: new recording window created")
}

func (r *Recorder) FlushCurrentWindow() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Current == nil {
		logging.RecorderPrintln("FlushCurrentWindow: no active window")
		return nil, fmt.Errorf("no active window")
	}

	r.Current.mu.Lock()
	data := make([]byte, r.Current.Buffer.Len())
	copy(data, r.Current.Buffer.Bytes())
	r.Current.mu.Unlock()

	logging.RecorderPrintf("FlushCurrentWindow: flushed %d bytes", len(data))

	// Convert raw capture into type-safe Window (unbounded)
	win := &Window{
		StartTime: time.Now(),
		Command:   r.pendingCommand,
		Lines:     make([]Line, 0),
	}
	r.pendingCommand = "" // consumed
	if mightContainSecret(win.Command) {
		win.HasSecret = true
	}
	for _, raw := range bytes.Split(data, []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		ln := Line{Raw: append([]byte(nil), raw...)}
		ln.Secrets = findSecretSpans(string(raw))
		if len(ln.Secrets) > 0 {
			win.HasSecret = true
		}
		win.Lines = append(win.Lines, ln)
	}
	r.recent = append(r.recent, win)

	// If the just-flushed command was a terminal clear/reset (per the user's
	// clear_reset_commands policy), drop the entire protected history (including
	// the clearer itself). Future `redact` replays will start from a clean slate,
	// exactly as the visual terminal was cleared.
	if r.isClearResetCommand(win.Command) {
		r.recent = nil
		r.pendingCommand = ""
	}

	// Live re-read of history_length on every flush
	if cfg, _, err := config.Load(); err == nil && cfg.Redaction.HistoryLength > 0 {
		r.historyLength = cfg.Redaction.HistoryLength
	}
	if r.historyLength > 0 && len(r.recent) > r.historyLength {
		r.recent = r.recent[len(r.recent)-r.historyLength:]
	}

	// Enforce raw retention / sealing based on live buffer setting.
	// This both implements the automatic redaction grace period and
	// guarantees that plaintext secret material is bounded (never grows
	// unbounded across a long protected session).
	r.enforceBufferRetention()

	r.Current = &RecordingWindow{
		StartTime: time.Now(),
		Buffer:    &bytes.Buffer{},
	}

	return data, nil
}

func (r *Recorder) Stop() error {
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()

	if r.PTY != nil {
		r.PTY.Close()
	}
	if r.TTY != nil {
		r.TTY.Close()
	}
	if r.Cmd.Process != nil {
		r.Cmd.Process.Kill()
	}
	return nil
}

// --- RecorderContext implementation ---

func (r *Recorder) LastWindowHasSecret() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.recent) == 0 {
		return false
	}
	return r.recent[len(r.recent)-1].HasSecret
}

func (r *Recorder) ResetHistory() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recent = nil
	r.pendingCommand = ""
	r.Current = nil
}

// isClearResetCommand returns true if the given command line matches one of the
// commands that should trigger a protected-mode history reset.
//
// The four core commands (clear, reset, tput clear, tput reset) are mandatory.
// A user cannot disable history reset for these by configuring
// redaction.clear_reset_commands — their list is only ever appended to the core set.
//
// Matching is token-based and argument-aware. It supports the common forms:
//   - "clear" matches "clear", "clear -x", "clear --quiet"
//   - "tput clear" matches "tput clear", "tput clear -T xterm-256color"
//   - "tput -T xterm clear", "tput --quiet reset", "tput -T foo clear -x"
//   - Same rules apply to "reset" / "tput reset" and any user-added commands.
func (r *Recorder) isClearResetCommand(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return false
	}

	// These four are non-removable. The user may only add more commands.
	core := []string{"clear", "reset", "tput clear", "tput reset"}

	// User's configured list (if any) is appended only.
	userList := []string{}
	if cfg, _, err := config.Load(); err == nil && len(cfg.Redaction.ClearResetCommands) > 0 {
		userList = cfg.Redaction.ClearResetCommands
	}

	// Build final list with deduplication (core entries are guaranteed first).
	seen := make(map[string]bool, len(core)+len(userList))
	list := make([]string, 0, len(core)+len(userList))
	for _, e := range append(core, userList...) {
		e = strings.TrimSpace(e)
		if e != "" && !seen[e] {
			seen[e] = true
			list = append(list, e)
		}
	}

	inputFields := strings.Fields(c)
	if len(inputFields) == 0 {
		return false
	}

	for _, entry := range list {
		entryFields := strings.Fields(entry)
		if len(entryFields) == 0 {
			continue
		}
		// Input must be at least as long as the entry (to support arguments)
		if len(inputFields) < len(entryFields) {
			continue
		}

		// Check that the leading tokens match exactly.
		match := true
		for i := range entryFields {
			if inputFields[i] != entryFields[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}

		// Special case for any "tput <cap>" style entry (core or user-added).
		// This supports the common `tput [options] <cap>` form:
		//   tput -T xterm clear
		//   tput --quiet reset
		//   tput -T screen-256color clear -x
		if len(entryFields) >= 2 && entryFields[0] == "tput" {
			cap := entryFields[1]
			// Find the first "tput" token, then look for the capability after it.
			for i, tok := range inputFields {
				if tok == "tput" {
					for j := i + 1; j < len(inputFields); j++ {
						if inputFields[j] == cap {
							return true
						}
					}
					break
				}
			}
		}
	}
	return false
}

func (r *Recorder) TriggerShutdown() {
	close(r.shutdown)
}

func (r *Recorder) ReplayRedacted(w io.Writer, requestedRecent int, mode, custom string, preserveColors bool) {
	r.handleReplayRedacted(w, requestedRecent, mode, custom, preserveColors)
}

// RunControlServer starts a Unix socket for Zsh/CLI control (new-window, flush, stop).
func (r *Recorder) RunControlServer(socketPath string) error {
	logging.RecorderPrintf("RunControlServer: listening on %s", socketPath)

	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		logging.RecorderPrintf("RunControlServer: listen error: %v", err)
		return err
	}
	defer ln.Close()
	_ = os.Chmod(socketPath, 0600)

	go func() {
		<-r.shutdown
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			logging.RecorderPrintf("RunControlServer: accept error: %v", err)
			continue
		}
		go r.handleConn(conn)
	}
	return nil
}

func (r *Recorder) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	line = line[:len(line)-1]

	logging.RecorderPrintf("handleConn: received command %q", line)

	cmd := line
	payload := ""
	if strings.HasPrefix(line, "NEW_WINDOW ") {
		cmd = "NEW_WINDOW"
		payload = strings.TrimPrefix(line, "NEW_WINDOW ")
	}
	if strings.HasPrefix(line, "REPLAY_REDACTED ") {
		cmd = "REPLAY_REDACTED"
		payload = strings.TrimPrefix(line, "REPLAY_REDACTED ")
	}

	var h handlers.CommandHandler
	switch cmd {
	case "NEW_WINDOW":
		h = handlers.NewWindowHandler{}
	case "FLUSH_WINDOW":
		h = handlers.FlushWindowHandler{}
	case "STOP":
		h = handlers.StopHandler{}
	case "REPLAY_REDACTED":
		h = handlers.ReplayRedactedHandler{}
	case "RESET_HISTORY":
		h = handlers.ResetHistoryHandler{}
	case "RECORDER_STATUS":
		// Lightweight status for CLI visibility of retention (buffer + raw window count).
		// Responds with a single JSON line (no OK sentinel needed for this query).
		buf, raw, tot := r.recorderStats()
		fmt.Fprintf(conn, `{"active":true,"buffer":%d,"current_raw_windows":%d,"total_windows":%d,"history_length":%d}`+"\n", buf, raw, tot, r.historyLength)
		return
	default:
		h = handlers.UnknownHandler{}
	}

	h.Handle(payload, r, conn)
}

func (r *Recorder) recorderStats() (buffer, currentRawWindows, totalWindows int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	buffer = r.getCurrentBuffer()
	for _, w := range r.recent {
		if len(w.Lines) > 0 {
			currentRawWindows++
		}
	}
	totalWindows = len(r.recent)
	return
}

// --- Buffer retention / sealing (unified raw retention + automatic redaction grace) ---

// getCurrentBuffer returns the live `redaction.buffer` value (default 1).
// This single value controls both auto redaction timing and how many recent
// windows retain full raw secret-containing bytes.
func (r *Recorder) getCurrentBuffer() int {
	if cfg, _, err := config.Load(); err == nil {
		if cfg.Redaction.Buffer < 0 {
			return 0
		}
		return cfg.Redaction.Buffer
	}
	return 1
}

// getDefaultRedactionMode and custom for use when sealing (mode at seal time).
func (r *Recorder) getDefaultRedactionMode() string {
	if cfg, _, err := config.Load(); err == nil && cfg.Redaction.RedactionMode != "" {
		return cfg.Redaction.RedactionMode
	}
	return "replace"
}

func (r *Recorder) getDefaultCustomReplacement() string {
	if cfg, _, err := config.Load(); err == nil && cfg.Redaction.CustomReplacement != "" {
		return cfg.Redaction.CustomReplacement
	}
	return "[REDACTED]"
}

// sealWindow builds the safe redacted representation using the default mode
// at seal time, then discards Lines (and thus all secret plaintext bytes).
// HasSecret is retained for remove_cmd decisions. Idempotent.
func (r *Recorder) sealWindow(w *Window) {
	if len(w.RedactedLines) > 0 {
		return // already sealed
	}

	mode := r.getDefaultRedactionMode()
	custom := r.getDefaultCustomReplacement()

	if w.Command != "" {
		if spans := findSecretSpans(w.Command); len(spans) > 0 {
			w.RedactedCommand = string(applyRedaction([]byte(w.Command), spans, mode, custom, true))
		} else {
			w.RedactedCommand = w.Command
		}
	}

	for _, ln := range w.Lines {
		if len(ln.Secrets) == 0 {
			w.RedactedLines = append(w.RedactedLines, string(ln.Raw))
		} else {
			red := applyRedaction(ln.Raw, ln.Secrets, mode, custom, true)
			w.RedactedLines = append(w.RedactedLines, string(red))
		}
	}

	// Discard secret material - this is the key step for the invariant.
	// The backing []byte for old Raw become unreachable and can be GC'd.
	w.Lines = nil
}

// enforceBufferRetention seals (discards raw secret data from) any windows
// that have aged past the current buffer value. Called after every flush
// (and trim). With buffer=0 all completed windows are sealed on next flush.
// With buffer=2 exactly the last 2 retain raw (if they had secrets).
func (r *Recorder) enforceBufferRetention() {
	buf := r.getCurrentBuffer()

	if buf <= 0 {
		// Aggressive: seal every completed window on the next flush.
		for i := range r.recent {
			r.sealWindow(r.recent[i])
		}
		return
	}
	if len(r.recent) <= buf {
		return
	}
	// Seal windows that have aged past the buffer.
	sealUpTo := len(r.recent) - buf
	for i := 0; i < sealUpTo; i++ {
		r.sealWindow(r.recent[i])
	}
}

