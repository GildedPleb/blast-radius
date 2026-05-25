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
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/creack/pty"
)

type RecordingWindow struct {
	StartTime time.Time
	Buffer    *bytes.Buffer
	mu        sync.Mutex
}

// SecretSpan records a known secret location inside a line (hash + offset + length).
type SecretSpan struct {
	Hash   string
	Start  int
	Length int
}

// Line holds one line of captured output plus any detected secrets.
type Line struct {
	Raw     []byte
	Secrets []SecretSpan
}

// Window is the persisted, type-safe unit owned by the Go Recorder.
type Window struct {
	StartTime time.Time
	Command   string
	Lines     []Line
	HasSecret bool // true if command or any line matched mightContainSecret
}

type Recorder struct {
	PTY            *os.File
	TTY            *os.File
	Cmd            *exec.Cmd
	Current        *RecordingWindow
	recent            []*Window // unbounded per-terminal protected history
	pendingCommand    string
	historyLength     int
	mu                sync.Mutex
	active            bool
}

func NewRecorder() (*Recorder, error) {
	// Initialize separate recorder log
	_ = logging.InitRecorder(logging.DefaultRecorderLogPath())

	logging.RecorderPrintln("NewRecorder: starting PTY recorder")

	r := &Recorder{
		recent: make([]*Window, 0),
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

	// Live re-read of history_length on every flush
	if cfg, _, err := config.Load(); err == nil && cfg.Redaction.HistoryLength > 0 {
		r.historyLength = cfg.Redaction.HistoryLength
	}
	if r.historyLength > 0 && len(r.recent) > r.historyLength {
		r.recent = r.recent[len(r.recent)-r.historyLength:]
	}

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

	for {
		conn, err := ln.Accept()
		if err != nil {
			logging.RecorderPrintf("RunControlServer: accept error: %v", err)
			continue
		}
		go r.handleConn(conn)
	}
}

func (r *Recorder) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	line = line[:len(line)-1]

	logging.RecorderPrintf("handleConn: received command %q", line)

	cmd := line
	if strings.HasPrefix(line, "NEW_WINDOW ") {
		cmd = "NEW_WINDOW"
	}

	switch cmd {
	case "NEW_WINDOW":
		payload := ""
		if strings.HasPrefix(line, "NEW_WINDOW ") {
			payload = strings.TrimPrefix(line, "NEW_WINDOW ")
		}
		r.StartNewWindowWithCommand(payload)
		conn.Write([]byte("OK\n"))
	case "FLUSH_WINDOW":
		data, err := r.FlushCurrentWindow()
		if err != nil {
			conn.Write([]byte("ERR\n"))
			return
		}
		// Return the raw data followed by a secret flag line for Zsh automation
		flag := "NO_SECRET\n"
		if len(r.recent) > 0 && r.recent[len(r.recent)-1].HasSecret {
			flag = "HAS_SECRET\n"
		}
		conn.Write(append(data, '\n'))
		conn.Write([]byte(flag))
	case "STOP":
		r.Stop()
		conn.Write([]byte("OK\n"))
		os.Exit(0)
	case "REPLAY_REDACTED":
		mode := "replace"
		custom := "[REDACTED]"
		preserveColors := true
		if strings.HasPrefix(line, "REPLAY_REDACTED ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "REPLAY_REDACTED "), " ", 3)
			if len(parts) > 0 && parts[0] != "" {
				mode = parts[0]
			}
			if len(parts) > 1 {
				custom = parts[1]
			}
			if len(parts) > 2 && parts[2] == "false" {
				preserveColors = false
			}
		}
		r.handleReplayRedacted(conn, mode, custom, preserveColors)
		return
	case "RESET_HISTORY":
		r.recent = nil
		r.pendingCommand = ""
		r.Current = nil
		conn.Write([]byte("OK\n"))
	default:
		conn.Write([]byte("UNKNOWN\n"))
	}
}

func mightContainSecret(line string) bool {
	return (len(line) > 0 &&
		(bytes.Contains([]byte(line), []byte("aws_")) ||
			bytes.Contains([]byte(line), []byte("ghp_")) ||
			bytes.Contains([]byte(line), []byte("gho_")) ||
			bytes.Contains([]byte(line), []byte("Bearer")) ||
			bytes.Contains([]byte(line), []byte("token=")) ||
			bytes.Contains([]byte(line), []byte("secret=")) ||
			bytes.Contains([]byte(line), []byte("password=")) ||
			bytes.Contains([]byte(line), []byte("apikey")) ||
			bytes.Contains([]byte(line), []byte("="))))
}

// findSecretSpans locates secrets and returns their byte offsets + hashes.
// This is the one-time work done at flush time.
func findSecretSpans(line string) []SecretSpan {
	var spans []SecretSpan
	b := []byte(line)

	// Known prefixes
	prefixes := [][]byte{[]byte("aws_"), []byte("ghp_"), []byte("gho_"), []byte("Bearer")}
	for _, p := range prefixes {
		idx := bytes.Index(b, p)
		if idx >= 0 {
			// take until whitespace or end
			end := idx
			for end < len(b) && b[end] != ' ' && b[end] != '\t' {
				end++
			}
			val := b[idx:end]
			h := sha256.Sum256(val)
			spans = append(spans, SecretSpan{Hash: fmt.Sprintf("%x", h[:]), Start: idx, Length: len(val)})
		}
	}

	// After '=' (simple heuristic)
	if eq := bytes.LastIndexByte(b, '='); eq >= 0 && eq+1 < len(b) {
		start := eq + 1
		end := start
		for end < len(b) && b[end] != ' ' && b[end] != '\t' && b[end] != '"' && b[end] != '\'' {
			end++
		}
		if end > start {
			val := b[start:end]
			if len(val) >= 8 { // avoid tiny false positives
				h := sha256.Sum256(val)
				spans = append(spans, SecretSpan{Hash: fmt.Sprintf("%x", h[:]), Start: start, Length: len(val)})
			}
		}
	}
	return spans
}

// applyRedaction takes a raw line and its pre-computed SecretSpans and
// produces the output according to the requested mode.
// When preserveColors is true, original ANSI sequences around the secret are kept.
func applyRedaction(raw []byte, spans []SecretSpan, mode, custom string, preserveColors bool) []byte {
	if len(spans) == 0 {
		return raw
	}
	if mode == "" {
		mode = "replace"
	}
	if custom == "" {
		custom = "[REDACTED]"
	}

	if mode == "remove_cmd" {
		return nil
	}

	result := make([]byte, 0, len(raw)+64)
	last := 0
	for _, sp := range spans {
		result = append(result, raw[last:sp.Start]...)
		if preserveColors {
			// Keep original color by not emitting extra escapes
			result = append(result, []byte(custom)...)
		} else {
			result = append(result, []byte("%F{yellow}")...)
			result = append(result, []byte(custom)...)
			result = append(result, []byte("%f")...)
		}
		last = sp.Start + sp.Length
	}
	result = append(result, raw[last:]...)
	return result
}

func (r *Recorder) handleReplayRedacted(conn net.Conn, mode, custom string, preserveColors bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	logging.RecorderPrintln("handleReplayRedacted: starting redacted replay")

	for _, win := range r.recent {
		// remove_cmd: skip entire window if it contained any secret
		if mode == "remove_cmd" && win.HasSecret {
			continue
		}

		// Command line
		if win.Command != "" {
			if mode == "remove_cmd" && win.HasSecret {
				// already skipped above
			} else if len(findSecretSpans(win.Command)) > 0 {
				out := applyRedaction([]byte(win.Command), findSecretSpans(win.Command), mode, custom, preserveColors)
				if out != nil {
					conn.Write(append(out, '\n'))
				}
			} else {
				conn.Write(append([]byte(win.Command), '\n'))
			}
		}

		for _, ln := range win.Lines {
			if len(ln.Secrets) == 0 {
				conn.Write(append(append([]byte(nil), ln.Raw...), '\n'))
				continue
			}
			out := applyRedaction(ln.Raw, ln.Secrets, mode, custom, preserveColors)
			if out != nil {
				conn.Write(append(out, '\n'))
			}
		}
	}
	conn.Write([]byte("OK\n"))
	logging.RecorderPrintln("handleReplayRedacted: finished")
}