// recorder/recorder.go
package recorder

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/creack/pty"
)

type RecordingWindow struct {
	StartTime time.Time
	Buffer    *bytes.Buffer
	mu        sync.Mutex
}

type Recorder struct {
	PTY       *os.File
	TTY       *os.File
	Cmd       *exec.Cmd
	Current   *RecordingWindow
	recent    [][]byte // bounded recent windows (raw IO, transient)
	mu sync.Mutex
	active    bool
}

func NewRecorder() (*Recorder, error) {
	// Initialize separate recorder log
	_ = logging.InitRecorder(logging.DefaultRecorderLogPath())

	logging.RecorderPrintln("NewRecorder: starting PTY recorder")

	r := &Recorder{
		recent: make([][]byte, 0, 20),
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
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Current = &RecordingWindow{
		StartTime: time.Now(),
		Buffer:    &bytes.Buffer{},
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

	// Store for redacted replay (bounded), then reset
	if len(r.recent) >= 20 {
		r.recent = r.recent[1:]
	}
	r.recent = append(r.recent, data)

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

	switch line {
	case "NEW_WINDOW":
		r.StartNewWindow()
		conn.Write([]byte("OK\n"))
	case "FLUSH_WINDOW":
		data, err := r.FlushCurrentWindow()
		if err != nil {
			conn.Write([]byte("ERR\n"))
			return
		}
		conn.Write(append(data, '\n'))
	case "STOP":
		r.Stop()
		conn.Write([]byte("OK\n"))
		os.Exit(0)
	case "REPLAY_REDACTED":
		r.handleReplayRedacted(conn)
		return
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

func (r *Recorder) handleReplayRedacted(conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	logging.RecorderPrintln("handleReplayRedacted: starting redacted replay")

	for _, win := range r.recent {
		for _, line := range bytes.Split(win, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			if mightContainSecret(string(line)) {
				logging.RecorderPrintf("REDACTED: %s", string(line))
				conn.Write([]byte("%F{yellow}[REDACTED]%f\n"))
			} else {
				conn.Write(append(line, '\n'))
			}
		}
	}
	conn.Write([]byte("OK\n"))
	logging.RecorderPrintln("handleReplayRedacted: finished")
}