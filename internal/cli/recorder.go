package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/recorder"
)

// RunRecorder launches the Go PTY recorder (simple CLI entry for #1).
func RunRecorder(args []string) {
	_ = logging.Init(logging.DefaultDaemonLogPath())

	if len(args) == 0 {
		fmt.Println("recorder start|stop")
		return
	}
	switch args[0] {
	case "start":
		logging.Printf("RunRecorder: starting recorder")
		rec, err := recorder.NewRecorder()
		if err != nil {
			logging.Printf("RunRecorder: failed to start recorder: %v", err)
			fmt.Fprintf(os.Stderr, "recorder start failed: %v\n", err)
			osExit(1)
		}
		rec.StartNewWindow()
		socket := os.Getenv("BR_RECORDER_SOCKET")
		if socket == "" {
			socket = filepath.Join(os.TempDir(), "br-recorder.sock")
		}
		fmt.Printf("Recorder started. Control socket: %s\n", socket)
		logging.Printf("RunRecorder: control socket = %s", socket)
		rec.RunControlServer(socket)
	case "stop":
		logging.Println("RunRecorder: stop requested (stub)")
		fmt.Println("use socket or kill for now")
	default:
		fmt.Println("unknown recorder cmd")
	}
}
