package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/GildedPleb/blast-radius/internal/logging"
	"github.com/GildedPleb/blast-radius/recorder"
)

// RunRecorder launches the Go PTY recorder (internal entrypoint used by
// `blastradius protection start` and for direct debugging of the recorder
// process). The "recorder" subcommand is not part of the public stable
// surface.
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
		socket := ""
		if len(args) > 1 {
			socket = args[1]
		} else if envSock := os.Getenv("BR_RECORDER_SOCKET"); envSock != "" {
			// Legacy fallback (pre-CLI-refactor). Direct `blastradius recorder start`
			// users should pass the explicit TTY-derived socket path instead.
			logging.Printf("RunRecorder: using legacy BR_RECORDER_SOCKET (deprecated)")
			socket = envSock
		}
		if socket == "" {
			// For direct manual invocation, fall back to a throwaway path.
			// The proper way to start a recorder for a terminal is via
			// `blastradius protection start` (which always supplies the path).
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
