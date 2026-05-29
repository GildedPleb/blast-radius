package logging

import (
	"log"
	"os"
	"path/filepath"
)

// Init sets up logging to the given file path with the standard daemon format.
// It creates the parent directory if needed and configures the global logger.
func Init(logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	log.SetOutput(logFile)
	log.SetPrefix("blastradius: ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return nil
}

// DefaultDaemonLogPath returns the standard daemon log location.
func DefaultDaemonLogPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "blastradius", "daemon.log")
}

// The following are thin wrappers so call sites can migrate to logging. without
// changing behavior. Existing code using the global log package will continue to
// work after Init is called.

func Printf(format string, v ...any) { log.Printf(format, v...) }
func Println(v ...any)                 { log.Println(v...) }
func Fatalf(format string, v ...any)   { log.Fatalf(format, v...) }
func Fatal(v ...any)                   { log.Fatal(v...) }
