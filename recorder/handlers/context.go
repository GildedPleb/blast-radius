package handlers

import "io"

// RecorderContext is the narrow interface implemented by *recorder.Recorder.
type RecorderContext interface {
	StartNewWindowWithCommand(string)
	FlushCurrentWindow() ([]byte, error)
	LastWindowHasSecret() bool
	Stop() error
	TriggerShutdown()
	ReplayRedacted(io.Writer, int, string, string, bool) // requestedRecent (N), mode, custom, preserveColors
	ResetHistory()
}
