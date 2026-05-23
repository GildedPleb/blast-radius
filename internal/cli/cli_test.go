package cli

import "testing"

func TestCLI(t *testing.T) {}

func TestRunStatus(t *testing.T) {
	RunStatus(false)
	RunStatus(true)
}

func TestRunStop(t *testing.T) {
	RunStop()
}

func TestRunLogs(t *testing.T) {
	RunLogs()
}

func TestRunDuplicates(t *testing.T) {
	RunDuplicates()
}

func TestRunScrubHistory(t *testing.T) {
	RunScrubHistory()
}

func TestRunClear(t *testing.T) {
	RunClear()
}

func TestRunStart(t *testing.T) {
	RunStart()
}

func TestRunCheckHash(t *testing.T) {
	RunCheckHash("deadbeef")
}

func TestRunRecorder(t *testing.T) {
	RunRecorder(nil)
}

func TestRunEnvCheck(t *testing.T) {
	RunEnvCheck("")
}

func TestRunClipboard(t *testing.T) {
	RunClipboard(nil)
}