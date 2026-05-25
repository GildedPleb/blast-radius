package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GildedPleb/blast-radius/internal/logging"
)

type ScrubHistoryHandler struct{}

func (ScrubHistoryHandler) Name() string { return "SCRUB_HISTORY" }

func (ScrubHistoryHandler) Handle(_ string, d DaemonContext) (any, error) {
	logging.Println("Starting history scrub operation")

	histFile := findHistoryFile()
	if histFile == "" {
		return map[string]any{
			"status":  "error",
			"message": "Could not determine history file location",
		}, nil
	}

	data, err := os.ReadFile(histFile)
	if err != nil {
		logging.Printf("Failed to read history file %s: %v", histFile, err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to read history file: %v", err),
		}, nil
	}

	lines := strings.Split(string(data), "\n")
	originalCount := len(lines)

	knownHashes := make(map[string]bool)
	for _, hash := range d.AllHashes() {
		knownHashes[fmt.Sprintf("%x", hash)] = true
	}

	cleaned := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		shouldRemove := false
		for h := range knownHashes {
			if strings.Contains(line, h) {
				shouldRemove = true
				break
			}
		}
		if shouldRemove {
			removed++
			continue
		}
		cleaned = append(cleaned, line)
	}

	if removed == 0 {
		logging.Printf("History scrub complete. No sensitive lines found in %s", histFile)
		return map[string]any{
			"status":        "ok",
			"message":       "No sensitive entries found in history",
			"file":          histFile,
			"lines_removed": 0,
		}, nil
	}

	tmpFile := histFile + ".blastradius-tmp"
	cleanContent := strings.Join(cleaned, "\n")
	if err := os.WriteFile(tmpFile, []byte(cleanContent), 0600); err != nil {
		logging.Printf("Failed to write temp history file: %v", err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to write cleaned history: %v", err),
		}, nil
	}

	if err := os.Rename(tmpFile, histFile); err != nil {
		os.Remove(tmpFile)
		logging.Printf("Failed to replace history file: %v", err)
		return map[string]any{
			"status":  "error",
			"message": fmt.Sprintf("failed to atomically replace history file: %v", err),
		}, nil
	}

	logging.Printf("History scrub complete. Removed %d sensitive line(s) from %s", removed, histFile)
	return map[string]any{
		"status":         "ok",
		"message":        fmt.Sprintf("Scrubbed %d sensitive line(s) from history", removed),
		"file":           histFile,
		"lines_removed":  removed,
		"original_lines": originalCount,
	}, nil
}

func findHistoryFile() string {
	candidates := []string{
		os.Getenv("HISTFILE"),
		filepath.Join(os.Getenv("HOME"), ".zsh_history"),
		filepath.Join(os.Getenv("HOME"), ".zhistory"),
		filepath.Join(os.Getenv("HOME"), ".history"),
	}
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}
