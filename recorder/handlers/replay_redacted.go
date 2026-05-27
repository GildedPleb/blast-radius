package handlers

import (
	"io"
	"strconv"
	"strings"
)

type ReplayRedactedHandler struct{}

func (ReplayRedactedHandler) Name() string { return "REPLAY_REDACTED" }

func (ReplayRedactedHandler) Handle(args string, r RecorderContext, w io.Writer) error {
	requestedRecent := 0
	mode := "replace"
	custom := "[REDACTED]"
	preserveColors := true

	if args != "" {
		parts := strings.SplitN(args, " ", 4)
		if len(parts) > 0 && parts[0] != "" {
			if n, err := strconv.Atoi(parts[0]); err == nil && n >= 0 {
				requestedRecent = n
				parts = parts[1:]
			}
		}
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

	r.ReplayRedacted(w, requestedRecent, mode, custom, preserveColors)
	return nil
}
