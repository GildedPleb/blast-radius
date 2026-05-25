package handlers

import (
	"io"
	"strings"
)

type ReplayRedactedHandler struct{}

func (ReplayRedactedHandler) Name() string { return "REPLAY_REDACTED" }

func (ReplayRedactedHandler) Handle(args string, r RecorderContext, w io.Writer) error {
	mode := "replace"
	custom := "[REDACTED]"
	preserveColors := true

	if args != "" {
		parts := strings.SplitN(args, " ", 3)
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

	r.ReplayRedacted(w, mode, custom, preserveColors)
	return nil
}
