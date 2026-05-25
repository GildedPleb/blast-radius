package handlers

import "strings"

type CheckHashHandler struct{}

func (CheckHashHandler) Name() string { return "CHECK_HASH" }

func (CheckHashHandler) Handle(args string, d DaemonContext) (any, error) {
	hashHex := strings.TrimSpace(args)
	known := d.IsKnownHashHex(hashHex)
	return map[string]any{
		"status": "ok",
		"known":  known,
	}, nil
}
