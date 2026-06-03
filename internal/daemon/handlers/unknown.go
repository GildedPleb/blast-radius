package handlers

import "fmt"

type UnknownHandler struct {
	// cmd holds the original unrecognized command token (the first word sent by
	// the client). We capture it here because dispatch passes only the "args"
	// tail to Handle; without it the error message would show the tail or be empty.
	cmd string
}

func (UnknownHandler) Name() string { return "" }

// No init() registration: UnknownHandler is the explicit fallback in GetHandler
// (and Name()=="" would cause Register to ignore it anyway).

func (u UnknownHandler) Handle(_ string, _ DaemonContext) (any, error) {
	msg := "unknown command"
	if u.cmd != "" {
		msg = fmt.Sprintf("unknown command: %s", u.cmd)
	}
	return map[string]string{
		"status":  "error",
		"message": msg,
	}, nil
}
