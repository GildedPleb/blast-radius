package handlers

import "fmt"

type UnknownHandler struct{}

func (UnknownHandler) Name() string { return "" }

func (UnknownHandler) Handle(cmd string, _ DaemonContext) (any, error) {
	return map[string]string{
		"status":  "error",
		"message": fmt.Sprintf("unknown command: %s", cmd),
	}, nil
}
