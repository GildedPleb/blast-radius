package handlers

import (
	"fmt"
	"io"
)

type UnknownHandler struct{}

func (UnknownHandler) Name() string { return "" }

func (UnknownHandler) Handle(cmd string, _ RecorderContext, w io.Writer) error {
	_, _ = w.Write([]byte(fmt.Sprintf("UNKNOWN: %s\n", cmd)))
	return nil
}
