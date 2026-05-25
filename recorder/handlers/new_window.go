package handlers

import "io"

type NewWindowHandler struct{}

func (NewWindowHandler) Name() string { return "NEW_WINDOW" }

func (NewWindowHandler) Handle(args string, r RecorderContext, w io.Writer) error {
	r.StartNewWindowWithCommand(args)
	_, _ = w.Write([]byte("OK\n"))
	return nil
}
