package handlers

import "io"

type StopHandler struct{}

func (StopHandler) Name() string { return "STOP" }

func (StopHandler) Handle(_ string, r RecorderContext, w io.Writer) error {
	r.Stop()
	_, _ = w.Write([]byte("OK\n"))
	r.TriggerShutdown()
	return nil
}
