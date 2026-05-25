package handlers

import "io"

type ResetHistoryHandler struct{}

func (ResetHistoryHandler) Name() string { return "RESET_HISTORY" }

func (ResetHistoryHandler) Handle(_ string, r RecorderContext, w io.Writer) error {
	r.ResetHistory()
	_, _ = w.Write([]byte("OK\n"))
	return nil
}
