package handlers

import "io"

type FlushWindowHandler struct{}

func (FlushWindowHandler) Name() string { return "FLUSH_WINDOW" }

func (FlushWindowHandler) Handle(_ string, r RecorderContext, w io.Writer) error {
	data, err := r.FlushCurrentWindow()
	if err != nil {
		_, _ = w.Write([]byte("ERR\n"))
		return nil
	}
	// Write raw data
	_, _ = w.Write(append(data, '\n'))

	flag := "NO_SECRET\n"
	if r.LastWindowHasSecret() {
		flag = "HAS_SECRET\n"
	}
	_, _ = w.Write([]byte(flag))
	return nil
}
