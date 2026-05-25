package handlers

import (
	"bytes"
	"testing"
)

func TestStopHandler(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := StopHandler{}
	err := h.Handle("", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !f.stopCalled || !f.shutdownCalled {
		t.Error("expected Stop and TriggerShutdown to be called")
	}
	if buf.String() != "OK\n" {
		t.Errorf("expected OK, got %q", buf.String())
	}
}
