package handlers

import (
	"bytes"
	"testing"
)

func TestResetHistoryHandler(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := ResetHistoryHandler{}
	err := h.Handle("", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !f.resetCalled {
		t.Error("expected ResetHistory to be called")
	}
	if buf.String() != "OK\n" {
		t.Errorf("expected OK, got %q", buf.String())
	}
}
