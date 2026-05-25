package handlers

import (
	"bytes"
	"testing"
)

func TestNewWindowHandler(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := NewWindowHandler{}
	err := h.Handle("echo hello", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.startNewWindowCalls) != 1 || f.startNewWindowCalls[0] != "echo hello" {
		t.Errorf("unexpected calls: %v", f.startNewWindowCalls)
	}
	if buf.String() != "OK\n" {
		t.Errorf("expected OK, got %q", buf.String())
	}
}
