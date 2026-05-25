package handlers

import (
	"bytes"
	"testing"
)

func TestFlushWindowHandler_Happy(t *testing.T) {
	f := &fakeContext{
		flushData:     []byte("hello world"),
		lastHasSecret: true,
	}
	var buf bytes.Buffer
	h := FlushWindowHandler{}
	err := h.Handle("", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("hello world")) {
		t.Error("expected data in output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("HAS_SECRET")) {
		t.Error("expected HAS_SECRET flag")
	}
}

func TestFlushWindowHandler_Error(t *testing.T) {
	f := &fakeContext{flushErr: bytes.ErrTooLarge}
	var buf bytes.Buffer
	h := FlushWindowHandler{}
	h.Handle("", f, &buf)
	if !bytes.Contains(buf.Bytes(), []byte("ERR")) {
		t.Error("expected ERR on flush error")
	}
}
