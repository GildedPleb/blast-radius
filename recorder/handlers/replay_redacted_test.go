package handlers

import (
	"bytes"
	"strings"
	"testing"
)

func TestReplayRedactedHandler_Default(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := ReplayRedactedHandler{}
	err := h.Handle("", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.replayMode != "replace" || f.replayCustom != "[REDACTED]" || !f.replayPreserve || f.replayRequested != 0 {
		t.Errorf("unexpected replay args: requested=%d mode=%s custom=%s preserve=%v", f.replayRequested, f.replayMode, f.replayCustom, f.replayPreserve)
	}
	if !strings.Contains(buf.String(), "REDACTED_LINE") {
		t.Error("expected redacted output")
	}
}

func TestReplayRedactedHandler_Custom(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := ReplayRedactedHandler{}
	err := h.Handle("remove_cmd *** false", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.replayMode != "remove_cmd" || f.replayCustom != "***" || f.replayPreserve {
		t.Errorf("unexpected custom args: %+v", f)
	}
}

func TestReplayRedactedHandler_ParsesN(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := ReplayRedactedHandler{}
	err := h.Handle("3 replace [REDACTED] true", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.replayRequested != 3 || f.replayMode != "replace" {
		t.Errorf("expected N=3 parsed, got requested=%d mode=%s", f.replayRequested, f.replayMode)
	}
}
