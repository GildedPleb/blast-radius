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
	if f.replayMode != "replace" || f.replayCustom != "[REDACTED]" || !f.replayPreserve {
		t.Errorf("unexpected replay args: mode=%s custom=%s preserve=%v", f.replayMode, f.replayCustom, f.replayPreserve)
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
