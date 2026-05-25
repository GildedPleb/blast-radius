package handlers

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnknownHandler(t *testing.T) {
	f := &fakeContext{}
	var buf bytes.Buffer
	h := UnknownHandler{}
	err := h.Handle("FOO_BAR", f, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "UNKNOWN: FOO_BAR") {
		t.Errorf("unexpected unknown output: %q", buf.String())
	}
}
