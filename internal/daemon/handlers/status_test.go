package handlers

import (
	"testing"
	"time"
)

func TestStatusHandler(t *testing.T) {
	f := &fakeContext{
		snapshot: map[string]int{"count": 3},
		now:      time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
	}
	h := StatusHandler{}
	resp, err := h.Handle("", f)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["status"] != "ok" || m["registry"] == nil {
		t.Errorf("unexpected status response: %+v", m)
	}
}
