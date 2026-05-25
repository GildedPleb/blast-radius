package handlers

import "testing"

func TestCheckHashHandler(t *testing.T) {
	f := &fakeContext{
		knownHashes: map[string]bool{"deadbeef": true},
	}
	h := CheckHashHandler{}

	resp, _ := h.Handle("deadbeef", f)
	if !resp.(map[string]any)["known"].(bool) {
		t.Error("expected known=true")
	}

	resp2, _ := h.Handle("notfound", f)
	if resp2.(map[string]any)["known"].(bool) {
		t.Error("expected known=false")
	}
}
