package handlers

import "testing"

func TestHaltHandler(t *testing.T) {
	f := &fakeContext{}
	h := HaltHandler{}
	resp, err := h.Handle("", f)
	if err != nil {
		t.Fatal(err)
	}
	if !f.shutdown {
		t.Error("expected shutdown to be triggered")
	}
	if resp.(map[string]string)["status"] != "ok" {
		t.Error("expected ok response")
	}
}
