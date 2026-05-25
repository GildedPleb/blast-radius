package handlers

import "testing"

func TestPingHandler(t *testing.T) {
	h := PingHandler{}
	resp, err := h.Handle("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.(map[string]string)["status"] != "pong" {
		t.Error("expected pong")
	}
}
