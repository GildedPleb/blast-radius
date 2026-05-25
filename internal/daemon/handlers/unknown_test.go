package handlers

import "testing"

func TestUnknownHandler(t *testing.T) {
	h := UnknownHandler{}
	resp, err := h.Handle("FOO", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.(map[string]string)["message"]
	if msg == "" || msg == "unknown command: FOO" {
		// ok
	} else {
		t.Errorf("unexpected message: %s", msg)
	}
}
