package handlers

import "testing"

func TestUnknownHandler(t *testing.T) {
	// Bare literal has no cmd (simulates direct construction); message is generic.
	h := UnknownHandler{}
	resp, err := h.Handle("FOO", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.(map[string]string)["message"]
	if msg != "unknown command" {
		t.Errorf("bare UnknownHandler message = %q, want %q", msg, "unknown command")
	}

	// The cmd-carrying form (what GetHandler actually returns) produces the good message.
	h2 := UnknownHandler{cmd: "FOOBAR"}
	resp2, err := h2.Handle("tail", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2 := resp2.(map[string]string)["message"]
	if msg2 != "unknown command: FOOBAR" {
		t.Errorf("UnknownHandler{cmd} message = %q, want %q", msg2, "unknown command: FOOBAR")
	}
}
