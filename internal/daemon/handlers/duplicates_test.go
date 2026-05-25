package handlers

import "testing"

func TestDuplicatesHandler(t *testing.T) {
	hash := [32]byte{0xaa}
	f := &fakeContext{
		dups:         map[[32]byte][]string{hash: {"proj1"}},
		displayNames: map[string]string{"proj1": "myproj"},
	}
	h := DuplicatesHandler{}
	resp, err := h.Handle("", f)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.(map[string]any)
	if m["total"].(int) != 1 {
		t.Error("expected 1 duplicate")
	}
}
