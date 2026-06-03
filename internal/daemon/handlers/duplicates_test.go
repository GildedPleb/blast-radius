package handlers

import (
	"testing"

	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestDuplicatesHandler(t *testing.T) {
	hash := registry.SecretHash{0xaa}
	proj := registry.ProjectID("proj1")
	f := &fakeContext{
		dups:         map[registry.SecretHash][]registry.ProjectID{hash: {proj}},
		displayNames: map[registry.ProjectID]string{proj: "myproj"},
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
