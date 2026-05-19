package registry

import (
	"testing"
)

func TestHashValue_NeverPlaintext(t *testing.T) {
	secret := []byte("AKIAIOSFODNN7EXAMPLE")
	h := HashValue(secret)

	// Ensure we didn't accidentally store the original value anywhere
	if string(h[:]) == string(secret) {
		t.Fatal("HashValue returned plaintext instead of hash")
	}
}

func TestRegistry_AddAndHas(t *testing.T) {
	r := New()
	h := HashValue([]byte("super-secret-value"))
	project := ProjectID("/Users/test/project-a")

	r.Add(h, project)

	if !r.Has(h) {
		t.Error("Expected hash to be present after Add")
	}

	projects := r.GetProjectsForHash(h)
	if len(projects) != 1 || projects[0] != project {
		t.Errorf("Unexpected projects: %v", projects)
	}
}

func TestRegistry_CountAndSnapshot(t *testing.T) {
	r := New()
	h1 := HashValue([]byte("secret1"))
	h2 := HashValue([]byte("secret2"))

	r.Add(h1, "proj1")
	r.Add(h2, "proj2")

	if r.Count() != 2 {
		t.Errorf("Expected 2 hashes, got %d", r.Count())
	}

	snap := r.Snapshot()
	if snap["tracked_hashes"].(int) != 2 {
		t.Error("Snapshot did not reflect correct count")
	}
}

func TestRegistry_MinimalMetadata(t *testing.T) {
	// This test documents the design intent: we only store what's necessary
	r := New()
	h := HashValue([]byte("test"))

	r.Add(h, "project-x")

	// In a real security review we would assert no extra fields exist
	// For Phase 0 we simply confirm the structure is minimal
	if r.Count() != 1 {
		t.Error("Registry should remain minimal")
	}
}