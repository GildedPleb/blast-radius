package registry

import (
	"fmt"
	"testing"
)

func TestRegistry_GetProjects(t *testing.T) {
	r := New()
	h := HashValue([]byte("x"))
	r.Add(h, "proj")
	ps := r.GetProjectsForHash(h)
	if len(ps) != 1 {
		t.Error("projects")
	}
}

func TestRegistry_Count(t *testing.T) {
	r := New()
	if r.Count() != 0 {
		t.Error("empty count")
	}
	r.Add(HashValue([]byte("y")), "p")
	if r.Count() != 1 {
		t.Error("count1")
	}
}

func TestRegistry_Snapshot(t *testing.T) {
	r := New()
	s := r.Snapshot()
	if s["tracked_hashes"].(int) != 0 {
		t.Error("snap")
	}
}

func TestRegistry_RemoveNoEntry(t *testing.T) {
	r := New()
	r.Remove(HashValue([]byte("no")), "p")
}

func TestRegistry_Has(t *testing.T) {
	r := New()
	h := HashValue([]byte("h"))
	if r.Has(h) {
		t.Error("has false")
	}
	r.Add(h, "p")
	if !r.Has(h) {
		t.Error("has true")
	}
}

func TestRegistry_FindDuplicates(t *testing.T) {
	r := New()
	h := HashValue([]byte("d"))
	r.Add(h, "p1")
	r.Add(h, "p2")
	if len(r.FindDuplicates()) == 0 {
		t.Error("find dups")
	}
}

func TestRegistry_AllHashes(t *testing.T) {
	r := New()
	r.Add(HashValue([]byte("a")), "p")
	if len(r.AllHashes()) == 0 {
		t.Error("all hashes")
	}
}

func TestRegistry_IsKnownHashHex(t *testing.T) {
	r := New()
	h := HashValue([]byte("k"))
	r.Add(h, "p")
	hex := ""
	for i := 0; i < 32; i++ {
		hex += "00"
	}
	// fake hex
	_ = r.IsKnownHashHex(hex)
}

func TestRegistry_ScanStates(t *testing.T) {
	r := New()
	for _, st := range []ScanState{ScanStateInProgress, ScanStateFailed, ScanStateCompleted} {
		r.SetScanState(st)
		if r.GetScanState() != st {
			t.Error("state")
		}
	}
}

func TestRegistry_Concurrent(t *testing.T) {
	r := New()
	done := make(chan bool)
	go func() {
		for i := 0; i < 10; i++ {
			r.Add(HashValue([]byte("c")), "p")
		}
		done <- true
	}()
	<-done
}

func TestRegistry_ProjectDisplayName(t *testing.T) {
	cases := []struct {
		id   ProjectID
		want string // prefix check is enough
	}{
		{"", "(unknown project)"},
		{"foo", ".../foo"},
		{"a/b", ".../a/b"},
		{"/home/user/my-project", ".../user/my-project"},
		{"p1/p2/p3", ".../p2/p3"},
	}
	for _, c := range cases {
		got := ProjectDisplayName(c.id)
		if got != c.want {
			t.Errorf("ProjectDisplayName(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestRegistry_Remove_Success(t *testing.T) {
	r := New()
	h := HashValue([]byte("to-remove"))
	r.Add(h, "projX")
	r.Add(h, "projY")
	if r.Count() != 1 {
		t.Fatalf("pre: count=%d", r.Count())
	}
	r.Remove(h, "projX")
	// still has projY so entry remains
	ps := r.GetProjectsForHash(h)
	if len(ps) != 1 || ps[0] != "projY" {
		t.Errorf("after partial remove: %v", ps)
	}
	r.Remove(h, "projY")
	if r.Has(h) {
		t.Error("full remove should drop the hash entry")
	}
}

func TestRegistry_DuplicateCount(t *testing.T) {
	r := New()
	h1 := HashValue([]byte("dup1"))
	h2 := HashValue([]byte("dup2"))
	r.Add(h1, "p1")
	r.Add(h1, "p2")
	r.Add(h2, "p3")
	if r.DuplicateCount() != 1 {
		t.Errorf("DuplicateCount = %d, want 1", r.DuplicateCount())
	}
}

func TestRegistry_IsKnownHashHex_Happy(t *testing.T) {
	r := New()
	h := HashValue([]byte("known-hex"))
	r.Add(h, "px")
	// compute the real hex of h
	hex := ""
	for _, b := range h {
		hex += fmt.Sprintf("%02x", b)
	}
	if !r.IsKnownHashHex(hex) {
		t.Error("IsKnownHashHex happy path failed")
	}
	if r.IsKnownHashHex("not64chars") {
		t.Error("short hex should be false")
	}
}