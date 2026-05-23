package registry

import "testing"

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