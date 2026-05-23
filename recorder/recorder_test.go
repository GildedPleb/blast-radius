package recorder

import (
	"testing"
	"time"
)

func TestRecorder_Windows(t *testing.T) {
	r, _ := NewRecorder()
	r.StartNewWindow()
	time.Sleep(10 * time.Millisecond)
	r.FlushCurrentWindow()
	if len(r.recent) == 0 {
		t.Error("window not flushed")
	}
	r.Stop()
}

func TestRecorder_Errors(t *testing.T) {
	r, _ := NewRecorder()
	_, err := r.FlushCurrentWindow()
	if err == nil {
		t.Error("no current")
	}
	r.Stop()
}

func TestMightContain(t *testing.T) {
	mightContainSecret("foo")
}

