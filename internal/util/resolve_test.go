package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCommand(t *testing.T) {
	// Fail path: guaranteed bad PATH (hermetic even if test env has the binary).
	orig := os.Getenv("PATH")
	t.Setenv("PATH", "/no/such/dir/anywhere/for/resolve/test")
	if p := ResolveCommand("definitelynotacommand12345"); p != "definitelynotacommand12345" {
		t.Errorf("expected bare name fallback on LookPath fail, got %q", p)
	}
	t.Setenv("PATH", orig)

	// Success path: create a temp executable "resolve-test-bin-xyz", put in PATH,
	// ResolveCommand should return its absolute path (not the bare name).
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "resolve-test-bin-xyz")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+":"+orig)

	got := ResolveCommand("resolve-test-bin-xyz")
	if got == "resolve-test-bin-xyz" {
		t.Error("expected absolute path from successful LookPath, got bare name")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute result, got %q", got)
	}
	if filepath.Base(got) != "resolve-test-bin-xyz" {
		t.Errorf("resolved to wrong base: %q", got)
	}
}
