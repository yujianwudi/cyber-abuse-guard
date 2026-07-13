package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRequiresEveryPatternToMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	matched := filepath.Join(dir, "matched.go")
	if err := os.WriteFile(matched, []byte("package fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	patterns := []string{filepath.ToSlash(filepath.Join(dir, "*.go")), filepath.ToSlash(filepath.Join(dir, "missing", "*.go"))}
	if _, err := snapshot(patterns, false); err == nil {
		t.Fatal("snapshot accepted an unmatched pattern")
	}
}

func TestSnapshotRequiresEligibleNonTestMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only_test.go"), []byte("package fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot([]string{filepath.ToSlash(filepath.Join(dir, "*.go"))}, true); err == nil {
		t.Fatal("snapshot accepted a pattern whose matches were all excluded")
	}
}

func TestSnapshotHashesCompletePatternSet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"one.go", "two.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	patterns := []string{
		filepath.ToSlash(filepath.Join(dir, "*.go")),
		filepath.ToSlash(filepath.Join(dir, "*.yaml")),
	}
	if digest, err := snapshot(patterns, false); err != nil {
		t.Fatalf("snapshot: %v", err)
	} else if len(digest) != 64 {
		t.Fatalf("digest length=%d, want 64", len(digest))
	}
}
