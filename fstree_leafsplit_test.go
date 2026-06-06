package filesystem_apfs

// fstree_leafsplit_test.go — regression test for the FS-tree
// leaf-split index-propagation bug. Before the fix, a leaf split in
// a multi-level tree (root → internal → leaf) added the new right
// sibling's index entry to the ROOT instead of to the leaf's
// IMMEDIATE PARENT, producing a structurally invalid tree in which
// some descents stopped at the wrong leaf and entries appeared
// "missing" even though they were still on disk. The fix walks the
// descent path returned by descendToLeafPath and updates the
// immediate parent (and propagates the split upward, splitting
// internal nodes as needed) so the index is consistent at every
// level.

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestFSTreeReadAfterManySplits creates 2000 small files in one
// directory and confirms every file is reachable both via ListDir
// and via ReadFile. Without the propagation fix, reads of early
// files (e.g. f_0000000) start failing around the ~1024-file mark
// once the tree reaches level 2 and the next leaf split mis-routes
// the new sibling's index entry.
func TestFSTreeReadAfterManySplits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping leaf-split read test in -short mode")
	}
	const N = 2000
	dir := t.TempDir()
	img := filepath.Join(dir, "leafsplit_reads.apfs")
	fs, err := Format(img, containerSizeForFiles(N+200, 64), FormatConfig{Label: "LeafSplit"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		if err := fs.WriteFile(name, []byte(fmt.Sprintf("e-%d", i)), 0o644); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	entries, err := fs.ListDir("/d")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != N {
		t.Fatalf("ListDir count: got %d want %d", len(entries), N)
	}
	// Every file must be readable AND have the original content.
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		want := fmt.Sprintf("e-%d", i)
		got, err := fs.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("content %s: got %q want %q", name, string(got), want)
		}
	}
}

// TestFSTreeIncrementalReadback inserts files one at a time and
// after each insert verifies that the EARLIEST file (the one most
// vulnerable to a misrouted descent) is still reachable. Catches
// the bug at the precise insert where the misroute happens.
func TestFSTreeIncrementalReadback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping incremental leaf-split test in -short mode")
	}
	const N = 1600
	dir := t.TempDir()
	img := filepath.Join(dir, "leafsplit_incremental.apfs")
	fs, err := Format(img, containerSizeForFiles(N+200, 64), FormatConfig{Label: "LeafSplitInc"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	canary := "/d/f_0000000"
	canaryWant := "e-0"
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		if err := fs.WriteFile(name, []byte(fmt.Sprintf("e-%d", i)), 0o644); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		got, err := fs.ReadFile(canary)
		if err != nil {
			t.Fatalf("canary %s became unreadable after create %d (%s): %v",
				canary, i, name, err)
		}
		if string(got) != canaryWant {
			t.Fatalf("canary content drift after create %d: got %q want %q",
				i, string(got), canaryWant)
		}
	}
}
