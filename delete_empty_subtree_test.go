package filesystem_apfs

// delete_empty_subtree_test.go — regression test for the
// "apfs: refreshRoot: leftmost key for child N: empty node at paddr M"
// failure that surfaced once a multi-level FS-tree had any leaf
// drained of all its keys by per-file deletes. The fix prunes
// drained subtrees from internal-node TOCs before the root walk
// rebuilds the index.

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestDeleteAllFilesInOneDir creates N files in a single directory
// and removes each one. Without the pruner, the second delete after
// ~13 files would error with "leftmost key … empty node at paddr …";
// the test asserts every delete returns nil.
func TestDeleteAllFilesInOneDir(t *testing.T) {
	const N = 200
	dir := t.TempDir()
	img := filepath.Join(dir, "delete_loop.apfs")
	fs, err := Format(img, 1<<26, FormatConfig{Label: "DelLoop"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		if err := fs.WriteFile(name, []byte(fmt.Sprintf("c-%d", i)), 0o644); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		if err := fs.DeleteFile(name); err != nil {
			t.Fatalf("delete %d (%s): %v", i, name, err)
		}
	}
	// After deleting every file the directory should be empty.
	entries, err := fs.ListDir("/d")
	if err != nil {
		t.Fatalf("ListDir after delete: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ListDir after delete: got %d entries, want 0", len(entries))
	}
}

// TestDeleteAllInLargeMultiLevelTree exercises the pruner against a
// deeper FS-tree shape. 1500 files force the root to level 2, so the
// drained leaves end up two index levels below the root and the
// pruner has to recurse to clean them up.
func TestDeleteAllInLargeMultiLevelTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-level delete loop in -short mode")
	}
	const N = 1500
	dir := t.TempDir()
	img := filepath.Join(dir, "delete_multilevel.apfs")
	fs, err := Format(img, containerSizeForFiles(N+200, 64), FormatConfig{Label: "DelML"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	for i := 0; i < N; i++ {
		if err := fs.WriteFile(fmt.Sprintf("/d/f_%07d", i),
			[]byte(fmt.Sprintf("c-%d", i)), 0o644); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("/d/f_%07d", i)
		if err := fs.DeleteFile(name); err != nil {
			t.Fatalf("delete %d (%s): %v", i, name, err)
		}
	}
}

// TestDeleteThenReadSurvivors verifies the pruner does not collateral-
// damage other entries: after deleting half the files the surviving
// half must remain readable and ListDir must report exactly the
// remaining names.
func TestDeleteThenReadSurvivors(t *testing.T) {
	const N = 100
	dir := t.TempDir()
	img := filepath.Join(dir, "delete_survivors.apfs")
	fs, err := Format(img, 1<<26, FormatConfig{Label: "DelSurv"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	for i := 0; i < N; i++ {
		if err := fs.WriteFile(fmt.Sprintf("/d/f_%07d", i),
			[]byte(fmt.Sprintf("c-%d", i)), 0o644); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	for i := 0; i < N; i += 2 {
		if err := fs.DeleteFile(fmt.Sprintf("/d/f_%07d", i)); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	for i := 1; i < N; i += 2 {
		name := fmt.Sprintf("/d/f_%07d", i)
		want := fmt.Sprintf("c-%d", i)
		got, err := fs.ReadFile(name)
		if err != nil {
			t.Fatalf("read survivor %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("survivor content %s: got %q want %q", name, string(got), want)
		}
	}
	entries, err := fs.ListDir("/d")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if got, want := len(entries), N/2; got != want {
		t.Fatalf("survivor count: got %d want %d", got, want)
	}
}
