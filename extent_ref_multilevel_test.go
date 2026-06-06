package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestExtentRefMultiLevel_PromotesAtThreshold creates enough files to
// push the volume's extent-ref tree past its single-leaf capacity
// (~108 entries with the existing j_phys_ext layout). The test
// verifies that:
//
//  1. The promotion path runs without errors (no "leaf overflow" /
//     "multi-level tree not supported" surfacing).
//  2. The extent-ref root after promotion has IsLeaf() == false
//     (level ≥ 1).
//  3. Every created file is still discoverable through the FS-tree
//     after re-open — i.e. the FS-tree side stays healthy regardless
//     of the extent-ref-side promotion.
func TestExtentRefMultiLevel_PromotesAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "promote.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	// 32 MiB container — plenty of room for 130 × 4 KiB extents +
	// metadata trees.
	if err := FormatContainer(path, 1<<25, "ExtRefPromote"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	const nFiles = 130
	names := make([]string, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		name := fmt.Sprintf("f%03d.bin", i)
		// 1-byte payload → 1-block extent each, one extent-ref entry
		// per file.
		body := []byte{byte('A' + i%26)}
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d (%s): %v", i, name, err)
		}
		names = append(names, name)
	}

	// Force a checkpoint so OpenContainer below reads our writes.
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify the extent-ref root is now multi-level.
	c2, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW (reopen): %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume (reopen): %v", err)
	}
	rawRoot, err := v2.c.readBlock(v2.apsb.extentRefOID)
	if err != nil {
		t.Fatalf("read extent-ref root: %v", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		t.Fatalf("parse extent-ref root: %v", err)
	}
	if rootNode.IsLeaf() {
		t.Fatalf("extent-ref tree did not promote: root is still a leaf with %d entries",
			rootNode.nKeys)
	}
	if rootNode.level != 1 {
		t.Errorf("extent-ref root level: got %d, want 1", rootNode.level)
	}

	// Smoke check: every file is still listed in the FS-tree.
	inos, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	seen := 0
	for _, ino := range inos {
		if ino.Mode&0xF000 == 0x8000 {
			seen++
		}
	}
	if seen != nFiles {
		t.Errorf("file count: got %d, want %d", seen, nFiles)
	}
}

// TestExtentRefMultiLevel_DeleteAfterPromote creates enough files to
// trigger the extent-ref-tree promotion, then deletes 10 of them.
// The removeExtentRefRecord path must descend through the level-1
// root to the right leaf and rewrite it; the file's blocks are
// freed normally and the deletes round-trip through Commit + re-open.
func TestExtentRefMultiLevel_DeleteAfterPromote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "promote_del.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "ExtRefDel"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	const nFiles = 130
	for i := 0; i < nFiles; i++ {
		name := fmt.Sprintf("f%03d.bin", i)
		body := []byte{byte('A' + i%26)}
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d: %v", i, err)
		}
	}
	// Promotion happened above; now delete every 13th file (10 files).
	for i := 0; i < nFiles; i += 13 {
		name := fmt.Sprintf("f%03d.bin", i)
		if err := v.DeleteFile(2, name); err != nil {
			c.Close()
			t.Fatalf("DeleteFile %s: %v", name, err)
		}
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	inos, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	seen := 0
	for _, ino := range inos {
		if ino.Mode&0xF000 == 0x8000 {
			seen++
		}
	}
	deletes := 0
	for i := 0; i < nFiles; i += 13 {
		deletes++
	}
	want := nFiles - deletes
	if seen != want {
		t.Errorf("regular-file count after delete: got %d, want %d", seen, want)
	}
}
