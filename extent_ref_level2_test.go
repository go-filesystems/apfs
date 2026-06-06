package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestExtentRef_PromotesToLevel2 forces the extent-ref tree past its
// level-1 root cap. Production uses the natural ~122-child per-block
// limit (≈13 000 unique extents). The test lowers it via
// extentRefInternalCapEntries so the level-2 promotion path runs
// without that many files. After promotion the extent-ref root must
// be level=2 and every file must still be readable end-to-end.
func TestExtentRef_PromotesToLevel2(t *testing.T) {
	prev := extentRefInternalCapEntries
	extentRefInternalCapEntries = 4 // 5 child leaves → triggers L2 promotion.
	defer func() { extentRefInternalCapEntries = prev }()

	if testing.Short() {
		t.Skip("skipping in -short: creates ~700 files")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ext_l2.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<26, "EXTL2"); err != nil {
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
	// Each CreateFile inserts one j_phys_ext per allocated extent.
	// With cap=4 the level-1 root holds 4 leaves before L2 fires; 5
	// leaves × ~108 entries ≈ 540 unique extents trigger promotion.
	const N = 700
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("f_%04d.bin", i)
		body := []byte{byte('A' + i%26)}
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d: %v", i, err)
		}
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	c.Close()

	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume reopen: %v", err)
	}
	rawRoot, err := c2.readBlock(v2.apsb.extentRefOID)
	if err != nil {
		t.Fatalf("read extent-ref root: %v", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		t.Fatalf("parse extent-ref root: %v", err)
	}
	t.Logf("after %d files: extent-ref root level=%d, nKeys=%d", N, rootNode.level, rootNode.nKeys)
	if rootNode.level < 2 {
		t.Fatalf("extent-ref root level: got %d, want ≥ 2", rootNode.level)
	}
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	regulars := 0
	for _, ino := range inodes {
		if ino.Mode&0xF000 == 0x8000 {
			regulars++
		}
	}
	if regulars != N {
		t.Errorf("file count after re-open: got %d, want %d", regulars, N)
	}
}
