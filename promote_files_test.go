package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRootPromotion_FilesLevel2 creates enough files to push the
// FS-tree past level=1 (each file emits 4 records — inode, drec,
// dstream_id, file_extent — vs 2 for a directory). At ~7-10 records
// per leaf and ~120 leaf pointers in a level-1 root, the cap is
// roughly 800-1200 files. We create 1500 to comfortably exceed it
// and assert the resulting tree reaches level ≥ 2.
//
// If `promoteRoot` couldn't handle level-1 → level-2 promotion the
// test would fail at CreateFile time with "node overflow at entry N";
// PASS confirms the promotion actually runs end-to-end.
func TestRootPromotion_FilesLevel2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: creates 1500 files to drive level-1 → level-2 FS-tree promotion")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "files.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	// 64 MiB — enough room for 1500 × 4 KiB extents + multi-level metadata.
	if err := FormatContainer(path, 1<<26, "FilesL2"); err != nil {
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
	const N = 1500
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("f_%04d.bin", i)
		body := []byte{byte('A' + i%26)}
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d (%s): %v", i, name, err)
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
	t.Logf("after %d files: FS-tree root level = %d", N, v2.rootNode.level)
	if v2.rootNode.level < 2 {
		t.Errorf("root level: got %d, want ≥ 2 (level-2 promotion didn't fire)", v2.rootNode.level)
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
