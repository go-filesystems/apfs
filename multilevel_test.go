package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMultiLevelFSTreeWrite_ManyFiles creates many files in a row via
// CreateFile + Commit. The number is chosen high enough to force at
// least one leaf split (at ~12-14 files of mixed metadata records each
// FS-tree leaf is full), plus enough additional inserts that we land
// in the multi-level write path (root becomes an internal node with
// level=1). Verifies every file is readable end-to-end via re-open.
func TestMultiLevelFSTreeWrite_ManyFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "ManyFiles"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	const N = 50
	wantContent := make(map[string][]byte, N)
	for i := 0; i < N; i++ {
		v, err := c.OpenVolume(0)
		if err != nil {
			c.Close()
			t.Fatalf("OpenVolume @ %d: %v", i, err)
		}
		name := fmt.Sprintf("file_%03d.txt", i)
		body := []byte(fmt.Sprintf("body of %s\n", name))
		wantContent[name] = body
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d (%q): %v", i, name, err)
		}
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify every file is visible with the right content.
	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer (post-write): %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	if v2.rootNode.IsLeaf() {
		t.Errorf("FS-tree root is still a single leaf after %d files — expected a split", N)
	} else {
		t.Logf("FS-tree promoted to internal node (level=%d) after %d files", v2.rootNode.level, N)
	}
	// Count records by type via traverseFSTree to validate on-disk
	// completeness. Expected after N files (with rebindToRoot=true):
	//   inodes  = N + 2 (new files + root + private-dir)
	//   drecs   = N + 2 (one per file under parent=2 + 2 special-dir
	//                    drecs under parent=1)
	//   extents = N
	//   dstreams= N
	counts := map[uint8]int{}
	if err := v2.traverseFSTree(func(k, val []byte) error {
		_, typ, _ := jKeyHeader(k)
		counts[typ]++
		return nil
	}); err != nil {
		t.Fatalf("traverseFSTree: %v", err)
	}
	t.Logf("record counts: inode=%d drec=%d ext=%d dstream=%d total=%d",
		counts[jTypeInode], counts[jTypeDirRec], counts[jTypeFileExt], counts[jTypeDStreamID],
		counts[jTypeInode]+counts[jTypeDirRec]+counts[jTypeFileExt]+counts[jTypeDStreamID])
	if got := counts[jTypeInode]; got != N+2 {
		t.Errorf("inode count: got %d, want %d", got, N+2)
	}
	if got := counts[jTypeDirRec]; got != N+2 {
		t.Errorf("drec count: got %d, want %d", got, N+2)
	}
	if got := counts[jTypeFileExt]; got != N {
		t.Errorf("file_extent count: got %d, want %d", got, N)
	}
	if got := counts[jTypeDStreamID]; got != N {
		t.Errorf("dstream_id count: got %d, want %d", got, N)
	}
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	byName := map[string]Inode{}
	for _, ino := range inodes {
		byName[ino.Name] = ino
	}
	missing := 0
	for name, want := range wantContent {
		ino, ok := byName[name]
		if !ok {
			missing++
			t.Errorf("inode %q missing after re-open (have %d inodes)", name, len(inodes))
			continue
		}
		full, err := v2.FindInode(ino.ID)
		if err != nil {
			t.Errorf("FindInode(%d) for %q: %v", ino.ID, name, err)
			continue
		}
		got, err := v2.ReadFile(full)
		if err != nil {
			t.Errorf("ReadFile %q: %v", name, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("content mismatch for %q:\n got:  %q\n want: %q", name, got, want)
		}
	}
	if missing == 0 {
		t.Logf("ManyFiles round-trip OK: %d files, FS-tree multi-level", N)
	}
}
