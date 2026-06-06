package filesystem_apfs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestTruncateFile_Shrink resizes a file down (newSize < currentSize)
// and verifies ReadFile returns exactly newSize bytes.
func TestTruncateFile_Shrink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "TruncShrink"); err != nil {
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
	body := []byte("the quick brown fox jumps over the lazy dog")
	fileOID, err := v.CreateFile(2, "log.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.TruncateFile(fileOID, 9); err != nil {
		c.Close()
		t.Fatalf("TruncateFile: %v", err)
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
		t.Fatalf("OpenContainer (re-open): %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != 9 {
		t.Errorf("inode.Size: got %d, want 9", ino.Size)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, []byte("the quick")) {
		t.Errorf("ReadFile: got %q, want %q", got, "the quick")
	}
}

// TestOverwriteFile_InPlace replaces content with a smaller-or-equal
// payload that fits in the existing extent — no extent allocation.
func TestOverwriteFile_InPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ow.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "OWInPlace"); err != nil {
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
	original := []byte("original content of the file")
	fileOID, err := v.CreateFile(2, "data.txt", original)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	replacement := []byte("REPLACED!")
	if err := v.OverwriteFile(fileOID, replacement); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile: %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != uint64(len(replacement)) {
		t.Errorf("size: got %d, want %d", ino.Size, len(replacement))
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, replacement) {
		t.Errorf("content: got %q, want %q", got, replacement)
	}
}

// TestOverwriteFile_Grow replaces content with a payload larger than
// the existing extent capacity, forcing a new extent allocation.
func TestOverwriteFile_Grow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ow.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "OWGrow"); err != nil {
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
	// Initial content fits in one block (4 KiB extent).
	small := bytes.Repeat([]byte{'A'}, 100)
	fileOID, err := v.CreateFile(2, "log.txt", small)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	// Grow to 5 KiB — needs a SECOND extent (the first 4 KiB extent
	// stays; a new 4 KiB extent gets allocated for the remaining 1 KiB).
	big := append(bytes.Repeat([]byte{'B'}, 4096), bytes.Repeat([]byte{'C'}, 1024)...)
	if err := v.OverwriteFile(fileOID, big); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile (grow): %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != uint64(len(big)) {
		t.Errorf("size: got %d, want %d", ino.Size, len(big))
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Errorf("content len mismatch: got %d, want %d (head 4 bytes: %q vs %q)",
			len(got), len(big), got[:min(4, len(got))], big[:4])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestOverwriteFile_GrowMultiExtent grows a file from 100 bytes → 5 KiB
// (forcing one fresh extent), then grows it again to 12 KiB so the
// payload now spans THREE extents written across two grow rounds. The
// final read must round-trip the full 12 KiB payload byte-for-byte.
func TestOverwriteFile_GrowMultiExtent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ow.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "OWGrowMulti"); err != nil {
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
	small := bytes.Repeat([]byte{'A'}, 100)
	fileOID, err := v.CreateFile(2, "log.txt", small)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	// First grow: 5 KiB (now 2 extents).
	medium := append(bytes.Repeat([]byte{'B'}, 4096), bytes.Repeat([]byte{'C'}, 1024)...)
	if err := v.OverwriteFile(fileOID, medium); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile (grow to 5 KiB): %v", err)
	}
	// Second grow: 12 KiB. Existing capacity is 8 KiB (two 4 KiB extents),
	// so a third extent of 4 KiB must be allocated for the tail.
	big := make([]byte, 12*1024)
	for i := range big {
		big[i] = byte('D' + (i % 4))
	}
	if err := v.OverwriteFile(fileOID, big); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile (grow to 12 KiB): %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != uint64(len(big)) {
		t.Errorf("size: got %d, want %d", ino.Size, len(big))
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Errorf("content mismatch: got %d bytes, want %d", len(got), len(big))
	}
}

// TestTruncateFile_FreesTrailingBlocks grows a file across two extents
// (5 KiB total, 2 × 4 KiB), then truncates to 100 bytes. After re-open
// the file's logical size must be 100 and its content must be the
// first 100 bytes of the pre-truncate content (the second extent
// having been freed entirely).
func TestTruncateFile_FreesTrailingBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "TruncFree"); err != nil {
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
	small := bytes.Repeat([]byte{'A'}, 100)
	fileOID, err := v.CreateFile(2, "log.txt", small)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	// Grow to 5 KiB → 2 extents, alloc_count bumps by 1 (one new 4 KiB block).
	big := append(bytes.Repeat([]byte{'B'}, 4096), bytes.Repeat([]byte{'C'}, 1024)...)
	if err := v.OverwriteFile(fileOID, big); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile (grow): %v", err)
	}
	// Truncate to 100 bytes — the second extent must be freed entirely.
	if err := v.TruncateFile(fileOID, 100); err != nil {
		c.Close()
		t.Fatalf("TruncateFile: %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != 100 {
		t.Errorf("inode.Size: got %d, want 100", ino.Size)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := bytes.Repeat([]byte{'B'}, 100)
	if !bytes.Equal(got, want) {
		t.Errorf("content: got %q (len %d), want first-100-bytes-of-grown-file (len %d)",
			got[:min(len(got), 16)], len(got), len(want))
	}
}

// TestTruncateFile_MultiLevelTree exercises the shrink path on an
// FS-tree that's been promoted to level=1 (≥ ~30 files). Without
// the multi-level dispatch this fails with "multi-level FS-tree
// shrink not yet supported"; with it, the targeted file truncates
// cleanly and unrelated files in the same tree are unaffected.
func TestTruncateFile_MultiLevelTree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "TruncMulti"); err != nil {
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
	// Push the FS-tree past single-leaf by creating ~50 files.
	const N = 50
	var targetOID uint64
	body := append(bytes.Repeat([]byte{'X'}, 4096), bytes.Repeat([]byte{'Y'}, 4096)...)
	for i := 0; i < N; i++ {
		oid, err := v.CreateFile(2, fmt.Sprintf("f_%02d.bin", i), []byte("seed"))
		if err != nil {
			c.Close()
			t.Fatalf("CreateFile %d: %v", i, err)
		}
		if i == N/2 {
			targetOID = oid
			// Grow the target across two extents.
			if err := v.OverwriteFile(oid, body); err != nil {
				c.Close()
				t.Fatalf("OverwriteFile target: %v", err)
			}
		}
	}
	if v.rootNode.IsLeaf() {
		c.Close()
		t.Fatalf("expected level-1 FS-tree; got root.IsLeaf=true (test workload too small)")
	}
	// Now shrink: the FS-tree is multi-level, so this exercises the
	// per-key descend dispatch.
	if err := v.TruncateFile(targetOID, 100); err != nil {
		c.Close()
		t.Fatalf("TruncateFile on multi-level tree: %v", err)
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
		t.Fatalf("OpenVolume reopen: %v", err)
	}
	ino, err := v2.FindInode(targetOID)
	if err != nil {
		t.Fatalf("FindInode target: %v", err)
	}
	if ino.Size != 100 {
		t.Errorf("target Size: got %d, want 100", ino.Size)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	want := bytes.Repeat([]byte{'X'}, 100)
	if !bytes.Equal(got, want) {
		t.Errorf("target content after shrink: got %q, want all 'X' (first 100)", got[:min(len(got), 16)])
	}
	// Spot-check that an unrelated file still reads correctly.
	inos, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	regulars := 0
	for _, in := range inos {
		if in.Mode&0xF000 == 0x8000 {
			regulars++
		}
	}
	if regulars != N {
		t.Errorf("regular file count: got %d, want %d", regulars, N)
	}
}

// TestTruncateFile_BoundaryShrink truncates so the new size lands
// inside the FIRST extent of a two-extent file. The boundary extent
// stays (cannot shrink below one block); the second extent is freed
// entirely.
func TestTruncateFile_BoundaryShrink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "TruncBoundary"); err != nil {
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
	// Two extents with distinct payload patterns so we can verify the
	// boundary cleanly.
	body := append(bytes.Repeat([]byte{'X'}, 4096), bytes.Repeat([]byte{'Y'}, 4096)...)
	fileOID, err := v.CreateFile(2, "data.bin", body[:100])
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.OverwriteFile(fileOID, body); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile: %v", err)
	}
	// Truncate to 4096 — exactly the first extent's capacity. The
	// second extent must be freed.
	if err := v.TruncateFile(fileOID, 4096); err != nil {
		c.Close()
		t.Fatalf("TruncateFile: %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != 4096 {
		t.Errorf("inode.Size: got %d, want 4096", ino.Size)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 4096 {
		t.Errorf("ReadFile length: got %d, want 4096", len(got))
	}
	for i, b := range got {
		if b != 'X' {
			t.Errorf("byte %d: got %q, want 'X'", i, b)
			break
		}
	}
}
