package filesystem_apfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// buildSingleFileImage assembles a synthetic APFS container with one
// regular file ("data.bin", inode 101, parent 1) backed by two
// contiguous 4 KiB extents at physical blocks 10 and 11. Used by the
// WriteFileInPlace tests.
func buildSingleFileImage(declaredSize uint64) []byte {
	const fileName = "data.bin"
	img := &containerImage{blocks: make([][]byte, 12)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "WriteVol")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, declaredSize, 0o100644)},
		{key: fileExtKey(101, 0), val: buildFileExtentValue(4096, 10)},
		{key: fileExtKey(101, 4096), val: buildFileExtentValue(4096, 11)},
		{key: drecKey(1, fileName), val: buildDrecValue(101)},
	})
	for i := 0; i < 4096; i++ {
		img.blocks[10][i] = 0xAA
		img.blocks[11][i] = 0xBB
	}
	return img.bytes()
}

// writeImageToFile materialises the synthetic image at path so RW APIs
// (OpenContainerRW) can operate on it. Returns the file path.
func writeImageToFile(t *testing.T, buf []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vol.apfs")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	return path
}

// TestWriteFileInPlace_RoundTrip writes new content via
// OpenContainerRW + WriteFileInPlace, then re-opens read-only and confirms
// ReadFile returns the new bytes.
func TestWriteFileInPlace_RoundTrip(t *testing.T) {
	const declaredSize uint64 = 8192
	path := writeImageToFile(t, buildSingleFileImage(declaredSize))

	// Mutating session.
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	ino, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	want := bytes.Repeat([]byte{0xCC}, int(declaredSize))
	if err := v.WriteFileInPlace(ino, want); err != nil {
		t.Fatalf("WriteFileInPlace: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read-back session.
	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("re-OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("re-OpenVolume: %v", err)
	}
	ino2, err := v2.FindInode(101)
	if err != nil {
		t.Fatalf("re-FindInode: %v", err)
	}
	got, err := v2.ReadFile(ino2)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadFile after WriteFileInPlace mismatch (first 8 got=%x, want=%x)", got[:8], want[:8])
	}
}

// TestWriteFileInPlace_ShortPayloadKeepsTail confirms the
// documented "no metadata change" semantics: writing fewer bytes than
// the file's size leaves the trailing bytes inside the existing extents
// untouched on disk; the inode's declared size remains unchanged so
// ReadFile returns size bytes — first len(data) of them are the new
// payload, the rest are the old physical content.
func TestWriteFileInPlace_ShortPayloadKeepsTail(t *testing.T) {
	const declaredSize uint64 = 8192
	path := writeImageToFile(t, buildSingleFileImage(declaredSize))

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)

	newPrefix := bytes.Repeat([]byte{0x42}, 100)
	if err := v.WriteFileInPlace(ino, newPrefix); err != nil {
		t.Fatalf("WriteFileInPlace: %v", err)
	}
	c.Close()

	c2, _ := OpenContainer(path)
	defer c2.Close()
	v2, _ := c2.OpenVolume(0)
	ino2, _ := v2.FindInode(101)
	got, err := v2.ReadFile(ino2)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got[:100], newPrefix) {
		t.Fatalf("first 100 bytes not overwritten: got %x", got[:100])
	}
	// Bytes 100..4096 are the un-touched portion of the first extent (0xAA).
	if !bytes.Equal(got[100:4096], bytes.Repeat([]byte{0xAA}, 4096-100)) {
		t.Fatalf("extent 1 tail was modified beyond the prefix")
	}
	// Bytes 4096..8192 are the un-touched second extent (0xBB).
	if !bytes.Equal(got[4096:8192], bytes.Repeat([]byte{0xBB}, 4096)) {
		t.Fatalf("extent 2 was modified")
	}
}

// TestWriteFileInPlace_RejectsOversize verifies that a write
// larger than the file's allocated capacity is refused without touching
// any block.
func TestWriteFileInPlace_RejectsOversize(t *testing.T) {
	path := writeImageToFile(t, buildSingleFileImage(8192))
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	tooBig := bytes.Repeat([]byte{0x55}, 8193)
	err = v.WriteFileInPlace(ino, tooBig)
	if err == nil {
		t.Fatal("expected error for oversized write")
	}
}

// TestWriteFileInPlace_RejectsReadOnly verifies that OpenContainer
// (O_RDONLY) refuses WriteFileInPlace via ErrReadOnly.
func TestWriteFileInPlace_RejectsReadOnly(t *testing.T) {
	path := writeImageToFile(t, buildSingleFileImage(8192))
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	err = v.WriteFileInPlace(ino, []byte("hi"))
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("got %v, want ErrReadOnly", err)
	}
}

// TestWriteFileInPlace_RejectsSnapshotView verifies that
// WriteFileInPlace called on a snapshot-view Volume (xidLimit !=
// ^uint64(0)) refuses the operation rather than implicitly mutating the
// live volume's blocks.
func TestWriteFileInPlace_RejectsSnapshotView(t *testing.T) {
	path := writeImageToFile(t, buildSingleFileImage(8192))
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	// Forge a snapshot view by mutating xidLimit (no real snapshot in this
	// image — we are exercising the guard, not the snapshot logic).
	v.xidLimit = 1
	err = v.WriteFileInPlace(ino, []byte("nope"))
	if err == nil {
		t.Fatal("expected error on snapshot view")
	}
}

// TestWriteFile_UpdatesSize is iteration B's acceptance test: the
// new content is visible through ReadFile AND the inode's reported size
// matches len(data) after the write — which means the J_DSTREAM.size
// field was patched on disk inside the FS-tree leaf.
func TestWriteFile_UpdatesSize(t *testing.T) {
	const declaredSize uint64 = 8192
	path := writeImageToFile(t, buildSingleFileImage(declaredSize))

	// Writer session.
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, _ := c.OpenVolume(0)
	ino, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != declaredSize {
		t.Fatalf("preconditions: original size=%d want %d", ino.Size, declaredSize)
	}
	want := []byte("WriteFile updated content with arbitrary length 1234567890")
	if err := v.WriteFile(ino, want); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	c.Close()

	// Reader session: size + content must reflect the write.
	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("re-OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, _ := c2.OpenVolume(0)
	ino2, err := v2.FindInode(101)
	if err != nil {
		t.Fatalf("re-FindInode: %v", err)
	}
	if ino2.Size != uint64(len(want)) {
		t.Fatalf("after WriteFile: size=%d want %d (J_DSTREAM.size patch failed)", ino2.Size, len(want))
	}
	got, err := v2.ReadFile(ino2)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadFile after WriteFile: got %q, want %q", got, want)
	}
}

// TestWriteFile_ShrinkAndGrow walks the inode through several
// sizes within its allocated capacity, asserting each transition is
// observable end-to-end through ReadFile.
func TestWriteFile_ShrinkAndGrow(t *testing.T) {
	const declaredSize uint64 = 8192
	path := writeImageToFile(t, buildSingleFileImage(declaredSize))

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)

	for _, payload := range [][]byte{
		bytes.Repeat([]byte{'a'}, 1),
		bytes.Repeat([]byte{'b'}, 4096),
		bytes.Repeat([]byte{'c'}, 5000),
		bytes.Repeat([]byte{'d'}, 8192),
		bytes.Repeat([]byte{'e'}, 10),
		[]byte{}, // empty; size shrinks to 0
	} {
		ino, err := v.FindInode(101)
		if err != nil {
			t.Fatalf("FindInode: %v", err)
		}
		if err := v.WriteFile(ino, payload); err != nil {
			t.Fatalf("WriteFile len=%d: %v", len(payload), err)
		}
		// Re-open lookup inside the same volume to verify the on-disk size
		// without closing the writer session.
		ino2, err := v.FindInode(101)
		if err != nil {
			t.Fatalf("FindInode after WriteFile len=%d: %v", len(payload), err)
		}
		if ino2.Size != uint64(len(payload)) {
			t.Fatalf("size after WriteFile(%d bytes)=%d, want %d", len(payload), ino2.Size, len(payload))
		}
		// Read back through the same volume; the read path should report
		// the new size and content for the new prefix.
		got, err := v.ReadFile(ino2)
		if err != nil {
			t.Fatalf("ReadFile after WriteFile len=%d: %v", len(payload), err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("ReadFile after WriteFile len=%d: mismatch", len(payload))
		}
	}
}

// TestWriteFile_RejectsReadOnly mirrors the in-place test for the
// metadata-aware variant.
func TestWriteFile_RejectsReadOnly(t *testing.T) {
	path := writeImageToFile(t, buildSingleFileImage(8192))
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	if err := v.WriteFile(ino, []byte("nope")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("got %v, want ErrReadOnly", err)
	}
}

// TestWriteFile_RejectsOversize verifies that a payload larger
// than allocated capacity is refused (delegated to WriteFileInPlace) and
// that the inode size remains unchanged after the failed write.
func TestWriteFile_RejectsOversize(t *testing.T) {
	path := writeImageToFile(t, buildSingleFileImage(8192))
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	if err := v.WriteFile(ino, bytes.Repeat([]byte{0x42}, 9000)); err == nil {
		t.Fatal("expected oversize rejection")
	}
	ino2, _ := v.FindInode(101)
	if ino2.Size != 8192 {
		t.Fatalf("size mutated despite failed write: %d", ino2.Size)
	}
}

// TestWriteFileInPlace_AfterFormatContainer is the end-to-end story:
// FormatContainer produces an empty volume; we are not yet able to create
// files (that's iteration B/C), so we cannot test write-after-format
// without a synthetic injected file. This test stays as a placeholder
// pending iteration B and verifies for now that an empty volume contains
// no inode that WriteFileInPlace could target.
func TestWriteFileInPlace_OnEmptyVolume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Empty"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := v.FindInode(101); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FindInode on empty volume: got %v, want os.ErrNotExist", err)
	}
}
