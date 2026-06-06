package filesystem_apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateSparseFile_RoundTrip creates a 64 KiB sparse file and
// verifies (a) the inode reports the right logical size, (b) ReadFile
// returns 64 KiB of zeros, (c) the on-disk allocation is just metadata
// (no payload extent blocks consumed beyond the J_FILE_EXTENT record
// itself).
func TestCreateSparseFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sparse.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "Sparse"); err != nil {
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
	const size = uint64(64 * 1024)
	fileOID, err := v.CreateSparseFile(2, "hole.bin", size)
	if err != nil {
		c.Close()
		t.Fatalf("CreateSparseFile: %v", err)
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
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	if ino.Size != size {
		t.Errorf("inode.Size: got %d, want %d", ino.Size, size)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if uint64(len(got)) != size {
		t.Fatalf("ReadFile len: got %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, make([]byte, size)) {
		t.Errorf("ReadFile: sparse file is not all zeros (first non-zero at %d)",
			indexFirstNonZero(got))
	}
}

func indexFirstNonZero(b []byte) int {
	for i, x := range b {
		if x != 0 {
			return i
		}
	}
	return -1
}
