package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSpecialFiles_RoundTrip creates one of each special file type
// (FIFO, socket, block dev, char dev) and verifies they round-trip
// through our reader with the right mode bits.
func TestSpecialFiles_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "SpecTest"); err != nil {
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
	fifoOID, err := v.CreateFifo(2, "fifo", 0o644)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFifo: %v", err)
	}
	sockOID, err := v.CreateSocket(2, "sock", 0o755)
	if err != nil {
		c.Close()
		t.Fatalf("CreateSocket: %v", err)
	}
	const rdev uint32 = 0x12340500 // arbitrary major:minor pair
	blkOID, err := v.CreateBlockDevice(2, "blk", 0o660, rdev)
	if err != nil {
		c.Close()
		t.Fatalf("CreateBlockDevice: %v", err)
	}
	chrOID, err := v.CreateCharDevice(2, "chr", 0o666, rdev)
	if err != nil {
		c.Close()
		t.Fatalf("CreateCharDevice: %v", err)
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
	expected := map[uint64]uint16{
		fifoOID: 0xA000, // top nibble doesn't matter; check below per oid
		sockOID: 0xC000,
		blkOID:  0x6000,
		chrOID:  0x2000,
	}
	wantTop := map[uint64]uint16{
		fifoOID: 0x1000, // S_IFIFO
		sockOID: 0xC000, // S_IFSOCK
		blkOID:  0x6000, // S_IFBLK
		chrOID:  0x2000, // S_IFCHR
	}
	_ = expected // silence vet
	for oid, want := range wantTop {
		ino, err := v2.FindInode(oid)
		if err != nil {
			t.Errorf("FindInode(%d): %v", oid, err)
			continue
		}
		got := ino.Mode & 0xF000
		if got != want {
			t.Errorf("oid %d mode top-nibble: got 0x%x, want 0x%x", oid, got, want)
		}
	}
}
