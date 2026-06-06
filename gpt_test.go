package filesystem_apfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenContainerAuto_NakedImage asserts that OpenContainerAuto opens
// a non-GPT image (one our FormatContainer produces) at offset 0 — i.e.
// the GPT detection is opportunistic and never trips on naked images.
func TestOpenContainerAuto_NakedImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "naked.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "Naked"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerAuto(path)
	if err != nil {
		t.Fatalf("OpenContainerAuto naked: %v", err)
	}
	defer c.Close()
	if v, err := c.OpenVolume(0); err != nil {
		t.Fatalf("OpenVolume: %v", err)
	} else if got := v.Name(); got != "Naked" {
		t.Errorf("volume name: got %q, want %q", got, "Naked")
	}
}

// TestOpenContainerAuto_GPTWrapped verifies that OpenContainerAuto skips
// a protective MBR + GPT header at the start of an image and opens the
// APFS NX SB at the start of the Apple_APFS partition. Mirrors what
// `hdiutil create -fs APFS file.dmg` produces.
func TestOpenContainerAuto_GPTWrapped(t *testing.T) {
	dir := t.TempDir()
	innerPath := filepath.Join(dir, "inner.apfs")
	if err := os.WriteFile(innerPath, nil, 0o600); err != nil {
		t.Fatalf("create inner: %v", err)
	}
	const innerSize = int64(1 << 23) // 8 MiB
	if err := FormatContainer(innerPath, innerSize, "GPTPartition"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	innerBytes, err := os.ReadFile(innerPath)
	if err != nil {
		t.Fatalf("read inner: %v", err)
	}

	// Build a minimal GPT-wrapped image:
	//   sector 0:    protective MBR (we leave it all-zero except the
	//                "EFI PART" magic stays on sector 1)
	//   sector 1:    GPT header
	//   sector 2:    GPT entry array (one Apple_APFS entry at LBA 2048)
	//   sectors 2048..: APFS payload (innerBytes)
	const partStartLBA = int64(2048)
	const partOffset = partStartLBA * gptSectorSize
	wrappedSize := partOffset + innerSize
	wrapped := make([]byte, wrappedSize)
	// GPT header at sector 1.
	hdr := wrapped[gptSectorSize : 2*gptSectorSize]
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 2)   // partition_entry_lba = 2
	binary.LittleEndian.PutUint32(hdr[0x50:0x54], 128) // num_partition_entries
	binary.LittleEndian.PutUint32(hdr[0x54:0x58], 128) // size_of_partition_entry
	// One partition entry at sector 2.
	entry := wrapped[2*gptSectorSize : 2*gptSectorSize+128]
	copy(entry[0:16], appleAPFSPartTypeGUID[:])
	binary.LittleEndian.PutUint64(entry[0x20:0x28], uint64(partStartLBA))
	binary.LittleEndian.PutUint64(entry[0x28:0x30], uint64(partStartLBA+innerSize/gptSectorSize-1))
	// APFS payload.
	copy(wrapped[partOffset:], innerBytes)

	wrappedPath := filepath.Join(dir, "wrapped.dmg")
	if err := os.WriteFile(wrappedPath, wrapped, 0o600); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}
	c, err := OpenContainerAuto(wrappedPath)
	if err != nil {
		t.Fatalf("OpenContainerAuto wrapped: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if got := v.Name(); got != "GPTPartition" {
		t.Errorf("volume name: got %q, want %q", got, "GPTPartition")
	}
}

// TestOpenContainerAuto_GPTWithoutAPFS verifies that a GPT-wrapped image
// whose partition table contains no Apple_APFS entry surfaces a clear
// error rather than corrupting state by reading garbage.
func TestOpenContainerAuto_GPTWithoutAPFS(t *testing.T) {
	dir := t.TempDir()
	wrappedPath := filepath.Join(dir, "no-apfs.img")
	wrapped := make([]byte, 1<<20)
	hdr := wrapped[gptSectorSize : 2*gptSectorSize]
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 2)
	binary.LittleEndian.PutUint32(hdr[0x50:0x54], 128)
	binary.LittleEndian.PutUint32(hdr[0x54:0x58], 128)
	// Use a non-APFS GUID (Linux fs data).
	linuxGUID := [16]byte{
		0xAF, 0x3D, 0xC6, 0x0F,
		0x83, 0x84,
		0x72, 0x47,
		0x8E, 0x79,
		0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
	}
	entry := wrapped[2*gptSectorSize : 2*gptSectorSize+128]
	copy(entry[0:16], linuxGUID[:])
	binary.LittleEndian.PutUint64(entry[0x20:0x28], 2048)
	binary.LittleEndian.PutUint64(entry[0x28:0x30], 4096)
	if err := os.WriteFile(wrappedPath, wrapped, 0o600); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}
	if _, err := OpenContainerAuto(wrappedPath); err == nil {
		t.Fatal("OpenContainerAuto: expected error on GPT image without APFS partition")
	}
}

// TestOpenContainerRWAuto_GPTWrapped_WriteThrough verifies that a write
// performed via the auto-opened RW container lands inside the partition
// payload — i.e. the offset wrapping applies to WriteAt as well.
func TestOpenContainerRWAuto_GPTWrapped_WriteThrough(t *testing.T) {
	dir := t.TempDir()
	innerPath := filepath.Join(dir, "inner.apfs")
	if err := os.WriteFile(innerPath, nil, 0o600); err != nil {
		t.Fatalf("create inner: %v", err)
	}
	const innerSize = int64(1 << 23)
	if err := FormatContainer(innerPath, innerSize, "WriteThru"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	innerBytes, err := os.ReadFile(innerPath)
	if err != nil {
		t.Fatalf("read inner: %v", err)
	}
	const partStartLBA = int64(2048)
	const partOffset = partStartLBA * gptSectorSize
	wrappedSize := partOffset + innerSize
	wrapped := make([]byte, wrappedSize)
	hdr := wrapped[gptSectorSize : 2*gptSectorSize]
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 2)
	binary.LittleEndian.PutUint32(hdr[0x50:0x54], 128)
	binary.LittleEndian.PutUint32(hdr[0x54:0x58], 128)
	entry := wrapped[2*gptSectorSize : 2*gptSectorSize+128]
	copy(entry[0:16], appleAPFSPartTypeGUID[:])
	binary.LittleEndian.PutUint64(entry[0x20:0x28], uint64(partStartLBA))
	binary.LittleEndian.PutUint64(entry[0x28:0x30], uint64(partStartLBA+innerSize/gptSectorSize-1))
	copy(wrapped[partOffset:], innerBytes)
	wrappedPath := filepath.Join(dir, "wrapped.dmg")
	if err := os.WriteFile(wrappedPath, wrapped, 0o600); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	c, err := OpenContainerRWAuto(wrappedPath)
	if err != nil {
		t.Fatalf("OpenContainerRWAuto: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	want := []byte("hello via GPT-aware RW open\n")
	if _, err := v.CreateFile(2, "thru.txt", want); err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify the file is readable. This proves writes
	// landed in the partition (not in the GPT header / pre-partition
	// padding); a write at offset 0 would have clobbered the GPT.
	c2, err := OpenContainerAuto(wrappedPath)
	if err != nil {
		t.Fatalf("OpenContainerAuto re-open: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	var found bool
	for _, ino := range inodes {
		if ino.Name == "thru.txt" {
			found = true
			full, err := v2.FindInode(ino.ID)
			if err != nil {
				t.Fatalf("FindInode(%d): %v", ino.ID, err)
			}
			data, err := v2.ReadFile(full)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(data) != string(want) {
				t.Fatalf("ReadFile content mismatch:\n got:  %q\n want: %q", data, want)
			}
		}
	}
	if !found {
		t.Fatalf("thru.txt not found after RW round-trip through GPT-wrapped image")
	}
	// Sanity: GPT header magic must still be intact at sector 1.
	hdrBytes := make([]byte, 8)
	f, err := os.Open(wrappedPath)
	if err != nil {
		t.Fatalf("re-open file: %v", err)
	}
	defer f.Close()
	if _, err := f.ReadAt(hdrBytes, gptSectorSize); err != nil {
		t.Fatalf("read GPT magic: %v", err)
	}
	if string(hdrBytes) != "EFI PART" {
		t.Fatalf("GPT header was clobbered (magic: %q)", hdrBytes)
	}
}
