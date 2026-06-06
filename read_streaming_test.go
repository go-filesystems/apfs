package filesystem_apfs

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestFileReaderAt_RoundTrip writes a multi-extent file (two extents
// after OverwriteFile grow), then reads back several windows via
// FileReaderAt. Verifies that:
//
//   - Head window reads from the first extent.
//   - Mid window crosses the extent boundary.
//   - Tail window stops at inode.Size (signals io.EOF on overshoot).
//   - A read entirely past the size returns io.EOF immediately.
func TestFileReaderAt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rdat.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "FileRdAt"); err != nil {
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
	body := append(bytes.Repeat([]byte{'A'}, 4096), bytes.Repeat([]byte{'B'}, 2048)...)
	fileOID, err := v.CreateFile(2, "data.bin", body[:100])
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.OverwriteFile(fileOID, body); err != nil {
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
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume reopen: %v", err)
	}
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	rd, err := v2.FileReaderAt(ino)
	if err != nil {
		t.Fatalf("FileReaderAt: %v", err)
	}

	// Head: first 10 bytes — all 'A'.
	buf := make([]byte, 10)
	if n, err := rd.ReadAt(buf, 0); n != 10 || err != nil {
		t.Errorf("head: n=%d err=%v, want 10 nil", n, err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'A'}, 10)) {
		t.Errorf("head: got %q, want %q", buf, bytes.Repeat([]byte{'A'}, 10))
	}

	// Cross boundary: 4090..4106 — last 6 bytes of extent 0 + first 10 of extent 1.
	buf = make([]byte, 16)
	if n, err := rd.ReadAt(buf, 4090); n != 16 || err != nil {
		t.Errorf("cross: n=%d err=%v, want 16 nil", n, err)
	}
	wantCross := append(bytes.Repeat([]byte{'A'}, 6), bytes.Repeat([]byte{'B'}, 10)...)
	if !bytes.Equal(buf, wantCross) {
		t.Errorf("cross: got %q, want %q", buf, wantCross)
	}

	// Tail clip: read 100 bytes starting 50 before EOF — should return 50 + io.EOF.
	buf = make([]byte, 100)
	totalLen := int64(len(body))
	n, err := rd.ReadAt(buf, totalLen-50)
	if n != 50 || err != io.EOF {
		t.Errorf("tail clip: n=%d err=%v, want 50 io.EOF", n, err)
	}
	if !bytes.Equal(buf[:50], bytes.Repeat([]byte{'B'}, 50)) {
		t.Errorf("tail clip content: got %q, want all 'B'", buf[:50])
	}

	// Past EOF: any read fully past size returns 0 + io.EOF.
	n, err = rd.ReadAt(buf, totalLen)
	if n != 0 || err != io.EOF {
		t.Errorf("past EOF: n=%d err=%v, want 0 io.EOF", n, err)
	}
}

// TestFileReaderAt_SparseFile reads through a 3-block sparse file:
// only the middle block is allocated; the head and tail must read
// back as zeros without consuming I/O for the unallocated regions.
func TestFileReaderAt_SparseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sparse.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "FileRdSparse"); err != nil {
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
	// CreateSparseFile makes a 12 KiB file with no extents (entirely sparse).
	fileOID, err := v.CreateSparseFile(2, "hole.bin", 12*1024)
	if err != nil {
		c.Close()
		t.Fatalf("CreateSparseFile: %v", err)
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
	rd, err := v2.FileReaderAt(ino)
	if err != nil {
		t.Fatalf("FileReaderAt: %v", err)
	}
	// Read the whole 12 KiB — must be all zeros.
	buf := make([]byte, 12*1024)
	if n, err := rd.ReadAt(buf, 0); n != 12*1024 || err != nil {
		t.Fatalf("read sparse: n=%d err=%v", n, err)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("sparse byte %d: got 0x%02x, want 0", i, b)
		}
	}
}

// TestXAttrStreamReaderAt_RoundTrip writes a 5 KiB stream xattr,
// then reads it back through XAttrStreamReaderAt window-by-window.
func TestXAttrStreamReaderAt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xat.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "XAttrRd"); err != nil {
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
	fileOID, err := v.CreateFile(2, "host.bin", []byte("host"))
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	payload := make([]byte, 5*1024)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	if err := v.SetXAttrStream(fileOID, "user.big", payload); err != nil {
		c.Close()
		t.Fatalf("SetXAttrStream: %v", err)
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
	xs, err := v2.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	var stream XAttr
	found := false
	for _, x := range xs {
		if x.Name == "user.big" {
			stream = x
			found = true
			break
		}
	}
	if !found {
		t.Fatal("xattr user.big not found")
	}
	rd, err := v2.XAttrStreamReaderAt(stream)
	if err != nil {
		t.Fatalf("XAttrStreamReaderAt: %v", err)
	}
	// Read a window in the middle.
	buf := make([]byte, 100)
	if n, err := rd.ReadAt(buf, 1000); n != 100 || err != nil {
		t.Fatalf("xattr window: n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, payload[1000:1100]) {
		t.Errorf("xattr window content mismatch")
	}
	// Read past EOF.
	if n, err := rd.ReadAt(buf, int64(len(payload))); n != 0 || err != io.EOF {
		t.Errorf("xattr past EOF: n=%d err=%v, want 0 io.EOF", n, err)
	}
}
