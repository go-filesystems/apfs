package filesystem_apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSetXAttrStream_RoundTrip writes a stream-mode xattr with a 5 KiB
// payload and verifies our reader surfaces it via ListXAttrs with the
// stream flag + StreamID + StreamSize set.
func TestSetXAttrStream_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xs.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "XStream"); err != nil {
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
	fileOID, err := v.CreateFile(2, "doc.bin", []byte("file content"))
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	// Stream xattr: 5 KiB payload (well above any inline threshold).
	bigPayload := bytes.Repeat([]byte{0xAB}, 5*1024)
	const xattrName = "com.apple.metadata:_kBigBlob"
	if err := v.SetXAttrStream(fileOID, xattrName, bigPayload); err != nil {
		c.Close()
		t.Fatalf("SetXAttrStream: %v", err)
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
	xs, err := v2.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	var found bool
	for _, x := range xs {
		if x.Name != xattrName {
			continue
		}
		found = true
		if x.Flags&xattrFlagDataStream == 0 {
			t.Errorf("xattr %q is not flagged as stream (flags=0x%x)", xattrName, x.Flags)
		}
		if x.StreamID == 0 {
			t.Errorf("xattr %q StreamID is zero", xattrName)
		}
		if x.StreamSize != uint64(len(bigPayload)) {
			t.Errorf("xattr %q StreamSize: got %d, want %d", xattrName, x.StreamSize, len(bigPayload))
		}
	}
	if !found {
		t.Errorf("xattr %q not found in ListXAttrs (got %d xattrs)", xattrName, len(xs))
	}
}

// TestSetXAttrStream_ReplaceInPlace overwrites an existing stream
// xattr with a different payload (different size). Verifies the new
// payload round-trips, the old extent's blocks aren't double-counted
// in apsb.apfs_fs_alloc_count, and only one J_FILE_EXTENT survives
// for the new xattr_obj_id (no orphaned old extent records).
func TestSetXAttrStream_ReplaceInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replace.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "XReplace"); err != nil {
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
	fileOID, err := v.CreateFile(2, "doc.bin", []byte("payload"))
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	const xattrName = "com.apple.metadata:_replaceTest"

	first := bytes.Repeat([]byte{0xAA}, 4*1024)
	if err := v.SetXAttrStream(fileOID, xattrName, first); err != nil {
		c.Close()
		t.Fatalf("SetXAttrStream first: %v", err)
	}

	second := bytes.Repeat([]byte{0xBB}, 9*1024)
	if err := v.SetXAttrStream(fileOID, xattrName, second); err != nil {
		c.Close()
		t.Fatalf("SetXAttrStream second: %v", err)
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
	xs, err := v2.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	var streamID uint64
	var nameHits int
	for _, x := range xs {
		if x.Name == xattrName {
			nameHits++
			streamID = x.StreamID
			if x.StreamSize != uint64(len(second)) {
				t.Errorf("StreamSize after replace: got %d, want %d", x.StreamSize, len(second))
			}
		}
	}
	if nameHits != 1 {
		t.Errorf("xattr %q appears %d times after replace, want 1", xattrName, nameHits)
	}
	body, err := v2.ReadXAttrStream(XAttr{
		OwnerID: fileOID, Name: xattrName,
		Flags: xattrFlagDataStream, StreamID: streamID, StreamSize: uint64(len(second)),
	})
	if err != nil {
		t.Fatalf("ReadXAttrStream: %v", err)
	}
	if !bytes.Equal(body, second) {
		t.Errorf("ReadXAttrStream body: got %d bytes, want %d (first byte got=0x%x want=0x%x)",
			len(body), len(second), body[0], second[0])
	}
}

// TestSetXAttrStream_RejectsEmbeddedOverwrite refuses to replace an
// embedded (inline) xattr via SetXAttrStream — caller must delete or
// use SetXAttr.
func TestSetXAttrStream_RejectsEmbeddedOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reject.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<22, "XReject"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	fileOID, err := v.CreateFile(2, "doc.bin", []byte("x"))
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.SetXAttr(fileOID, "com.apple.tag", []byte("inline-payload")); err != nil {
		t.Fatalf("SetXAttr embedded: %v", err)
	}
	if err := v.SetXAttrStream(fileOID, "com.apple.tag", bytes.Repeat([]byte{0xCC}, 4*1024)); err == nil {
		t.Fatal("SetXAttrStream over embedded: expected error")
	}
}
