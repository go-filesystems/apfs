package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// xattrKey builds a J_XATTR key: j_key_t(oid|TYPE) + uint16 nameLen + name (NUL-terminated).
func xattrKey(oid uint64, name string) []byte {
	k := make([]byte, 10+len(name)+1)
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeXattr)<<60))
	binary.LittleEndian.PutUint16(k[8:10], uint16(len(name)+1))
	copy(k[10:], name)
	return k
}

// xattrEmbeddedValue builds a J_XATTR value carrying inline payload.
func xattrEmbeddedValue(payload []byte) []byte {
	v := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(v[0:2], xattrFlagDataEmbedded)
	binary.LittleEndian.PutUint16(v[2:4], uint16(len(payload)))
	copy(v[4:], payload)
	return v
}

// siblingKey builds a J_SIBLING_LINK key: j_key_t(oid|TYPE) + uint64 sibling_id.
func siblingKey(oid, siblingID uint64) []byte {
	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeSibLink)<<60))
	binary.LittleEndian.PutUint64(k[8:16], siblingID)
	return k
}

// siblingValue builds a J_SIBLING_LINK value: parent_id + nameLen + name (NUL).
func siblingValue(parentID uint64, name string) []byte {
	v := make([]byte, 10+len(name)+1)
	binary.LittleEndian.PutUint64(v[0:8], parentID)
	binary.LittleEndian.PutUint16(v[8:10], uint16(len(name)+1))
	copy(v[10:], name)
	return v
}

// TestSparseFileZeroFill verifies that a hole between two extents is
// zero-filled by ReadFile rather than rejected.
func TestSparseFileZeroFill(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 12)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Sparse")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	// File 101: declared 12288 bytes (3 blocks). Extents at logical 0 and
	// 8192 — middle 4096 bytes are a sparse hole.
	const fname = "sparse.bin"
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 12288, 0o100644)},
		{key: drecKey(1, fname), val: buildDrecValue(101)},
		{key: fileExtKey(101, 0), val: buildFileExtentValue(4096, 10)},
		{key: fileExtKey(101, 8192), val: buildFileExtentValue(4096, 11)},
	})
	for i := 0; i < 4096; i++ {
		img.blocks[10][i] = 0xAA
		img.blocks[11][i] = 0xBB
	}

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	ino, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	data, err := v.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 12288 {
		t.Fatalf("len=%d want 12288", len(data))
	}
	if !bytes.Equal(data[0:4096], bytes.Repeat([]byte{0xAA}, 4096)) {
		t.Fatal("first extent not 0xAA")
	}
	if !bytes.Equal(data[4096:8192], make([]byte, 4096)) {
		t.Fatal("middle hole not zero-filled")
	}
	if !bytes.Equal(data[8192:12288], bytes.Repeat([]byte{0xBB}, 4096)) {
		t.Fatal("third extent not 0xBB")
	}
}

// TestTrailingZeroRegion verifies that an inode declaring a size
// larger than its extents on disk has the trailing region zero-filled.
func TestTrailingZeroRegion(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 11)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Trail")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	const size = 6000 // fits in 1 block + trailing zeros
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, size, 0o100644)},
		{key: drecKey(1, "trail.bin"), val: buildDrecValue(101)},
		{key: fileExtKey(101, 0), val: buildFileExtentValue(4096, 10)},
	})
	for i := 0; i < 4096; i++ {
		img.blocks[10][i] = 0xCC
	}
	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	vol, _ := c.OpenVolume(0)
	ino, _ := vol.FindInode(101)
	data, err := vol.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != size {
		t.Fatalf("len=%d want %d", len(data), size)
	}
	if !bytes.Equal(data[0:4096], bytes.Repeat([]byte{0xCC}, 4096)) {
		t.Fatal("first 4 KiB not 0xCC")
	}
	if !bytes.Equal(data[4096:size], make([]byte, size-4096)) {
		t.Fatal("trailing region not zero")
	}
}

// TestXAttrEmbedded decodes two embedded extended attributes on the
// same inode and confirms ListXAttrs returns their payloads verbatim.
func TestXAttrEmbedded(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Xattr")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	finderInfo := bytes.Repeat([]byte{0x42}, 32) // 32-byte FinderInfo blob
	tagPayload := []byte("user.tag=red")
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
		{key: drecKey(1, "f"), val: buildDrecValue(101)},
		{key: xattrKey(101, "com.apple.FinderInfo"), val: xattrEmbeddedValue(finderInfo)},
		{key: xattrKey(101, "user.tag"), val: xattrEmbeddedValue(tagPayload)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	vol, _ := c.OpenVolume(0)
	ino, err := vol.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	xs, err := vol.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	if len(xs) != 2 {
		t.Fatalf("len(xs)=%d want 2: %+v", len(xs), xs)
	}
	byName := map[string][]byte{}
	for _, x := range xs {
		if x.Flags&xattrFlagDataEmbedded == 0 {
			t.Fatalf("xattr %q not flagged embedded", x.Name)
		}
		byName[x.Name] = x.EmbeddedValue
	}
	if !bytes.Equal(byName["com.apple.FinderInfo"], finderInfo) {
		t.Fatalf("FinderInfo payload mismatch: %x", byName["com.apple.FinderInfo"])
	}
	if !bytes.Equal(byName["user.tag"], tagPayload) {
		t.Fatalf("user.tag payload mismatch: %q", byName["user.tag"])
	}
}

// TestSiblingLinks decodes two sibling-link records (alternate hard
// link paths) for the same inode.
func TestSiblingLinks(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Hard")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
		{key: drecKey(1, "primary.txt"), val: buildDrecValue(101)},
		{key: siblingKey(101, 1), val: siblingValue(1, "primary.txt")},
		{key: siblingKey(101, 2), val: siblingValue(1, "alias.txt")},
	})

	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	vol, _ := c.OpenVolume(0)
	ino, err := vol.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	sibs, err := vol.ListSiblings(ino)
	if err != nil {
		t.Fatalf("ListSiblings: %v", err)
	}
	if len(sibs) != 2 {
		t.Fatalf("len=%d want 2: %+v", len(sibs), sibs)
	}
	names := map[uint64]string{}
	for _, s := range sibs {
		if s.OwnerID != 101 {
			t.Fatalf("OwnerID=%d want 101", s.OwnerID)
		}
		if s.ParentID != 1 {
			t.Fatalf("ParentID=%d want 1", s.ParentID)
		}
		names[s.SiblingID] = s.Name
	}
	if names[1] != "primary.txt" || names[2] != "alias.txt" {
		t.Fatalf("sibling names mismatch: %+v", names)
	}
}
