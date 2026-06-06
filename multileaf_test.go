package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"
)

// This test builds a 12-block synthetic APFS image with a 2-level FS-tree:
//
//	block 0:  NX superblock (omap=1, fs_oid=[100])
//	block 1:  container OMAP (tree=2)
//	block 2:  container OMAP B-tree leaf (oid 100 → block 3)
//	block 3:  APSB (omap=4, root_tree_oid=200)
//	block 4:  volume OMAP (tree=5)
//	block 5:  volume OMAP leaf
//	            oid 200 → block 6  (FS-tree internal root)
//	            oid 201 → block 7  (FS-tree leaf 1)
//	            oid 202 → block 8  (FS-tree leaf 2)
//	block 6:  FS-tree internal root pointing to children {201, 202}
//	block 7:  FS-tree leaf 1 — inode + drec + file_extent(logical=0, len=4096, phys=10)
//	block 8:  FS-tree leaf 2 — file_extent(logical=4096, len=4096, phys=11)
//	block 9:  unused
//	block 10: file payload, first half  (4096 bytes "AAAA…")
//	block 11: file payload, second half (4096 bytes "BBBB…")
func TestMultiLeafMultiExtent(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 12)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}

	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{
		{oid: 100, paddr: 3}, // APSB
	})
	writeAPSB(img.blocks[3], 100, 4, 200, "MultiVol")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6}, // FS-tree internal root
		{oid: 201, paddr: 7}, // FS-tree leaf 1
		{oid: 202, paddr: 8}, // FS-tree leaf 2
	})

	// FS-tree internal root: keys are j_key_t prefixes (8 bytes); values
	// are uint64 child OIDs. We use variable-shape because the FS-tree is
	// always BT_VAR_KV_SIZE.
	//
	// APFS sorts records globally by compareFSKey (j_key_t uint64 then
	// tail). For inode 101 (parent=1) the canonical sort order is:
	//
	//   inode(101)        0x3000…0065  →
	//   ext0(101, 0)      0x8000…0065 + tail 0
	//   ext1(101, 4096)   0x8000…0065 + tail 4096
	//   drec(1, "name")   0x9000…0001 + tail name
	//
	// Leaf 1 holds the three inode-101 records; leaf 2 holds the drec.
	// This is the only distribution that respects the B-tree invariant
	// "every leaf's smallest key ≥ the previous leaf's largest key".
	writeFSTreeInternal(img.blocks[6], []fsInternalEntry{
		{key: jKey(101, jTypeInode), childOID: 201},
		{key: jKey(1, jTypeDirRec), childOID: 202},
	})

	const fileName = "multi.bin"
	// Leaf 1: inode 101 + ext(logical=0) + ext(logical=4096).
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 8192, 0o100644)},
		{key: fileExtKey(101, 0), val: buildFileExtentValue(4096, 10)},
		{key: fileExtKey(101, 4096), val: buildFileExtentValue(4096, 11)},
	})
	// Leaf 2: drec for "multi.bin" under parent 1.
	writeFSTreeLeafCustom(img.blocks[8], []fsLeafEntry{
		{key: drecKey(1, fileName), val: buildDrecValue(101)},
	})
	for i := 0; i < 4096; i++ {
		img.blocks[10][i] = 'A'
		img.blocks[11][i] = 'B'
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
	if v.Name() != "MultiVol" {
		t.Fatalf("Name=%q want MultiVol", v.Name())
	}

	inodes, err := v.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	var got *Inode
	for i := range inodes {
		if inodes[i].ID == 101 {
			got = &inodes[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("inode 101 not found across multi-leaf traversal: %+v", inodes)
	}
	if got.Name != fileName || got.Size != 8192 {
		t.Fatalf("inode mismatch: name=%q size=%d", got.Name, got.Size)
	}
	if len(got.dataExtents) != 2 {
		t.Fatalf("expected 2 extents collected across leaves, got %d", len(got.dataExtents))
	}

	data, err := v.ReadFile(*got)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 8192 {
		t.Fatalf("ReadFile length=%d want 8192", len(data))
	}
	if !bytes.Equal(data[:4096], bytes.Repeat([]byte{'A'}, 4096)) {
		t.Fatalf("first half not all 'A'")
	}
	if !bytes.Equal(data[4096:], bytes.Repeat([]byte{'B'}, 4096)) {
		t.Fatalf("second half not all 'B'")
	}

	if _, err := v.FindInode(101); err != nil {
		t.Fatalf("FindInode(101): %v", err)
	}
	if _, err := v.FindInode(9999); err == nil {
		t.Fatal("FindInode(9999) unexpectedly succeeded")
	}
}

// fsInternalEntry / fsLeafEntry are pairs used to build variable-shape
// FS-tree nodes from arbitrary records, instead of the hard-coded set used
// by writeFSTreeLeaf in the original test.
type fsInternalEntry struct {
	key      []byte
	childOID uint64
}

type fsLeafEntry struct {
	key []byte
	val []byte
}

func jKey(oid uint64, typ uint8) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, oid|(uint64(typ)<<60))
	return out
}

func drecKey(parent uint64, name string) []byte {
	k := make([]byte, 10+len(name)+1)
	binary.LittleEndian.PutUint64(k[0:8], parent|(uint64(jTypeDirRec)<<60))
	binary.LittleEndian.PutUint16(k[8:10], uint16(len(name)+1))
	copy(k[10:], name)
	return k
}

func fileExtKey(oid, logical uint64) []byte {
	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeFileExt)<<60))
	binary.LittleEndian.PutUint64(k[8:16], logical)
	return k
}

// writeFSTreeInternal builds a variable-shape internal B-tree node whose
// values are 8-byte child OIDs (virtual; resolved through the volume omap).
// Entries are sorted by compareFSKey so the resulting node is in canonical
// APFS order, which is what binary-search descenders rely on.
func writeFSTreeInternal(block []byte, entries []fsInternalEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return compareFSKey(entries[i].key, entries[j].key) < 0
	})
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeFSTree))
	off := objPhysSize
	flags := btnFlagRoot // not leaf — internal
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 1) // level=1
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := uint16(len(entries) * 8)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + int(tocLen)
	endOfData := len(block) - btreeInfoSize

	keyOffs := []uint16{}
	keyLens := []uint16{}
	cur := 0
	for _, e := range entries {
		copy(block[keyArea+cur:], e.key)
		keyOffs = append(keyOffs, uint16(cur))
		keyLens = append(keyLens, uint16(len(e.key)))
		cur += len(e.key)
	}
	valOffs := []uint16{}
	valLens := []uint16{}
	cur = 0
	for _, e := range entries {
		v := make([]byte, 8)
		binary.LittleEndian.PutUint64(v, e.childOID)
		// kvloc convention: val.off = cumulative INCLUDING this value.
		cur += 8
		valOffs = append(valOffs, uint16(cur))
		valLens = append(valLens, 8)
		copy(block[endOfData-cur:], v)
	}
	for i := range entries {
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], keyOffs[i])
		binary.LittleEndian.PutUint16(block[base+2:base+4], keyLens[i])
		binary.LittleEndian.PutUint16(block[base+4:base+6], valOffs[i])
		binary.LittleEndian.PutUint16(block[base+6:base+8], valLens[i])
	}
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], 0)
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

// writeFSTreeLeafCustom is a variable-shape leaf builder taking arbitrary
// (key, value) byte sequences. Entries are sorted by compareFSKey so the
// resulting leaf matches APFS canonical order; binary-search readers
// (FindInode, LookupInodeRecord, seekAndIterate) rely on this.
func writeFSTreeLeafCustom(block []byte, entries []fsLeafEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return compareFSKey(entries[i].key, entries[j].key) < 0
	})
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeFSTree))
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := uint16(len(entries) * 8)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + int(tocLen)
	endOfData := len(block) - btreeInfoSize

	keyOffs := []uint16{}
	keyLens := []uint16{}
	cur := 0
	for _, e := range entries {
		copy(block[keyArea+cur:], e.key)
		keyOffs = append(keyOffs, uint16(cur))
		keyLens = append(keyLens, uint16(len(e.key)))
		cur += len(e.key)
	}
	valOffs := []uint16{}
	valLens := []uint16{}
	cur = 0
	for _, e := range entries {
		// Apple's variable-shape kvloc convention: val.off = cumulative
		// byte count INCLUDING this value (= distance from val_end to
		// the value's START going backward). fsck_apfs rejects val.off=0.
		cur += len(e.val)
		valOffs = append(valOffs, uint16(cur))
		valLens = append(valLens, uint16(len(e.val)))
		copy(block[endOfData-cur:], e.val)
	}
	for i := range entries {
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], keyOffs[i])
		binary.LittleEndian.PutUint16(block[base+2:base+4], keyLens[i])
		binary.LittleEndian.PutUint16(block[base+4:base+6], valOffs[i])
		binary.LittleEndian.PutUint16(block[base+6:base+8], valLens[i])
	}
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], 0)
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}
