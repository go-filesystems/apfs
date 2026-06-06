package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// writeOMAPInternal builds a fixed-shape internal B-tree node for the OMAP.
// Each entry's value is an 8-byte child OID (physical, since the OMAP is
// not virtualised through itself). Used to construct multi-level OMAP
// trees in tests so the binary-search descent path is exercised.
func writeOMAPInternal(block []byte, entries []struct{ oid, paddr uint64 }) {
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeOMAP))
	off := objPhysSize
	flags := btnFlagRoot | btnFlagFixedKVSize // not leaf — internal
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 1) // level=1
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := uint16(len(entries) * 4)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(tocLen)
	valBaseEnd := len(block) - btreeInfoSize
	for i, e := range entries {
		// Same TOC convention as writeOmapBTreeLeaf: keyOff = i*16
		// (each key is omap_key = 16 bytes). valOff = (i+1)*8 — Apple's
		// kvoff.v is the distance from val_end to the value's START
		// (values grow backward), so the first value (i=0) has
		// valOff = sizeof(value) = 8.
		keyOff := uint16(i * 16)
		valOff := uint16((i + 1) * 8)
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], keyOff)
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], valOff)
		// Key: oid + xid(=1)
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], 1)
		// Value: 8-byte child OID
		v := block[valBaseEnd-(i+1)*8 : valBaseEnd-i*8]
		binary.LittleEndian.PutUint64(v, e.paddr)
	}
	// btreeInfo: BT_FIXED_KV_SIZE, key=16, val=16 (leaf size; internal
	// values are 8 but the parser handles that lookup-side).
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], 0x4) // BTREE_FIXED_KV_SIZE
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint32(bi[8:12], 16)
	binary.LittleEndian.PutUint32(bi[12:16], 16)
	binary.LittleEndian.PutUint32(bi[16:20], 16)
	binary.LittleEndian.PutUint32(bi[20:24], 16)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

// TestLookupInodeRecord_FourLeaves builds a synthetic FS-tree with an
// internal root pointing to four sibling leaves, distributes inodes 100,
// 200, 300, 400 across them, and verifies LookupInodeRecord finds each one
// regardless of which subtree holds it. Lookups for unknown oids must
// return os.ErrNotExist.
func TestLookupInodeRecord_FourLeaves(t *testing.T) {
	const numLeaves = 4
	// Layout:
	//   block 0: NX SB (omap=1, fs_oid=[100])
	//   block 1: container OMAP (tree=2)
	//   block 2: container OMAP leaf
	//   block 3: APSB (omap=4, root_tree_oid=200)
	//   block 4: volume OMAP (tree=5)
	//   block 5: volume OMAP leaf with 5 mappings (root + 4 leaves)
	//   block 6: FS-tree internal root pointing to children 201..204
	//   blocks 7..10: FS-tree leaves
	img := &containerImage{blocks: make([][]byte, 11)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Search")
	writeOMAP(img.blocks[4], 5)

	// Distribute inodes evenly: 100, 200, 300, 400.
	inodeIDs := []uint64{100, 200, 300, 400}

	// Volume OMAP: virtual oid 200 is the tree root (block 6); virtual
	// oids 201..204 are leaves 1..4 (blocks 7..10).
	volOmapEntries := []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
	}
	for i := 0; i < numLeaves; i++ {
		volOmapEntries = append(volOmapEntries, struct{ oid, paddr uint64 }{
			oid:   uint64(201 + i),
			paddr: uint64(7 + i),
		})
	}
	writeOmapBTreeLeaf(img.blocks[5], volOmapEntries)

	// FS-tree internal root: each child entry's key is the smallest key
	// present in that subtree (jKey of inode at type=jTypeInode).
	internalEntries := make([]fsInternalEntry, numLeaves)
	for i, oid := range inodeIDs {
		internalEntries[i] = fsInternalEntry{
			key:      jKey(oid, jTypeInode),
			childOID: uint64(201 + i),
		}
	}
	writeFSTreeInternal(img.blocks[6], internalEntries)

	// Leaves: each leaf carries one J_INODE_VAL for its inode.
	for i, oid := range inodeIDs {
		writeFSTreeLeafCustom(img.blocks[7+i], []fsLeafEntry{
			{key: jKey(oid, jTypeInode), val: buildInodeValue(1, uint64(oid)*8, 0o100644)},
		})
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
	for _, oid := range inodeIDs {
		ino, err := v.LookupInodeRecord(oid)
		if err != nil {
			t.Fatalf("LookupInodeRecord(%d): %v", oid, err)
		}
		if ino.ID != oid {
			t.Fatalf("ID=%d want %d", ino.ID, oid)
		}
		if ino.Size != oid*8 {
			t.Fatalf("Size=%d want %d", ino.Size, oid*8)
		}
		if ino.ParentID != 1 {
			t.Fatalf("ParentID=%d want 1", ino.ParentID)
		}
	}

	// Negative path: unknown oids return os.ErrNotExist.
	for _, missing := range []uint64{50, 150, 250, 999} {
		_, err := v.LookupInodeRecord(missing)
		if err == nil {
			t.Fatalf("LookupInodeRecord(%d) unexpectedly succeeded", missing)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("LookupInodeRecord(%d) returned %v; want os.ErrNotExist", missing, err)
		}
	}
}

// TestOmapBinarySearch_MultiLevel verifies the OMAP binary-search
// descent by building a 2-level OMAP whose internal root points to two
// fixed-shape OMAP leaves; one entry lives in each child leaf.
func TestOmapBinarySearch_MultiLevel(t *testing.T) {
	// Layout:
	//   block 0: NX SB (omap=1, fs_oid=[100])
	//   block 1: container OMAP (tree=2)   // tree root is internal node
	//   block 2: OMAP internal root         (children 3 and 4)
	//   block 3: OMAP leaf #1  (oid 50  → paddr 6)
	//   block 4: OMAP leaf #2  (oid 100 → paddr 3 = APSB block)  – wait,
	//            but block 3 here is OMAP leaf, not APSB. We re-arrange:
	//
	// Renumber: let the APSB live at block 5. We need:
	//   block 5: APSB
	// Simpler: keep the test focused on the OMAP descent, and have the
	// FS-tree be a single-leaf one inhabited via a one-entry volume OMAP
	// (block 7..). The APSB is mapped through this 2-level container OMAP.
	img := &containerImage{blocks: make([][]byte, 10)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	// Container OMAP internal root (block 2) → children at blocks 3 and 4.
	writeOMAPInternal(img.blocks[2], []struct{ oid, paddr uint64 }{
		{oid: 50, paddr: 3},  // leaf #1 holds oid 50  → APSB candidate
		{oid: 100, paddr: 4}, // leaf #2 holds oid 100 → APSB
	})
	writeOmapBTreeLeaf(img.blocks[3], []struct{ oid, paddr uint64 }{
		{oid: 50, paddr: 5}, // unrelated mapping that must not pollute the search
	})
	writeOmapBTreeLeaf(img.blocks[4], []struct{ oid, paddr uint64 }{
		{oid: 100, paddr: 6}, // APSB lives at block 6
	})
	writeAPSB(img.blocks[6], 100, 7, 200, "OmapBS")
	writeOMAP(img.blocks[7], 8)
	writeOmapBTreeLeaf(img.blocks[8], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 9}})
	writeFSTreeLeafCustom(img.blocks[9], []fsLeafEntry{
		{key: jKey(123, jTypeInode), val: buildInodeValue(1, 7, 0o100644)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume (descended through 2-level container omap): %v", err)
	}
	if v.Name() != "OmapBS" {
		t.Fatalf("Name=%q want OmapBS", v.Name())
	}
	ino, err := v.LookupInodeRecord(123)
	if err != nil {
		t.Fatalf("LookupInodeRecord(123): %v", err)
	}
	if ino.Size != 7 {
		t.Fatalf("Size=%d want 7", ino.Size)
	}
}
