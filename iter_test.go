package filesystem_apfs

import (
	"encoding/binary"
	"testing"
)

// TestSeekAndIterate_StopsOnRangeBoundary asserts that seekAndIterate
// (a) walks every key once in ascending order across a multi-leaf tree,
// (b) honours an early-stop signal from the visit callback,
// (c) supports arbitrary seek targets (the "rightmost ≤ target" descent
//     followed by leaf "first ≥ target" binary search must always land us
//     on the correct first leaf entry, not one too early or one too late).
func TestSeekAndIterate_StopsOnRangeBoundary(t *testing.T) {
	// Layout (10 blocks):
	//   0  NX SB
	//   1  container OMAP
	//   2  container OMAP leaf
	//   3  APSB (root_tree_oid=200)
	//   4  volume OMAP
	//   5  volume OMAP leaf — root + 3 leaves
	//   6  FS-tree internal root (3 children)
	//   7  FS-tree leaf #1: inodes 100, 200
	//   8  FS-tree leaf #2: inodes 300, 400
	//   9  FS-tree leaf #3: inodes 500, 600
	img := &containerImage{blocks: make([][]byte, 10)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Iter")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
		{oid: 201, paddr: 7},
		{oid: 202, paddr: 8},
		{oid: 203, paddr: 9},
	})

	// Three leaves of two inodes each, in canonical sort order.
	leaves := [][]uint64{{100, 200}, {300, 400}, {500, 600}}
	for li, leaf := range leaves {
		entries := make([]fsLeafEntry, 0, len(leaf))
		for _, oid := range leaf {
			entries = append(entries, fsLeafEntry{
				key: jKey(oid, jTypeInode),
				val: buildInodeValue(1, oid, 0o100644),
			})
		}
		writeFSTreeLeafCustom(img.blocks[7+li], entries)
	}
	// Internal root: smallest key in each subtree.
	writeFSTreeInternal(img.blocks[6], []fsInternalEntry{
		{key: jKey(100, jTypeInode), childOID: 201},
		{key: jKey(300, jTypeInode), childOID: 202},
		{key: jKey(500, jTypeInode), childOID: 203},
	})

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

	// (a) Iteration from the smallest possible target visits all 6 inodes
	// in order across all 3 leaves.
	t.Run("full_iteration", func(t *testing.T) {
		var seen []uint64
		err := v.seekAndIterate(make([]byte, 8), func(k, val []byte) (bool, error) {
			oid, _, _ := jKeyHeader(k)
			seen = append(seen, oid)
			return false, nil
		})
		if err != nil {
			t.Fatalf("seekAndIterate: %v", err)
		}
		want := []uint64{100, 200, 300, 400, 500, 600}
		if len(seen) != len(want) {
			t.Fatalf("seen=%v want %v", seen, want)
		}
		for i, oid := range want {
			if seen[i] != oid {
				t.Fatalf("seen[%d]=%d want %d (full=%v)", i, seen[i], oid, seen)
			}
		}
	})

	// (b) Early-stop callback after seeing inode 300 must NOT visit 400/500/600.
	t.Run("early_stop", func(t *testing.T) {
		var seen []uint64
		err := v.seekAndIterate(make([]byte, 8), func(k, val []byte) (bool, error) {
			oid, _, _ := jKeyHeader(k)
			seen = append(seen, oid)
			if oid == 300 {
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			t.Fatalf("seekAndIterate (early stop): %v", err)
		}
		want := []uint64{100, 200, 300}
		if len(seen) != len(want) {
			t.Fatalf("seen=%v want %v", seen, want)
		}
	})

	// (c) Seeking to (350, type=jTypeInode) must skip leaf #1 entirely
	// and start iteration at inode 400 (leaf #2's second entry).
	t.Run("seek_skips_leaf", func(t *testing.T) {
		target := make([]byte, 8)
		binary.LittleEndian.PutUint64(target, 350|(uint64(jTypeInode)<<60))
		var seen []uint64
		err := v.seekAndIterate(target, func(k, val []byte) (bool, error) {
			oid, _, _ := jKeyHeader(k)
			seen = append(seen, oid)
			return false, nil
		})
		if err != nil {
			t.Fatalf("seekAndIterate (seek): %v", err)
		}
		want := []uint64{400, 500, 600}
		if len(seen) != len(want) {
			t.Fatalf("seen=%v want %v", seen, want)
		}
	})

	// (d) Seek past everything: no iterations.
	t.Run("seek_past_end", func(t *testing.T) {
		target := make([]byte, 8)
		binary.LittleEndian.PutUint64(target, 9999|(uint64(jTypeInode)<<60))
		var seen []uint64
		err := v.seekAndIterate(target, func(k, val []byte) (bool, error) {
			oid, _, _ := jKeyHeader(k)
			seen = append(seen, oid)
			return false, nil
		})
		if err != nil {
			t.Fatalf("seekAndIterate (past end): %v", err)
		}
		if len(seen) != 0 {
			t.Fatalf("expected no iterations past end, got %v", seen)
		}
	})
}

// TestFindInode_AggregatesAcrossLeaves confirms the cursor-based
// FindInode pulls together inode + extents from one leaf and the drec
// from another, returning a fully populated Inode.
func TestFindInode_AggregatesAcrossLeaves(t *testing.T) {
	// Reuse the multi-leaf layout shape but with a single inode whose
	// records straddle two leaves: leaf 1 = inode + ext, leaf 2 = drec.
	img := &containerImage{blocks: make([][]byte, 9)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Aggregate")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
		{oid: 201, paddr: 7},
		{oid: 202, paddr: 8},
	})
	writeFSTreeInternal(img.blocks[6], []fsInternalEntry{
		{key: jKey(101, jTypeInode), childOID: 201},
		{key: jKey(1, jTypeDirRec), childOID: 202},
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 4096, 0o100644)},
		{key: fileExtKey(101, 0), val: buildFileExtentValue(4096, 10)},
	})
	writeFSTreeLeafCustom(img.blocks[8], []fsLeafEntry{
		{key: drecKey(1, "agg.bin"), val: buildDrecValue(101)},
	})
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
	if ino.ID != 101 || ino.Name != "agg.bin" || ino.ParentID != 1 || ino.Size != 4096 {
		t.Fatalf("FindInode result mismatch: %+v", ino)
	}
	if len(ino.dataExtents) != 1 || ino.dataExtents[0].physBlock != 10 {
		t.Fatalf("expected 1 extent at block 10, got %+v", ino.dataExtents)
	}
}
