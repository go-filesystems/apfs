package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// writeOmapBTreeLeafXID is writeOmapBTreeLeaf but lets the caller specify
// the xid for each entry. Used to construct OMAPs that hold multiple
// (oid, xid) versions of the same logical object — the layout APFS uses
// to keep both live and snapshot views resolvable.
func writeOmapBTreeLeafXID(block []byte, entries []struct{ oid, xid, paddr uint64 }) {
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeOMAP))
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := uint16(len(entries) * 4)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(tocLen)
	valBaseEnd := len(block) - btreeInfoSize
	for i, e := range entries {
		keyOff := uint16(i * 16)
		valOff := uint16((i + 1) * 16)
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], keyOff)
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], valOff)
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], e.xid)
		v := block[valBaseEnd-(i+1)*16 : valBaseEnd-i*16]
		binary.LittleEndian.PutUint32(v[0:4], 0)
		binary.LittleEndian.PutUint32(v[4:8], 4096)
		binary.LittleEndian.PutUint64(v[8:16], e.paddr)
	}
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], 0x4)
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint32(bi[8:12], 16)
	binary.LittleEndian.PutUint32(bi[12:16], 16)
	binary.LittleEndian.PutUint32(bi[16:20], 16)
	binary.LittleEndian.PutUint32(bi[20:24], 16)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

// TestOpenSnapshot_FrozenFSTree builds an image whose container OMAP
// holds two versions of APSB OID 100 (live at xid 5000 and frozen at xid
// 2000) and whose volume OMAP holds two versions of FS-tree OID 200 (live
// at xid 5000 and frozen at xid 2000). The two FS-tree leaves carry
// different content for inode 101 — Size=100 in the live tree and Size=50
// in the snapshot tree. The test verifies:
//   - The live volume sees Size=100 (latest XID resolution).
//   - OpenSnapshot at xid 2000 sees Size=50 (frozen XID resolution).
//   - LookupSnapshotByName resolves a known name, and ErrNotExist for
//     unknown names.
func TestOpenSnapshot_FrozenFSTree(t *testing.T) {
	// Layout (12 blocks, 4 KiB each):
	//   0  NX SB         (omap=1, fs_oid=[100])
	//   1  container OMAP (tree=2)
	//   2  container OMAP leaf (oid=100 xid=2000 → block 4 frozen APSB,
	//                           oid=100 xid=5000 → block 3 live APSB)
	//   3  live APSB     (omap=5, root_tree_oid=200, snap_meta_oid=300)
	//   4  frozen APSB   (omap=5, root_tree_oid=200, snap_meta_oid=300)
	//   5  volume OMAP   (tree=6)
	//   6  volume OMAP leaf (oid=200 xid=2000 → block 8 frozen FS-tree,
	//                       oid=200 xid=5000 → block 7 live FS-tree,
	//                       oid=300 xid=5000 → block 9 snap meta tree)
	//   7  live FS-tree leaf — inode 101 Size=100
	//   8  frozen FS-tree leaf — inode 101 Size=50
	//   9  snap meta tree leaf — one J_SNAP_META at xid=2000 named "yesterday"
	img := &containerImage{blocks: make([][]byte, 10)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeafXID(img.blocks[2], []struct{ oid, xid, paddr uint64 }{
		{oid: 100, xid: 2000, paddr: 4}, // frozen APSB at older xid
		{oid: 100, xid: 5000, paddr: 3}, // live APSB at newer xid
	})
	writeAPSBWithSnapMeta(img.blocks[3], 100, 5, 200, 300, "Live")
	writeAPSBWithSnapMeta(img.blocks[4], 100, 5, 200, 300, "Live") // frozen apsb name doesn't matter for the test
	writeOMAP(img.blocks[5], 6)
	writeOmapBTreeLeafXID(img.blocks[6], []struct{ oid, xid, paddr uint64 }{
		{oid: 200, xid: 2000, paddr: 8}, // frozen FS-tree
		{oid: 200, xid: 5000, paddr: 7}, // live FS-tree
		{oid: 300, xid: 5000, paddr: 9}, // snap meta tree (only need latest)
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 100, 0o100644)},
	})
	writeFSTreeLeafCustom(img.blocks[8], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 50, 0o100644)},
	})
	writeFSTreeLeafCustom(img.blocks[9], []fsLeafEntry{
		{
			key: snapMetaKey(2000),
			val: snapMetaValue(0, 100 /* sblock_oid (live APSB) */, 0xC1, 0xC2, 1, 0, "yesterday"),
		},
	})

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()

	// --- Live volume sees the freshest content. -----------------------------
	live, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if live.xidLimit != ^uint64(0) {
		t.Fatalf("live xidLimit=%d, want ^uint64(0)", live.xidLimit)
	}
	liveIno, err := live.LookupInodeRecord(101)
	if err != nil {
		t.Fatalf("LookupInodeRecord (live): %v", err)
	}
	if liveIno.Size != 100 {
		t.Fatalf("live size=%d want 100", liveIno.Size)
	}

	// --- Snapshot enumeration. ---------------------------------------------
	snaps, err := live.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 || snaps[0].Name != "yesterday" || snaps[0].XID != 2000 {
		t.Fatalf("unexpected snapshots: %+v", snaps)
	}

	// --- LookupSnapshotByName. ----------------------------------------------
	resolved, err := live.LookupSnapshotByName("yesterday")
	if err != nil {
		t.Fatalf("LookupSnapshotByName: %v", err)
	}
	if resolved.XID != 2000 {
		t.Fatalf("resolved xid=%d want 2000", resolved.XID)
	}
	if _, err := live.LookupSnapshotByName("does-not-exist"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist for unknown snapshot, got %v", err)
	}

	// --- OpenSnapshot reads the frozen FS-tree. ----------------------------
	snap, err := c.OpenSnapshot(resolved)
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	if snap.xidLimit != 2000 {
		t.Fatalf("snapshot xidLimit=%d, want 2000", snap.xidLimit)
	}
	snapIno, err := snap.LookupInodeRecord(101)
	if err != nil {
		t.Fatalf("LookupInodeRecord (snapshot): %v", err)
	}
	if snapIno.Size != 50 {
		t.Fatalf("snapshot size=%d want 50 (we got the live tree, not the frozen one)", snapIno.Size)
	}
}
