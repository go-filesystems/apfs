package filesystem_apfs

import (
	"encoding/binary"
	"testing"
)

// snapMetaKey builds a J_SNAP_META key: j_key_t(xid|TYPE).
func snapMetaKey(xid uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, xid|(uint64(jTypeSnapMeta)<<60))
	return k
}

// snapMetaValue builds a J_SNAP_META value following the apfs_snap_meta_val
// layout (extentref_tree_oid, sblock_oid, create_time, change_time, inum,
// extentref_tree_type, flags, name_len, name (NUL-terminated)).
func snapMetaValue(extentRefOID, sblockOID, createT, changeT, inum uint64, flags uint32, name string) []byte {
	v := make([]byte, 50+len(name)+1)
	binary.LittleEndian.PutUint64(v[0:8], extentRefOID)
	binary.LittleEndian.PutUint64(v[8:16], sblockOID)
	binary.LittleEndian.PutUint64(v[16:24], createT)
	binary.LittleEndian.PutUint64(v[24:32], changeT)
	binary.LittleEndian.PutUint64(v[32:40], inum)
	binary.LittleEndian.PutUint32(v[40:44], 0) // extentref_tree_type
	binary.LittleEndian.PutUint32(v[44:48], flags)
	binary.LittleEndian.PutUint16(v[48:50], uint16(len(name)+1))
	copy(v[50:], name)
	// trailing NUL already zero
	return v
}

// writeAPSBWithSnapMeta is writeAPSB plus a snap_meta tree oid stored
// at offset 0x98 of the APSB block (the apfs_snap_meta_tree_oid slot
// per Apple's apfs_superblock layout).
func writeAPSBWithSnapMeta(block []byte, oid, omapOID, rootTreeOID, snapMetaOID uint64, name string) {
	writeAPSB(block, oid, omapOID, rootTreeOID, name)
	binary.LittleEndian.PutUint64(block[0x98:0xA0], snapMetaOID)
}

// TestListSnapshots constructs a synthetic image with a snapshot
// metadata tree carrying two J_SNAP_META records and verifies ListSnapshots
// returns both, with names, XIDs and sblock_oids round-tripping correctly.
func TestListSnapshots(t *testing.T) {
	// Layout:
	//   block 0:  NX SB  (omap=1, fs_oid=[100])
	//   block 1:  container OMAP  (tree=2)
	//   block 2:  container OMAP leaf
	//   block 3:  APSB  (omap=4, root_tree_oid=200, snap_meta_oid=300)
	//   block 4:  volume OMAP (tree=5)
	//   block 5:  volume OMAP leaf — maps oid 200 → block 6 (FS-tree root)
	//                              and  oid 300 → block 7 (snap meta tree root)
	//   block 6:  FS-tree leaf (single inode)
	//   block 7:  snap meta tree leaf (two J_SNAP_META records)
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSBWithSnapMeta(img.blocks[3], 100, 4, 200, 300, "SnapVol")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
		{oid: 300, paddr: 7},
	})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{
			key: snapMetaKey(7000),
			val: snapMetaValue(0, 1234, 0xC1, 0xC2, 5, 0, "morning-baseline"),
		},
		{
			key: snapMetaKey(7100),
			val: snapMetaValue(0, 5678, 0xD1, 0xD2, 9, 0, "lunch-pre-deploy"),
		},
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
	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("len=%d want 2: %+v", len(snaps), snaps)
	}
	byXID := map[uint64]Snapshot{}
	for _, s := range snaps {
		byXID[s.XID] = s
	}
	if got, ok := byXID[7000]; !ok || got.Name != "morning-baseline" || got.APSBOID != 1234 || got.Inum != 5 {
		t.Fatalf("xid 7000 mismatch: %+v", byXID[7000])
	}
	if got, ok := byXID[7100]; !ok || got.Name != "lunch-pre-deploy" || got.APSBOID != 5678 || got.Inum != 9 {
		t.Fatalf("xid 7100 mismatch: %+v", byXID[7100])
	}
}

// TestListSnapshots_NoTree verifies that a volume without a snapshot
// metadata tree (apfs_snap_meta_tree_oid = 0) returns an empty list rather
// than an error.
func TestListSnapshots_NoTree(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 7)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "NoSnap") // snap_meta_oid stays 0
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	v, _ := c.OpenVolume(0)
	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Fatalf("expected no snapshots, got %d", len(snaps))
	}
}
