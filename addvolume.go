package filesystem_apfs

// addvolume.go — Multi-volume container support.
//
// Apple's APFS containers can hold up to 100 volumes per container,
// each with its own APSB / FS-tree / snap-meta / extent-ref / volume
// OMAP. `Container.AddVolume(label)` extends a freshly-formatted
// single-volume container with an additional volume, allocating six
// metadata blocks past the existing format-time metadata, building
// the new volume's tree set, and threading the new volume's APSB
// through both the container OMAP and the NX SB's fs_oid array.
//
// Layout for the i-th additional volume (i ≥ 1):
//   formatMetadataBlocks + 6*(i-1) + 0 : APSB
//   formatMetadataBlocks + 6*(i-1) + 1 : volume OMAP
//   formatMetadataBlocks + 6*(i-1) + 2 : volume OMAP leaf
//   formatMetadataBlocks + 6*(i-1) + 3 : FS-tree root
//   formatMetadataBlocks + 6*(i-1) + 4 : snap-meta tree root
//   formatMetadataBlocks + 6*(i-1) + 5 : extent-ref tree root

import (
	"encoding/binary"
	"fmt"
	"time"
)

// AddVolume adds a new volume to an open APFS container. Returns the
// new volume's index in the container's fs_oid array (0-based; the
// existing first volume is at index 0). Caller does NOT need to
// invoke Commit afterward — the changes are persisted in place at
// block 0 + the current desc-area NX SB copy + the container OMAP
// leaf.
//
// Limit: the container starts with one volume from FormatContainer
// and can grow to a total of 100. Each additional volume needs 6
// fresh metadata blocks; AddVolume returns an error when the chunk
// bitmap can't supply 6 contiguous free blocks past the format-time
// metadata.
func (c *Container) AddVolume(label string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return 0, ErrReadOnly
	}
	if c.sb == nil {
		return 0, fmt.Errorf("apfs: AddVolume: container superblock not loaded")
	}
	if len(c.sb.fsOIDs) >= 100 {
		return 0, fmt.Errorf("apfs: AddVolume: max 100 volumes per container")
	}
	if label == "" {
		return 0, fmt.Errorf("apfs: AddVolume: empty label")
	}
	bs := uint64(c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}

	// 1. Allocate 6 contiguous blocks past existing metadata.
	startSearch := uint64(formatMetadataBlocks)
	firstBlock, ok, err := c.firstFreeBlockAtOrAfter(startSearch)
	if err != nil {
		return 0, fmt.Errorf("apfs: AddVolume: search free blocks: %w", err)
	}
	if !ok {
		return 0, fmt.Errorf("apfs: AddVolume: no free space for new volume metadata")
	}
	const newVolMetaBlocks = 6
	if err := c.markBlocksAllocated(firstBlock, newVolMetaBlocks); err != nil {
		return 0, fmt.Errorf("apfs: AddVolume: mark allocated: %w", err)
	}
	apsbPaddr := firstBlock
	volOmapPaddr := firstBlock + 1
	volOmapLeafPaddr := firstBlock + 2
	fsTreePaddr := firstBlock + 3
	snapMetaPaddr := firstBlock + 4
	extentRefPaddr := firstBlock + 5

	// 2. Allocate fresh virtual OIDs for the new volume.
	apsbOID := c.allocVirtualOID()
	fsTreeOID := c.allocVirtualOID()

	// 3. Build the 6 metadata blocks.
	apsbBlock := make([]byte, bs)
	encodeAPSBExplicit(apsbBlock, label, uint32(len(c.sb.fsOIDs)), apsbOID, fsTreeOID,
		volOmapPaddr, snapMetaPaddr, extentRefPaddr)
	sealBlock(apsbBlock)

	volOmapBlock := make([]byte, bs)
	encodeOMAPPhys(volOmapBlock, volOmapPaddr, volOmapLeafPaddr, false /* isContainer */)
	sealBlock(volOmapBlock)

	volOmapLeafBlock := make([]byte, bs)
	encodeOMAPLeaf(volOmapLeafBlock, volOmapLeafPaddr, []omapEntry{
		{oid: fsTreeOID, xid: defaultFormatXID, paddr: fsTreePaddr},
	})
	sealBlock(volOmapLeafBlock)

	fsTreeBlock := make([]byte, bs)
	if leaf, err := emitFSTreeLeafExplicit(upsertRootDir(nil), int(bs), fsTreeOID, defaultFormatXID); err == nil {
		copy(fsTreeBlock, leaf)
	} else {
		return 0, fmt.Errorf("apfs: AddVolume: emit FS-tree leaf: %w", err)
	}

	snapMetaBlock := make([]byte, bs)
	encodeEmptyPhysicalBTree(snapMetaBlock, snapMetaPaddr, objTypeSnapMetaTree)
	sealBlock(snapMetaBlock)

	extentRefBlock := make([]byte, bs)
	encodeEmptyPhysicalBTree(extentRefBlock, extentRefPaddr, objTypeBlockRefTree)
	sealBlock(extentRefBlock)

	// 4. Write the 6 blocks.
	for _, w := range []struct {
		paddr uint64
		data  []byte
	}{
		{apsbPaddr, apsbBlock},
		{volOmapPaddr, volOmapBlock},
		{volOmapLeafPaddr, volOmapLeafBlock},
		{fsTreePaddr, fsTreeBlock},
		{snapMetaPaddr, snapMetaBlock},
		{extentRefPaddr, extentRefBlock},
	} {
		if _, err := c.w.WriteAt(w.data, int64(w.paddr*bs)); err != nil {
			return 0, fmt.Errorf("apfs: AddVolume: write paddr %d: %w", w.paddr, err)
		}
	}

	// 5. Insert (apsbOID, defaultFormatXID) → apsbPaddr into the
	//    container OMAP leaf.
	if err := c.upsertContainerOMAPEntry(apsbOID, defaultFormatXID, apsbPaddr); err != nil {
		return 0, fmt.Errorf("apfs: AddVolume: container OMAP upsert: %w", err)
	}

	// 6. Update the NX SB at block 0 + the desc-area NX SB copy:
	//    - append apsbOID at fs_oid[len]
	//    - bump nx_next_oid past the highest oid we just allocated
	//    - re-seal both
	if err := c.appendFSOIDAndPersist(apsbOID); err != nil {
		return 0, fmt.Errorf("apfs: AddVolume: NX SB persist: %w", err)
	}

	// 7. Refresh in-memory state.
	c.sb.fsOIDs = append(c.sb.fsOIDs, apsbOID)
	if c.sb.nextOID < c.allocOIDCursor {
		c.sb.nextOID = c.allocOIDCursor
	}
	return len(c.sb.fsOIDs) - 1, nil
}

// upsertContainerOMAPEntry inserts (or replaces) an entry in the
// container OMAP's leaf. Mirrors `Volume.upsertVolumeOMAPEntry` but
// drives the CONTAINER OMAP (which lives at c.sb.omapOID, addressed
// as PHYSICAL via c.containerOmap.treeOID).
func (c *Container) upsertContainerOMAPEntry(oid, xid, paddr uint64) error {
	if c.w == nil {
		return ErrReadOnly
	}
	if c.containerOmap == nil || c.containerOmap.treeOID == 0 {
		return fmt.Errorf("no container OMAP")
	}
	bs := uint64(c.sb.blockSize)
	leafPaddr := c.containerOmap.treeOID
	rawLeaf, err := c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("read container OMAP leaf: %w", err)
	}
	leafNode, err := readBTreeNode(rawLeaf)
	if err != nil {
		return fmt.Errorf("parse container OMAP leaf: %w", err)
	}
	if !leafNode.IsLeaf() {
		return fmt.Errorf("container OMAP not a single leaf (level=%d)", leafNode.level)
	}
	leafInfo, err := readRootBTreeInfo(rawLeaf)
	if err != nil {
		return fmt.Errorf("parse OMAP info: %w", err)
	}
	r, err := newNodeReader(leafNode, leafInfo)
	if err != nil {
		return err
	}
	type omapKV struct{ oid, xid, paddr uint64 }
	entries := make([]omapKV, 0, r.EntryCount()+1)
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return err
		}
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		entries = append(entries, omapKV{
			oid:   binary.LittleEndian.Uint64(k[0:8]),
			xid:   binary.LittleEndian.Uint64(k[8:16]),
			paddr: binary.LittleEndian.Uint64(val[8:16]),
		})
	}
	updated := false
	for i := range entries {
		if entries[i].oid == oid && entries[i].xid == xid {
			entries[i].paddr = paddr
			updated = true
			break
		}
	}
	if !updated {
		entries = append(entries, omapKV{oid: oid, xid: xid, paddr: paddr})
	}
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0; j-- {
			a, b := entries[j-1], entries[j]
			if a.oid < b.oid || (a.oid == b.oid && a.xid <= b.xid) {
				break
			}
			entries[j-1], entries[j] = b, a
		}
	}
	out := make([]byte, bs)
	omapEntries := make([]omapEntry, len(entries))
	for i, e := range entries {
		omapEntries[i] = omapEntry{oid: e.oid, xid: e.xid, paddr: e.paddr}
	}
	encodeOMAPLeaf(out, leafPaddr, omapEntries)
	binary.LittleEndian.PutUint64(out[16:24], leafNode.hdr.xid)
	sealBlock(out)
	if _, err := c.w.WriteAt(out, int64(leafPaddr*bs)); err != nil {
		return fmt.Errorf("write container OMAP leaf: %w", err)
	}
	return nil
}

// appendFSOIDAndPersist writes the new APSB OID into the NX SB's
// fs_oid array (slot index = len(c.sb.fsOIDs)), bumps nx_next_oid to
// the high-water mark of allocated OIDs, and persists both block 0
// AND the current desc-area NX SB copy with re-Fletcher-sealed
// content. fsck cross-checks block 0 against the desc-area copy and
// rejects mismatches.
func (c *Container) appendFSOIDAndPersist(newOID uint64) error {
	bs := uint64(c.sb.blockSize)
	const fsOIDOffset = 184
	const maxFSOIDs = 100
	slot := len(c.sb.fsOIDs)
	if slot >= maxFSOIDs {
		return fmt.Errorf("fs_oid array full")
	}
	descCopyPaddr := c.sb.xpDescBase + uint64(c.sb.xpDescIndex) + uint64(c.sb.xpDescLen) - 1

	for _, paddr := range []uint64{0, descCopyPaddr} {
		block, err := c.readBlock(paddr)
		if err != nil {
			return fmt.Errorf("read NX SB at paddr %d: %w", paddr, err)
		}
		off := fsOIDOffset + slot*8
		if off+8 > len(block) {
			return fmt.Errorf("fs_oid slot %d out of range", slot)
		}
		binary.LittleEndian.PutUint64(block[off:off+8], newOID)
		// Bump nx_next_oid (offset 88) if the cursor moved past it.
		curNext := binary.LittleEndian.Uint64(block[88:96])
		if c.allocOIDCursor > curNext {
			binary.LittleEndian.PutUint64(block[88:96], c.allocOIDCursor)
		}
		sealBlock(block)
		if _, err := c.w.WriteAt(block, int64(paddr*bs)); err != nil {
			return fmt.Errorf("write NX SB at paddr %d: %w", paddr, err)
		}
	}
	return nil
}

// encodeAPSBExplicit is a parameterised version of encodeAPSB that
// drives the APSB construction with explicit OIDs/paddrs/index. Used
// by AddVolume to construct each additional volume's APSB block.
//
// The implementation mirrors encodeAPSB byte-for-byte but with the
// caller-supplied values plugged in; we don't simply call encodeAPSB
// then patch because (a) several fields are conditional on storage
// class and (b) we need a fresh apfs_vol_uuid per volume.
func encodeAPSBExplicit(block []byte, label string, fsIndex uint32, apsbOID, fsTreeOID, volOmapPaddr, snapMetaPaddr, extentRefPaddr uint64) {
	encodeObjHeader(block, apsbOID, defaultFormatXID, objTypeAPFSVolume, 0, objStorageVirtual)
	copy(block[0x20:0x24], apsbMagicASCII)
	binary.LittleEndian.PutUint32(block[0x24:0x28], fsIndex)
	binary.LittleEndian.PutUint64(block[0x28:0x30], 0x2)            // apfs_features = HARDLINK_MAP_RECORDS
	binary.LittleEndian.PutUint64(block[0x38:0x40], 0x1)            // apfs_incompatible_features = CASE_INSENSITIVE
	binary.LittleEndian.PutUint64(block[0x58:0x60], 5)              // apfs_fs_alloc_count
	const wmcsMajorVersion uint16 = 5
	const wmcsProtectionClassF uint32 = 6
	const wmcsKeyRevision uint16 = 1
	binary.LittleEndian.PutUint16(block[0x60:0x62], wmcsMajorVersion)
	binary.LittleEndian.PutUint32(block[0x68:0x6C], wmcsProtectionClassF)
	binary.LittleEndian.PutUint32(block[0x6C:0x70], 0x19440850)
	binary.LittleEndian.PutUint16(block[0x70:0x72], wmcsKeyRevision)
	const rootTreeType uint32 = objStorageVirtual | uint32(objTypeBTree)
	const extRefTreeType uint32 = objStoragePhysical | uint32(objTypeBTree)
	const snapMetaTreeType uint32 = objStoragePhysical | uint32(objTypeBTree)
	binary.LittleEndian.PutUint32(block[0x74:0x78], rootTreeType)
	binary.LittleEndian.PutUint32(block[0x78:0x7C], extRefTreeType)
	binary.LittleEndian.PutUint32(block[0x7C:0x80], snapMetaTreeType)
	binary.LittleEndian.PutUint64(block[0x80:0x88], volOmapPaddr)
	binary.LittleEndian.PutUint64(block[0x88:0x90], fsTreeOID)
	binary.LittleEndian.PutUint64(block[0x90:0x98], extentRefPaddr)
	binary.LittleEndian.PutUint64(block[0x98:0xA0], snapMetaPaddr)
	binary.LittleEndian.PutUint64(block[0xB0:0xB8], 0x10)
	if _, err := formatRandReadFn(block[0xF0:0x100]); err != nil {
		_ = err
	}
	formatNow := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(block[0x100:0x108], formatNow)
	const apfsFSUnencrypted uint64 = 0x1
	binary.LittleEndian.PutUint64(block[0x108:0x110], apfsFSUnencrypted)
	const formatterID = "go-filesystems/apfs (D-7)"
	copy(block[0x110:0x110+32], []byte(formatterID))
	binary.LittleEndian.PutUint64(block[0x130:0x138], formatNow)
	binary.LittleEndian.PutUint64(block[0x138:0x140], defaultFormatXID)
	const physicalBTree uint32 = objStoragePhysical | uint32(objTypeBTree)
	const bareBTree uint32 = uint32(objTypeBTree)
	binary.LittleEndian.PutUint32(block[0x410:0x414], physicalBTree)
	binary.LittleEndian.PutUint32(block[0x414:0x418], physicalBTree)
	binary.LittleEndian.PutUint64(block[0x420:0x428], defaultFormatXID)
	binary.LittleEndian.PutUint32(block[0x428:0x42C], 0x10)
	binary.LittleEndian.PutUint32(block[0x42C:0x430], bareBTree)
	binary.LittleEndian.PutUint32(block[0x450:0x454], bareBTree)
	binary.LittleEndian.PutUint32(block[0x460:0x464], bareBTree)
	binary.LittleEndian.PutUint32(block[0x468:0x46C], 0xC)
	if label != "" {
		const volNameOff = 0x2C0
		const volNameLen = 256
		raw := []byte(label)
		if len(raw) >= volNameLen {
			raw = raw[:volNameLen-1]
		}
		copy(block[volNameOff:volNameOff+len(raw)], raw)
	}
	const apfsMinDocID uint32 = 3
	binary.LittleEndian.PutUint32(block[0x3C0:0x3C4], apfsMinDocID)
}
