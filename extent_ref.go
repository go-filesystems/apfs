package filesystem_apfs

// extent_ref.go — iteration "Phase 4c + 4d" of the read/write roadmap.
//
// The volume's extent-ref tree (apsb.apfs_extentref_tree_oid → PHYSICAL
// B-tree of subtype APFS_OBJECT_TYPE_BLOCKREFTREE = 0x0F) records the
// reference count of every physical extent in the volume. fsck_apfs's
// per-extent cross-check walks every J_FILE_EXTENT in the FS-tree and
// expects a matching `j_phys_ext` record covering the same range, with
// refcnt = (number of FS-tree references). Without a matching record
// fsck reports
//   error: missing/invalid physical extent (N + 1) with refcnt 1
// for every extent we wrote.
//
// CreateFile invokes appendExtentRefRecord after writing payload + the
// FS-tree entries. The implementation handles the single-leaf case only
// (matching what we do for the FS-tree); split / multi-level support is
// follow-up work alongside FS-tree split.
//
// The APSB also tracks `apfs_fs_alloc_count` at offset 0x58: the number
// of blocks owned by the volume (metadata trees + every file extent).
// fsck reports "apfs_fs_alloc_count is not valid (expected N, actual M)"
// when this drifts. bumpFSAllocCount adjusts the counter in place after
// each allocation so the cross-check passes.

import (
	"encoding/binary"
	"fmt"
)

// encodePhysExtKey serialises a j_phys_ext_key (8 bytes: phys_block in
// the low 60 bits, jTypeExtent (=2) in the high 4 bits).
func encodePhysExtKey(physBlock uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, physBlock|(uint64(jTypeExtent)<<60))
	return k
}

// encodePhysExtValue serialises a j_phys_ext_val:
//   +0  uint64 len_and_kind   — block count in low 60 bits, kind in high 4
//   +8  uint64 owning_obj_id  — owning inode oid
//   +16 int32  refcnt         — reference count (1 for a single owner)
//
// kind = APFS_KIND_NEW (1) for newly written extents.
func encodePhysExtValue(blockCount, owningInode uint64, refcnt int32) []byte {
	const apfsKindNew uint64 = 1
	v := make([]byte, 20)
	binary.LittleEndian.PutUint64(v[0:8], blockCount|(apfsKindNew<<60))
	binary.LittleEndian.PutUint64(v[8:16], owningInode)
	binary.LittleEndian.PutUint32(v[16:20], uint32(refcnt))
	return v
}

// emitPhysicalBTreeLeafExplicit packs (key, value) entries into a fresh
// blockSize-byte PHYSICAL B-tree leaf node. Used for the extent-ref tree
// (subtype = APFS_OBJECT_TYPE_BLOCKREFTREE = 0x0F). The layout is
// identical to emitFSTreeLeafExplicit (variable-shape kvloc, BTreeInfo
// trailer) except:
//   - storage class is PHYSICAL (object oid = block paddr)
//   - bt_flags carries APFS_BTREE_PHYSICAL
func emitPhysicalBTreeLeafExplicit(entries []fsLeafKV, blockSize int, ownPaddr, xid uint64, subtype uint16) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTree, uint32(subtype), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0) // btn_level = 0
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := len(entries) * 8
	if tocLen < 64 {
		tocLen = 64
	}
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], uint16(tocLen))
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + tocLen
	endOfData := blockSize - btreeInfoSize

	keyOff := 0
	valCur := 0
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + len(e.key)
		if need > endOfData-valCur-len(e.val) {
			return nil, fmt.Errorf("apfs: emitPhysicalBTreeLeaf: leaf overflow at entry %d", i)
		}
		copy(block[keyArea+keyOff:keyArea+keyOff+len(e.key)], e.key)
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(len(e.key)))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+len(e.val)))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(len(e.val)))
		valCur += len(e.val)
		copy(block[endOfData-valCur:endOfData-valCur+len(e.val)], e.val)
		keyOff += len(e.key)
	}
	freeLen := uint16(endOfData - (keyArea + keyOff) - valCur)
	binary.LittleEndian.PutUint16(block[off+12:off+14], uint16(keyOff))
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)

	longestKey, longestVal := uint32(0), uint32(0)
	for _, e := range entries {
		if uint32(len(e.key)) > longestKey {
			longestKey = uint32(len(e.key))
		}
		if uint32(len(e.val)) > longestVal {
			longestVal = uint32(len(e.val))
		}
	}
	bi := block[blockSize-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical|btreeFlagKVNonAligned)
	binary.LittleEndian.PutUint32(bi[4:8], uint32(blockSize))
	binary.LittleEndian.PutUint32(bi[16:20], longestKey)
	binary.LittleEndian.PutUint32(bi[20:24], longestVal)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
	sealBlock(block)
	return block, nil
}

// appendExtentRefRecord adds a (phys_block, len_and_kind, owning_obj_id,
// refcnt=1) record to the volume's extent-ref tree. The tree must
// currently be a single leaf node (true on freshly-formatted volumes
// AND on Apple's `hdiutil create -fs APFS` output, which also starts
// empty). Returns nil if v.apsb.extentRefOID is zero (no tree).
//
// The leaf is rewritten in place at v.apsb.extentRefOID (PHYSICAL: oid
// IS the paddr). Its obj_phys.o_xid is preserved — fsck accepts an
// in-place edit as long as o_xid ≤ checkpoint xid.
func (v *Volume) appendExtentRefRecord(physBlock, blockCount, owningInode uint64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsb == nil || v.apsb.extentRefOID == 0 {
		return nil
	}
	bs := v.physicalBlockSize()
	rootPaddr := v.apsb.extentRefOID // PHYSICAL: oid is the paddr
	rawRoot, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref: read root at paddr %d: %w", rootPaddr, err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return fmt.Errorf("apfs: extentref: parse root: %w", err)
	}
	if !rootNode.IsLeaf() {
		// Already promoted: descend through the level-1 root.
		return v.extentRefAppendMultiLevel(rawRoot, rootNode, physBlock, blockCount, owningInode)
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return fmt.Errorf("apfs: extentref: parse btree info: %w", err)
	}
	existing, err := readAllLeafEntries(rootNode, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: extentref: read entries: %w", err)
	}
	all := make([]fsLeafKV, 0, len(existing)+1)
	all = append(all, existing...)
	all = append(all, fsLeafKV{
		key: encodePhysExtKey(physBlock),
		val: encodePhysExtValue(blockCount, owningInode, 1),
	})
	leafXID := rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitPhysicalBTreeLeafExplicit(all, int(bs), rootPaddr, leafXID, objTypeBlockRefTree)
	if err != nil {
		// Leaf overflow: promote to a 2-level tree and place the new
		// entry into the appropriate child leaf.
		return v.promoteExtentRefToTwoLevel(rootPaddr, leafXID, all)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: extentref: write leaf at paddr %d: %w", rootPaddr, err)
	}
	return nil
}

// bumpFSAllocCount adjusts the volume's APSB.apfs_fs_alloc_count (offset
// 0x58) by `delta` blocks. fsck_apfs's "apfs_fs_alloc_count is not valid
// (expected N, actual M)" warning fires when the counter drifts from
// the live FS state — every block the volume owns (metadata trees +
// each file extent) must be reflected here.
//
// Reads the APSB block at the paddr currently published by the
// container OMAP, mutates the field, re-Fletcher-seals, and writes back
// in place. Returns nil if the volume has no apsbOID (e.g. snapshot view).
func (v *Volume) bumpFSAllocCount(delta int64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsbOID == 0 {
		return nil
	}
	bs := v.physicalBlockSize()
	apsbPaddr, err := v.c.omapLookup(v.c.containerOmap, v.apsbOID, ^uint64(0))
	if err != nil {
		return fmt.Errorf("apfs: bumpFSAllocCount: lookup APSB: %w", err)
	}
	apsbBlock, err := v.c.readBlock(apsbPaddr)
	if err != nil {
		return fmt.Errorf("apfs: bumpFSAllocCount: read APSB at paddr %d: %w", apsbPaddr, err)
	}
	if len(apsbBlock) < 0x60 {
		return fmt.Errorf("apfs: bumpFSAllocCount: APSB block too short")
	}
	cur := binary.LittleEndian.Uint64(apsbBlock[0x58:0x60])
	var next uint64
	if delta < 0 {
		d := uint64(-delta)
		if d > cur {
			next = 0
		} else {
			next = cur - d
		}
	} else {
		next = cur + uint64(delta)
	}
	binary.LittleEndian.PutUint64(apsbBlock[0x58:0x60], next)
	sealBlock(apsbBlock)
	if _, err := v.c.w.WriteAt(apsbBlock, int64(apsbPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: bumpFSAllocCount: write APSB at paddr %d: %w", apsbPaddr, err)
	}
	return nil
}
