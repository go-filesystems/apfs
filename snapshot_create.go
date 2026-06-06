package filesystem_apfs

// snapshot_create.go adds the writer side of APFS snapshots: a
// J_SNAP_META + J_SNAP_NAME pair inserted into the volume's snap-meta
// tree (PHYSICAL B-tree at `apsb.snapMetaOID`), plus an
// `apfs_num_snapshots` bump in the APSB.
//
// MVP scope: a snapshot can be CREATED on a volume that has been
// committed and is otherwise idle. Subsequent writes (CreateFile,
// CreateDirectory, ...) are NOT yet copy-on-write, so modifying the
// volume after a snapshot would corrupt the snapshot's frozen view of
// the FS-tree / extent-ref tree. The current writer mutates roots in
// place; CoW for snapshots is a follow-up. Until that lands, callers
// should treat the volume as read-only after CreateSnapshot.
//
// Reference: `apfs_create_snapshot` in linux-apfs/apfsprogs/apfs/snap.c
// and `struct apfs_snap_metadata_val` in apfs_raw.h.

import (
	"encoding/binary"
	"fmt"
	"time"
)

// apfsAPSBNumSnapshotsOffset is the byte offset of `apfs_num_snapshots`
// in the volume superblock (apfs_raw.h: offset 0xD4).
const apfsAPSBNumSnapshotsOffset = 0xD4

// CreateSnapshot adds a snapshot named `name` to the current volume.
// Returns the snapshot's xid (which Apple uses both as the on-disk
// identifier and as the OMAP key for resolving the frozen APSB later
// via OpenSnapshot).
//
// The snapshot's xid is taken from the container's nextXID counter,
// matching Apple's convention of stamping a snapshot with the xid the
// container will hand out at the next Commit. The Commit cascade then
// promotes this xid into the live state.
func (v *Volume) CreateSnapshot(name string) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateSnapshot on a snapshot view is not supported")
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateSnapshot: empty name")
	}
	if v.apsb == nil || v.apsb.snapMetaOID == 0 {
		return 0, fmt.Errorf("apfs: CreateSnapshot: no snap-meta tree")
	}
	if !v.apsb.snapMetaIsPhysical() {
		return 0, fmt.Errorf("apfs: CreateSnapshot: only PHYSICAL snap-meta trees are supported")
	}

	// Snapshot xid: the container's CURRENT xid, matching Apple's
	// convention (linux-apfs/snapshot.c uses NXI->nx_xid, the active
	// namespace xid at snapshot creation time). fsck cross-checks this
	// xid against om_most_recent_snap on the volume OMAP — they must
	// agree, otherwise fsck reports `invalid hdr.obj_id` against the
	// J_SNAP_META record.
	snapXID := v.c.sb.xid
	if snapXID == 0 {
		snapXID = 1
	}
	createTime := uint64(time.Now().UnixNano())

	// CoW the volume's APSB to a fresh paddr (the snapshot's frozen
	// view). Per linux-apfs/snapshot.c::apfs_create_superblock_snapshot:
	//   1. Allocate a fresh paddr.
	//   2. Copy the current APSB bytes there.
	//   3. Set o_oid = new_paddr (the frozen APSB becomes a PHYSICAL
	//      object — its identity is its paddr, no longer OMAP-resolved).
	//   4. Zero the apfs_omap_oid + apfs_snap_meta_tree_oid fields in
	//      the copy (the snapshot doesn't have its own private trees;
	//      it shares them with the live volume's view at this xid).
	//   5. Reseal Fletcher64.
	frozenPaddr, err := v.allocateFrozenAPSBBlock(snapXID)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateSnapshot: alloc frozen APSB: %w", err)
	}

	// Build the records. J_SNAP_META.sblock_oid is the FROZEN APSB's
	// paddr — fsck reads it as a paddr (not as an OMAP-resolved virtual
	// oid).
	snapMetaKey := encodeSnapMetaKey(snapXID)
	snapMetaVal := encodeSnapMetaValue(
		v.apsb.extentRefOID,
		frozenPaddr,
		createTime, createTime,
		0, // inum (clone source; 0 for normal snapshots)
		v.apsb.extentRefTreeType,
		0, // flags: not auto-deleted
		name,
	)
	snapNameKey := encodeSnapNameKey(name)
	snapNameVal := encodeSnapNameValue(snapXID)
	if err := v.appendSnapMetaRecords([]fsLeafKV{
		{key: snapMetaKey, val: snapMetaVal},
		{key: snapNameKey, val: snapNameVal},
	}); err != nil {
		return 0, fmt.Errorf("apfs: CreateSnapshot: append snap-meta: %w", err)
	}
	if err := v.bumpAPSBNumSnapshots(1); err != nil {
		return 0, fmt.Errorf("apfs: CreateSnapshot: bump num_snapshots: %w", err)
	}
	// Refresh in-memory cache so the snapshot guard sees the new
	// snapshot count immediately (without requiring a re-Open).
	if v.apsb != nil {
		v.apsb.numSnapshots++
	}
	// Materialise the OMAP snapshot tree (om_snap_tree_oid). fsck cross-
	// checks every J_SNAP_META xid against this PHYSICAL B-tree (subtype
	// APFS_OBJECT_TYPE_OMAP_SNAPSHOT = 0x13, fixed-shape: 8-byte key
	// holding snap_xid, 16-byte value `apfs_omap_snapshot{flags, pad,
	// oid}`). Without it, fsck rejects with `Snapshot metadata tree is
	// invalid`. linux-apfs/snapshot.c::apfs_update_omap_snap_tree adds
	// one entry per snapshot using `oms_oid = 0` for the value.
	omapSnapTreePaddr, err := v.allocateOMAPSnapshotTree(snapXID)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateSnapshot: alloc omap_snap_tree: %w", err)
	}
	// Update volume OMAP: om_snap_count++, om_most_recent_snap = snapXID,
	// om_snapshot_tree_oid = omapSnapTreePaddr. Per linux-apfs/snapshot.c::
	// apfs_update_omap_snapshots, all three fields get touched on every
	// snapshot creation. fsck rejects "om_most_recent_snap (X) is not
	// equal to the largest snapshot xid (N)" otherwise.
	if err := v.bumpVolumeOMAPSnapshotState(snapXID, omapSnapTreePaddr); err != nil {
		return 0, fmt.Errorf("apfs: CreateSnapshot: update vol OMAP snap state: %w", err)
	}
	return snapXID, nil
}

// allocateOMAPSnapshotTree allocates a fresh paddr, emits a single-leaf
// PHYSICAL B-tree there with subtype APFS_OBJECT_TYPE_OMAP_SNAPSHOT
// (0x13) carrying one entry — (key=snapXID, val=zero apfs_omap_snapshot).
// Returns the new tree's paddr, ready to plug into the volume OMAP's
// om_snap_tree_oid field.
func (v *Volume) allocateOMAPSnapshotTree(snapXID uint64) (uint64, error) {
	bs := v.physicalBlockSize()
	paddr, err := v.nextFreeBlock()
	if err != nil {
		return 0, err
	}
	v.allocCursor = paddr + 1
	if err := v.c.markBlocksAllocated(paddr, 1); err != nil {
		return 0, err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return 0, err
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	block := emitOMAPSnapshotTreeLeaf(paddr, leafXID, snapXID, int(bs))
	if _, err := v.c.w.WriteAt(block, int64(paddr*bs)); err != nil {
		return 0, fmt.Errorf("apfs: snap-meta: write omap_snap_tree at %d: %w", paddr, err)
	}
	return paddr, nil
}

// objSubtypeOMAPSnapshot is APFS_OBJECT_TYPE_OMAP_SNAPSHOT = 0x13 — the
// subtype carried by every node in the per-OMAP snapshot tree. Defined
// in linux-apfs/apfs_raw.h.
const objSubtypeOMAPSnapshot uint16 = 0x0013

// emitOMAPSnapshotTreeLeaf writes a single-leaf PHYSICAL fixed-shape
// B-tree node (subtype OMAP_SNAPSHOT = 0x13) carrying one entry:
// key = snapXID (8 bytes uint64), val = apfs_omap_snapshot (16 bytes,
// all zero per linux-apfs convention — flags=0, pad=0, oms_oid=0).
//
// Layout matches encodeOMAPLeaf (the regular OMAP) but with different
// key/val sizes and a different subtype. fsck validates bt_key_size +
// bt_val_size against this fixed shape.
func emitOMAPSnapshotTreeLeaf(ownPaddr, xid, snapXID uint64, blockSize int) []byte {
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTree, uint32(objSubtypeOMAPSnapshot), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0) // level = 0
	binary.LittleEndian.PutUint32(block[off+4:off+8], 1) // nkeys = 1
	// Pre-allocate TOC space sufficient for ~80 entries (mkapfs's
	// min_table_size for fixed-shape OMAP-style trees is 4 bytes per
	// kvoff + a margin). Match the regular OMAP's pattern.
	const tocLen uint16 = 8 * 4 // 8 entries * 4-byte kvoff
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)         // table_space.off
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)   // table_space.len
	const keyLen = uint16(8)
	const valLen = uint16(16)
	const headLen = 56
	freeLen := uint16(blockSize - headLen - int(tocLen) - int(keyLen) - int(valLen) - btreeInfoSize)
	binary.LittleEndian.PutUint16(block[off+12:off+14], keyLen)        // free_space.off
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)  // key_free_list.off
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)  // val_free_list.off
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(tocLen)
	valBaseEnd := blockSize - btreeInfoSize
	// Single kvoff entry: key offset = 0 (relative to keyArea start),
	// val offset = 16 (distance from val_end to value's END = val_size).
	binary.LittleEndian.PutUint16(block[tocOff:tocOff+2], 0)
	binary.LittleEndian.PutUint16(block[tocOff+2:tocOff+4], 16)
	// Key: 8-byte uint64 snap_xid.
	binary.LittleEndian.PutUint64(block[keyArea:keyArea+8], snapXID)
	// Value: 16 bytes of zero (oms_flags=0, oms_pad=0, oms_oid=0). The
	// value occupies [valBaseEnd-16, valBaseEnd) per fixed-shape kvoff
	// convention.
	for i := valBaseEnd - 16; i < valBaseEnd; i++ {
		block[i] = 0
	}
	bi := block[blockSize-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical)
	binary.LittleEndian.PutUint32(bi[4:8], uint32(blockSize))
	binary.LittleEndian.PutUint32(bi[8:12], uint32(keyLen))
	binary.LittleEndian.PutUint32(bi[12:16], uint32(valLen))
	binary.LittleEndian.PutUint32(bi[16:20], uint32(keyLen)) // longest_key
	binary.LittleEndian.PutUint32(bi[20:24], uint32(valLen)) // longest_val
	binary.LittleEndian.PutUint64(bi[24:32], 1)              // bt_key_count
	binary.LittleEndian.PutUint64(bi[32:40], 1)              // bt_node_count
	sealBlock(block)
	return block
}

// allocateFrozenAPSBBlock copies the volume's current APSB block to a
// fresh paddr and stamps it as a PHYSICAL object (o_oid = paddr,
// o_xid = snapXID) with zeroed apfs_omap_oid / apfs_snap_meta_tree_oid
// (linux-apfs convention for snapshot-frozen APSBs). The o_xid match
// is what fsck cross-checks: a J_SNAP_META key at xid=N is only valid
// if the block at sblock_oid carries o_xid <= N (and the snapshot's
// xid is the canonical "this APSB was committed at this xid").
// Returns the new paddr.
func (v *Volume) allocateFrozenAPSBBlock(snapXID uint64) (uint64, error) {
	bs := v.physicalBlockSize()
	apsbPaddr, err := v.c.omapLookup(v.c.containerOmap, v.apsbOID, ^uint64(0))
	if err != nil {
		return 0, fmt.Errorf("apfs: snap-meta: lookup live APSB: %w", err)
	}
	apsbBlock, err := v.c.readBlock(apsbPaddr)
	if err != nil {
		return 0, fmt.Errorf("apfs: snap-meta: read live APSB: %w", err)
	}
	frozenPaddr, err := v.nextFreeBlock()
	if err != nil {
		return 0, err
	}
	v.allocCursor = frozenPaddr + 1
	if err := v.c.markBlocksAllocated(frozenPaddr, 1); err != nil {
		return 0, err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return 0, err
	}
	frozen := append([]byte(nil), apsbBlock...)
	binary.LittleEndian.PutUint64(frozen[8:16], frozenPaddr) // o_oid = paddr (PHYSICAL)
	binary.LittleEndian.PutUint64(frozen[16:24], snapXID)    // o_xid = snap xid
	// o_type at offset 24 must be retyped from VIRTUAL (the live APSB's
	// storage class) to PHYSICAL — fsck rejects with `invalid hdr.obj_id`
	// when the stored block carries VIRTUAL bits but is referenced as a
	// paddr (J_SNAP_META.sblock_oid is a paddr, so the block must be
	// PHYSICAL).
	binary.LittleEndian.PutUint32(frozen[24:28], objStoragePhysical|uint32(objTypeAPFSVolume))
	// Zero apfs_omap_oid (offset 0x80) and apfs_snap_meta_tree_oid
	// (offset 0x98) per linux-apfs convention.
	binary.LittleEndian.PutUint64(frozen[0x80:0x88], 0)
	binary.LittleEndian.PutUint64(frozen[0x98:0xA0], 0)
	sealBlock(frozen)
	if _, err := v.c.w.WriteAt(frozen, int64(frozenPaddr*bs)); err != nil {
		return 0, fmt.Errorf("apfs: snap-meta: write frozen APSB at %d: %w", frozenPaddr, err)
	}
	return frozenPaddr, nil
}

// bumpVolumeOMAPSnapshotState updates the volume OMAP's om_snap_count
// (offset +0x04 inside om_*), om_snapshot_tree_oid (offset +0x18), and
// om_most_recent_snap (offset +0x20) fields to reflect a new snapshot
// at snapXID rooted at omapSnapTreePaddr. fsck cross-checks all three
// against the snap-meta tree's largest xid.
//
// Volume OMAP layout (omap_phys, after obj_phys_t header at +0):
//
//	+0x20  uint32 om_flags
//	+0x24  uint32 om_snap_count
//	+0x28  uint32 om_tree_type
//	+0x2C  uint32 om_snap_tree_type
//	+0x30  uint64 om_tree_oid
//	+0x38  uint64 om_snapshot_tree_oid
//	+0x40  uint64 om_most_recent_snap
//
// (Field offsets are within the block, including the 32-byte obj_phys
// header.)
func (v *Volume) bumpVolumeOMAPSnapshotState(snapXID, omapSnapTreePaddr uint64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsb == nil || v.apsb.omapOID == 0 {
		return fmt.Errorf("apfs: snap-meta: no volume OMAP")
	}
	bs := v.physicalBlockSize()
	omapPaddr := v.apsb.omapOID // PHYSICAL → oid is the paddr
	block, err := v.c.readBlock(omapPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: read volume OMAP: %w", err)
	}
	const omSnapCountOff = objPhysSize + 0x04
	const omSnapTreeOIDOff = objPhysSize + 0x18
	const omMostRecentSnapOff = objPhysSize + 0x20
	if len(block) < omMostRecentSnapOff+8 {
		return fmt.Errorf("apfs: snap-meta: volume OMAP block too short")
	}
	cur := binary.LittleEndian.Uint32(block[omSnapCountOff : omSnapCountOff+4])
	binary.LittleEndian.PutUint32(block[omSnapCountOff:omSnapCountOff+4], cur+1)
	binary.LittleEndian.PutUint64(block[omSnapTreeOIDOff:omSnapTreeOIDOff+8], omapSnapTreePaddr)
	binary.LittleEndian.PutUint64(block[omMostRecentSnapOff:omMostRecentSnapOff+8], snapXID)
	sealBlock(block)
	if _, err := v.c.w.WriteAt(block, int64(omapPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta: write volume OMAP: %w", err)
	}
	return nil
}

// encodeSnapMetaKey serialises a J_SNAP_META key (the snapshot's xid in
// the j_key_t oid slot, type=jTypeSnapMeta=1 in the high 4 bits).
func encodeSnapMetaKey(xid uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, xid|(uint64(jTypeSnapMeta)<<60))
	return k
}

// encodeSnapMetaValue serialises a J_SNAP_META value per apfs_raw.h's
// apfs_snap_metadata_val (50 bytes + name, NUL-terminated):
//
//	+0x00  uint64 extentref_tree_oid
//	+0x08  uint64 sblock_oid       (volume APSB virtual oid)
//	+0x10  uint64 create_time
//	+0x18  uint64 change_time
//	+0x20  uint64 inum             (clone source; 0 for normal snapshots)
//	+0x28  uint32 extentref_tree_type
//	+0x2C  uint32 flags
//	+0x30  uint16 name_len         (including trailing NUL)
//	+0x32  name bytes (NUL-terminated)
func encodeSnapMetaValue(extentRefOID, sblockOID, createTime, changeTime, inum uint64, extentRefTreeType, flags uint32, name string) []byte {
	rawName := append([]byte(name), 0)
	v := make([]byte, 50+len(rawName))
	binary.LittleEndian.PutUint64(v[0x00:0x08], extentRefOID)
	binary.LittleEndian.PutUint64(v[0x08:0x10], sblockOID)
	binary.LittleEndian.PutUint64(v[0x10:0x18], createTime)
	binary.LittleEndian.PutUint64(v[0x18:0x20], changeTime)
	binary.LittleEndian.PutUint64(v[0x20:0x28], inum)
	binary.LittleEndian.PutUint32(v[0x28:0x2C], extentRefTreeType)
	binary.LittleEndian.PutUint32(v[0x2C:0x30], flags)
	binary.LittleEndian.PutUint16(v[0x30:0x32], uint16(len(rawName)))
	copy(v[0x32:], rawName)
	return v
}

// apfsSnapNameObjID is the j_key_t oid value Apple reserves for every
// J_SNAP_NAME record: the 60-bit oid field is all-ones
// (`~0ULL & APFS_OBJ_ID_MASK` = 0x0FFFFFFFFFFFFFFF). Per linux-apfs-rw
// snapshot.c::apfs_create_snap_name_rec, every J_SNAP_NAME key uses
// this sentinel — fsck rejects oid=0 with `invalid hdr.obj_id`.
const apfsSnapNameObjID uint64 = 0x0FFFFFFFFFFFFFFF

// encodeSnapNameKey serialises a J_SNAP_NAME key:
//
//	+0   j_key_t (8 bytes; oid=APFS_SNAP_NAME_OBJ_ID, type=11 in high 4 bits)
//	+8   uint16 name_len   (including trailing NUL)
//	+10  name bytes (NUL-terminated)
//
// fsck sorts J_SNAP_NAME keys alphabetically by name within their
// (apfsSnapNameObjID, type=11) range.
func encodeSnapNameKey(name string) []byte {
	rawName := append([]byte(name), 0)
	k := make([]byte, 10+len(rawName))
	binary.LittleEndian.PutUint64(k[0:8], apfsSnapNameObjID|(uint64(jTypeSnapName)<<60))
	binary.LittleEndian.PutUint16(k[8:10], uint16(len(rawName)))
	copy(k[10:], rawName)
	return k
}

// encodeSnapNameValue serialises a J_SNAP_NAME value (just the snap xid).
func encodeSnapNameValue(xid uint64) []byte {
	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, xid)
	return v
}

// appendSnapMetaRecords inserts new (key, val) pairs into the volume's
// snap-meta tree (PHYSICAL btree at apsb.snapMetaOID). The tree must
// be a single leaf (true on freshly-formatted volumes); the leaf is
// rewritten in place at its existing paddr.
func (v *Volume) appendSnapMetaRecords(newEntries []fsLeafKV) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsb == nil || v.apsb.snapMetaOID == 0 {
		return nil
	}
	bs := v.physicalBlockSize()
	rootPaddr := v.apsb.snapMetaOID
	rawRoot, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: read root: %w", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: parse root: %w", err)
	}
	if !rootNode.IsLeaf() {
		// Multi-level: descend per-record.
		for _, ne := range newEntries {
			if err := v.snapMetaAppendOneRecordMultiLevel(rawRoot, rootNode, ne.key, ne.val); err != nil {
				return err
			}
			// Re-read the root after each append (the index may have
			// changed if a leaf split bumped a child's first key).
			rawRoot, err = v.c.readBlock(rootPaddr)
			if err != nil {
				return fmt.Errorf("apfs: snap-meta: re-read root: %w", err)
			}
			rootNode, err = readBTreeNode(rawRoot)
			if err != nil {
				return fmt.Errorf("apfs: snap-meta: re-parse root: %w", err)
			}
		}
		return nil
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: parse btree info: %w", err)
	}
	existing, err := readAllLeafEntries(rootNode, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: read entries: %w", err)
	}
	all := append([]fsLeafKV(nil), existing...)
	for _, ne := range newEntries {
		all = upsertEntry(all, ne.key, ne.val)
	}
	leafXID := rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitPhysicalBTreeLeafExplicit(all, int(bs), rootPaddr, leafXID, objTypeSnapMetaTree)
	if err != nil {
		// Leaf overflow: promote to a 2-level tree, splitting all
		// entries between two new non-root leaves.
		return v.promoteSnapMetaToTwoLevel(rootPaddr, leafXID, all)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta: write leaf at paddr %d: %w", rootPaddr, err)
	}
	return nil
}

// bumpAPSBNumSnapshots adjusts the APSB's apfs_num_snapshots field
// (offset 0xD4) by `delta`. Reads the current APSB block (via the
// container OMAP), patches the uint32 in place, re-Fletcher-seals,
// writes back at the same paddr.
func (v *Volume) bumpAPSBNumSnapshots(delta int32) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsbOID == 0 {
		return fmt.Errorf("apfs: snap-meta: no apsbOID")
	}
	bs := v.physicalBlockSize()
	apsbPaddr, err := v.c.omapLookup(v.c.containerOmap, v.apsbOID, ^uint64(0))
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: lookup APSB: %w", err)
	}
	apsbBlock, err := v.c.readBlock(apsbPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta: read APSB: %w", err)
	}
	if len(apsbBlock) < apfsAPSBNumSnapshotsOffset+4 {
		return fmt.Errorf("apfs: snap-meta: APSB too short")
	}
	cur := int64(binary.LittleEndian.Uint32(apsbBlock[apfsAPSBNumSnapshotsOffset : apfsAPSBNumSnapshotsOffset+4]))
	next := cur + int64(delta)
	if next < 0 {
		next = 0
	}
	binary.LittleEndian.PutUint32(apsbBlock[apfsAPSBNumSnapshotsOffset:apfsAPSBNumSnapshotsOffset+4], uint32(next))
	sealBlock(apsbBlock)
	if _, err := v.c.w.WriteAt(apsbBlock, int64(apsbPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta: write APSB: %w", err)
	}
	return nil
}
