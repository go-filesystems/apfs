package filesystem_apfs

// xattr_stream.go adds a stream-mode xattr writer for payloads too
// large to fit inline in a J_XATTR_VAL. The on-disk shape per
// linux-apfs/apfs_raw.h::j_xattr_dstream:
//
//   J_XATTR_VAL:
//     uint16 flags         = XATTR_DATA_STREAM (0x01)
//     uint16 xdata_len     = 48
//     [j_xattr_dstream, 48 bytes]
//
//   j_xattr_dstream:
//     uint64 xattr_obj_id  (a fresh virtual oid; FS-tree carries
//                          J_FILE_EXTENT keyed under this oid + J_DSTREAM_ID)
//     j_dstream (40 bytes):
//       uint64 size
//       uint64 alloced_size
//       uint64 default_crypto_id
//       uint64 total_bytes_written
//       uint64 total_bytes_read
//
// Plus separately: a J_FILE_EXTENT (oid=xattr_obj_id, logical=0,
// length=alloced_size, paddr=newPaddr) and a J_DSTREAM_ID (oid=xattr_obj_id).

import (
	"encoding/binary"
	"fmt"
)

// SetXAttrStream sets (or replaces) a stream-mode extended attribute
// on the inode at `targetOID`. Use this for large xattr payloads
// (Time Machine's `com.apple.metadata:_kTimeMachineSnapshotMetadata`,
// quarantine attributes for big files, etc.) that don't fit inline
// in a single FS-tree leaf alongside the rest of the inode's records.
// The payload is written to a fresh extent at the volume's next free
// block; the extent + a J_DSTREAM_ID + a J_XATTR record (with the
// stream flag) are inserted into the FS-tree under a fresh
// `xattr_obj_id`.
//
// If a stream xattr with the same name already exists, its old
// payload extent is freed, its extent-ref record is removed, and its
// J_FILE_EXTENT + J_DSTREAM_ID records (under the previous
// xattr_obj_id) are dropped before the new ones are inserted. The
// J_XATTR record itself is replaced via upsert semantics. An
// existing embedded xattr of the same name is rejected — call
// SetXAttr (or delete first) for that case.
func (v *Volume) SetXAttrStream(targetOID uint64, name string, payload []byte) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: SetXAttrStream on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("apfs: SetXAttrStream: empty name")
	}
	if len(payload) == 0 {
		return fmt.Errorf("apfs: SetXAttrStream: empty payload (use SetXAttr instead)")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return err
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// 0. Look up any existing xattr by (targetOID, name). If it's a
	//    stream xattr, schedule its storage for removal (old extent,
	//    extent-ref, J_FILE_EXTENT, J_DSTREAM_ID). The new J_XATTR
	//    under the same key will overwrite the old via upsert.
	var toRemoveKeys [][]byte
	xKeyExisting := encodeXattrKey(targetOID, name)
	if _, oldXVal, lerr := v.lookupFSTreeFirst(xKeyExisting); lerr == nil {
		if len(oldXVal) < 4 {
			return fmt.Errorf("apfs: SetXAttrStream: existing xattr val too short")
		}
		oldFlags := binary.LittleEndian.Uint16(oldXVal[0:2])
		if oldFlags&xattrFlagDataStream == 0 {
			return fmt.Errorf("apfs: SetXAttrStream: %q already exists as an embedded xattr; delete it first", name)
		}
		if len(oldXVal) < 12 {
			return fmt.Errorf("apfs: SetXAttrStream: stream xattr val too short")
		}
		oldXattrObjID := binary.LittleEndian.Uint64(oldXVal[4:12])
		// Find the old J_FILE_EXTENT under oldXattrObjID.
		oldExtKey := encodeFileExtentKey(oldXattrObjID, 0)
		_, oldExtVal, eerr := v.lookupFSTreeFirst(oldExtKey)
		if eerr != nil {
			return fmt.Errorf("apfs: SetXAttrStream: lookup old extent: %w", eerr)
		}
		oldExt, ok := decodeFileExtent(oldExtKey, oldExtVal)
		if !ok {
			return fmt.Errorf("apfs: SetXAttrStream: decode old extent")
		}
		oldBlocks := (oldExt.length + bs - 1) / bs
		if err := v.c.markBlocksFreed(oldExt.physBlock, oldBlocks); err != nil {
			return fmt.Errorf("apfs: SetXAttrStream: free old extent at %d: %w", oldExt.physBlock, err)
		}
		if err := v.removeExtentRefRecord(oldExt.physBlock); err != nil {
			return fmt.Errorf("apfs: SetXAttrStream: remove old extent-ref: %w", err)
		}
		if err := v.bumpFSAllocCount(-int64(oldBlocks)); err != nil {
			return fmt.Errorf("apfs: SetXAttrStream: decrement alloc count: %w", err)
		}
		toRemoveKeys = append(toRemoveKeys, oldExtKey, encodeDStreamIDKey(oldXattrObjID))
	}

	// 1. Allocate xattr_obj_id (virtual; from the container's OID pool).
	xattrObjID := v.c.allocVirtualOID()

	// 2. Allocate + write the payload extent.
	extLen := uint64(len(payload))
	allocSize := ((extLen + bs - 1) / bs) * bs
	if allocSize == 0 {
		allocSize = bs
	}
	extBlocks := allocSize / bs
	firstBlock, err := v.nextFreeBlock()
	if err != nil {
		return err
	}
	if v.allocCursor < firstBlock+extBlocks {
		v.allocCursor = firstBlock + extBlocks
	}
	if _, err := v.c.w.WriteAt(payload, int64(firstBlock*bs)); err != nil {
		return fmt.Errorf("apfs: SetXAttrStream: write payload: %w", err)
	}
	if err := v.c.markBlocksAllocated(firstBlock, extBlocks); err != nil {
		return err
	}
	if err := v.appendExtentRefRecord(firstBlock, extBlocks, xattrObjID); err != nil {
		return err
	}
	if err := v.bumpFSAllocCount(int64(extBlocks)); err != nil {
		return err
	}

	// 3. Build the records:
	//    a) J_FILE_EXTENT under xattr_obj_id at logical=0
	//    b) J_DSTREAM_ID under xattr_obj_id (refcnt=1)
	//    c) J_XATTR under targetOID with the stream-flag value carrying
	//       j_xattr_dstream
	extKey := encodeFileExtentKey(xattrObjID, 0)
	extVal := encodeFileExtentValue(allocSize, firstBlock)
	dstreamIDKey := encodeDStreamIDKey(xattrObjID)
	dstreamIDVal := encodeDStreamIDValue(1)
	xKey := encodeXattrKey(targetOID, name)
	xVal := encodeXattrStreamValue(xattrObjID, extLen, allocSize)
	newRecords := []fsLeafKV{
		{key: extKey, val: extVal},
		{key: dstreamIDKey, val: dstreamIDVal},
		{key: xKey, val: xVal},
	}

	// 4. Insert into the FS-tree (single-leaf or multi-level), removing
	//    any stale old-storage keys collected in step 0.
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		all := filterOutKeys(append([]fsLeafKV(nil), existing...), toRemoveKeys)
		for _, ne := range newRecords {
			all = upsertEntry(all, ne.key, ne.val)
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return err
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return err
			}
			return v.reloadRoot(rootPaddr)
		}
		return v.splitRootLeafAndWrite(all, rootPaddr, leafXID)
	}
	for _, k := range toRemoveKeys {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(k)
		if err != nil {
			return fmt.Errorf("apfs: SetXAttrStream: descend old key: %w", err)
		}
		if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, k); err != nil {
			return fmt.Errorf("apfs: SetXAttrStream: remove old key: %w", err)
		}
	}
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return err
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return err
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return err
		}
	}
	return nil
}

// encodeXattrStreamValue serialises a J_XATTR_VAL carrying a stream
// xattr's dstream descriptor (48 bytes): flags=XATTR_DATA_STREAM,
// xdata_len=48, then j_xattr_dstream{xattr_obj_id, j_dstream}.
func encodeXattrStreamValue(xattrObjID, size, allocSize uint64) []byte {
	const xdataLen = 48
	v := make([]byte, 4+xdataLen)
	binary.LittleEndian.PutUint16(v[0:2], xattrFlagDataStream)
	binary.LittleEndian.PutUint16(v[2:4], xdataLen)
	binary.LittleEndian.PutUint64(v[4:12], xattrObjID)
	// j_dstream (40 bytes):
	binary.LittleEndian.PutUint64(v[12:20], size)        // size
	binary.LittleEndian.PutUint64(v[20:28], allocSize)   // alloced_size
	binary.LittleEndian.PutUint64(v[28:36], 0)           // default_crypto_id
	binary.LittleEndian.PutUint64(v[36:44], size)        // total_bytes_written
	binary.LittleEndian.PutUint64(v[44:52], 0)           // total_bytes_read
	return v
}
