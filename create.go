package filesystem_apfs

// create.go is iteration "C-1 + C-2" of the read/write roadmap.
// Together they make a freshly-formatted volume actually populatable:
//
//   C-1  Bump allocator
//        - nextFreeBlock walks every J_FILE_EXTENT in the FS-tree and
//          returns the smallest physical block strictly greater than
//          formatMetadataBlocks AND greater than any extent already in
//          use. Allocations are sequential within a session; callers
//          do not have to free.
//        - nextFreeInodeOID returns max(existing J_INODE_VAL.oid)+1, or
//          a base sentinel when no inodes exist yet.
//
//   C-2  CreateFile (single-leaf FS-tree)
//        - Picks new oid + extents.
//        - Writes the file payload to the freshly-allocated extent.
//        - Inserts J_INODE_VAL, J_FILE_EXTENT, J_DIR_REC into the
//          FS-tree leaf, re-emitting the leaf in canonical APFS sort
//          order.
//        - Refuses when the FS-tree root is not a leaf (multi-level
//          insertion is iteration C-3) or when the rebuilt leaf would
//          overflow a 4 KiB block (leaf-split is iteration C-3).
//
// What is intentionally out of scope here:
//   - Multi-block files (we round up to the next block boundary; for
//     payloads larger than one block, only the first block is
//     allocated and the remainder of the file is sparse).
//   - Leaf splits and internal-node mutations.
//   - Modification timestamps, J_DIR_STATS, J_INODE_FLAGS, xattrs, etc.
//   - Checkpoint cascade and crash safety.

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// CreateFile inserts a regular file under parentOID with the given name
// and content. Returns the new inode's object id on success.
//
// Preconditions: the FS-tree root must currently be a single leaf node
// (true immediately after FormatContainer and for small populated
// volumes), and the parent oid must reference an existing directory
// (or be 1, the synthetic root). The container must be opened with
// write capability (OpenContainerRW).
func (v *Volume) CreateFile(parentOID uint64, name string, data []byte) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateFile on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateFile: empty name")
	}

	bs := v.physicalBlockSize()
	// Round payload up to a whole block — the only allocation strategy
	// in this iteration. extLen is the on-disk extent length the new
	// J_FILE_EXTENT will declare (in bytes).
	extLen := alignUpU64(uint64(len(data)), bs)
	if extLen == 0 {
		extLen = bs
	}
	extBlocks := extLen / bs

	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateFile: resolve FS-tree root: %w", err)
	}

	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}
	firstBlock, err := v.nextFreeBlock()
	if err != nil {
		return 0, err
	}
	// Reserve the next extBlocks contiguous blocks for the file.
	if v.allocCursor < firstBlock+extBlocks {
		v.allocCursor = firstBlock + extBlocks
	}

	// Write payload data into the allocated extent. Trailing bytes
	// inside the last block stay zero (the underlying file is already
	// truncated to the container size by FormatContainer).
	if len(data) > 0 {
		if _, err := v.c.w.WriteAt(data, int64(firstBlock*bs)); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: write payload to phys %d: %w", firstBlock, err)
		}
	}
	// Record the allocation in the spaceman's chunk bitmap + free count.
	// Without this fsck reports `underallocation detected` for every
	// extent we wrote, because our FS-tree references blocks the bitmap
	// still considers free. The mutation is purely bookkeeping: the
	// kext mounts and reads correctly even without it (verified by
	// the N-5 probe), but fsck wants it for cross-check consistency.
	if err := v.c.markBlocksAllocated(firstBlock, extBlocks); err != nil {
		return 0, fmt.Errorf("apfs: CreateFile: record allocation: %w", err)
	}
	// Record the extent in the volume's extent-ref tree (PHYSICAL B-tree
	// of subtype BLOCKREFTREE). fsck_apfs cross-checks every J_FILE_EXTENT
	// against this tree and reports
	//   error: missing/invalid physical extent (N + 1) with refcnt 1
	// when an extent isn't tracked. Phase 4c.
	if err := v.appendExtentRefRecord(firstBlock, extBlocks, newOID); err != nil {
		return 0, fmt.Errorf("apfs: CreateFile: extentref: %w", err)
	}
	// Bump apfs_fs_alloc_count to reflect the newly-allocated payload
	// blocks. fsck reports "apfs_fs_alloc_count is not valid" when the
	// counter drifts. Phase 4d.
	if err := v.bumpFSAllocCount(int64(extBlocks)); err != nil {
		return 0, fmt.Errorf("apfs: CreateFile: bumpFSAllocCount: %w", err)
	}

	// Resolve which (parentOID, name) the new file should bind to. With
	// parentOID == APFS_ROOT_DIR_PARENT (1) or APFS_ROOT_DIR_INO_NUM (2),
	// rebind to the canonical root-dir inode oid (2) and ensure the root
	// dir inode itself is present.
	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}

	// Build the records the new file needs (using the rebound parentOID
	// so the inode val and drec key all agree). alloced_size is the
	// block-aligned extent length. A J_DSTREAM_ID record is required for
	// every file with extents — fsck_apfs warns "dstream … does not
	// have an associated dstream id object" otherwise.
	inodeVal := encodeInodeValue(newOID, parentOID, uint64(len(data)), extLen, 0o100644)
	extKey := encodeFileExtentKey(newOID, 0)
	extVal := encodeFileExtentValue(extLen, firstBlock)
	drKey := encodeDrecKey(parentOID, name)
	drVal := encodeDrecValue(newOID, drecTypeRegFile)
	dstreamIDKey := encodeDStreamIDKey(newOID)
	dstreamIDVal := encodeDStreamIDValue(1)
	newRecords := []fsLeafKV{
		{key: encodeInodeKey(newOID), val: inodeVal},
		{key: extKey, val: extVal},
		{key: drKey, val: drVal},
		{key: dstreamIDKey, val: dstreamIDVal},
	}

	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	if v.rootNode.IsLeaf() {
		// Single-leaf root: read everything, append the new records,
		// (optionally) bootstrap the canonical root-dir inode/dirstats,
		// and try to fit it back into the same root block. If overflow,
		// split into a 2-level tree.
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return 0, err
		}
		all := make([]fsLeafKV, 0, len(existing)+len(newRecords)+2)
		all = append(all, existing...)
		all = append(all, newRecords...)
		if rebindToRoot {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, parentOID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateFile: patch parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateFile: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return 0, fmt.Errorf("apfs: CreateFile: write leaf at paddr %d: %w", rootPaddr, err)
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return 0, err
			}
			return newOID, nil
		}
		// Split: emit two new leaves, write a fresh internal root in
		// place at rootPaddr.
		if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: split: %w", err)
		}
		return newOID, nil
	}

	// Multi-level (root is internal). Each of the new file's 4 records
	// can sort into a different leaf (drec lives under parentOID; the
	// other three under newOID), so we dispatch them individually:
	// re-descend after each insert because a leaf split rewrites the
	// root index node, invalidating prior descents.
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: insert: %w", err)
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: refresh parent: %w", err)
		}
	}
	// Refresh the root index node's keys + bt_longest/key_count/node_count
	// trailer fields. fsck cross-checks all of these against the live
	// leaf state, and an in-place leaf rewrite (no split) leaves the
	// root stale otherwise.
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateFile: refresh root: %w", err)
		}
	}
	return newOID, nil
}

// symlinkXAttrName is Apple's convention for storing a symlink's target:
// the target path is the embedded payload of an xattr with this name on
// an inode whose mode bits include S_IFLNK. apfs.kext's `readlink(2)`
// implementation goes straight to this xattr and returns its content.
const symlinkXAttrName = "com.apple.fs.symlink"

// drecTypeSymlink is the J_DIR_REC `dir_rec_flags` value for symlinks
// (DT_LNK = S_IFLNK >> 12 = 10). Apple's mount path uses this to
// short-circuit name resolution for symlinks.
const drecTypeSymlink uint16 = 10

// CreateSymlink creates a symbolic-link inode under parentOID with the
// given name. The target path is stored as the embedded payload of a
// `com.apple.fs.symlink` xattr — Apple's documented convention for APFS
// symlinks. Returns the new symlink's inode oid.
//
// Mode is fixed to S_IFLNK | 0o777 (the canonical UNIX symlink mode);
// timestamps come from `time.Now()` and owner/group from
// `os.Geteuid()/Getegid()` to match what `apfs.kext` writes when the
// host user creates a symlink through the mounted volume.
func (v *Volume) CreateSymlink(parentOID uint64, name, target string) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateSymlink on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateSymlink: empty name")
	}
	if target == "" {
		return 0, fmt.Errorf("apfs: CreateSymlink: empty target")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateSymlink: resolve FS-tree root: %w", err)
	}
	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}
	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}

	const symlinkMode = uint16(0o120000) | 0o777 // S_IFLNK = 0o120000
	inodeKey := encodeInodeKey(newOID)
	inodeVal := encodeSymlinkInodeValue(newOID, parentOID, symlinkMode)
	drKey := encodeDrecKey(parentOID, name)
	drVal := encodeDrecValue(newOID, drecTypeSymlink)
	// Symlink target as a NUL-terminated embedded xattr.
	targetBytes := append([]byte(target), 0)
	xKey := encodeXattrKey(newOID, symlinkXAttrName)
	xVal := encodeXattrEmbeddedValue(targetBytes)
	newRecords := []fsLeafKV{
		{key: inodeKey, val: inodeVal},
		{key: xKey, val: xVal},
		{key: drKey, val: drVal},
	}

	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return 0, err
		}
		all := make([]fsLeafKV, 0, len(existing)+len(newRecords)+2)
		all = append(all, existing...)
		for _, ne := range newRecords {
			all = upsertEntry(all, ne.key, ne.val)
		}
		if rebindToRoot {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, parentOID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateSymlink: patch parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateSymlink: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return 0, fmt.Errorf("apfs: CreateSymlink: write leaf: %w", err)
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return 0, err
			}
			return newOID, nil
		}
		if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: split: %w", err)
		}
		return newOID, nil
	}

	// Multi-level: dispatch each new record to its leaf, then refresh
	// parent's nchildren.
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: insert: %w", err)
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: refresh parent: %w", err)
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateSymlink: refresh root: %w", err)
		}
	}
	return newOID, nil
}

// encodeSymlinkInodeValue serialises a J_INODE_VAL for a symbolic link.
// Symlinks have no file content extent and no INO_EXT_TYPE_DSTREAM
// xfield (the target lives in an xattr instead). We still emit an
// xf_blob header (count=0, used_data_len=0) so fsck's xfield parser
// doesn't trip on a missing trailer; this matches what apfs.kext
// writes for kext-created symlinks.
func encodeSymlinkInodeValue(oid, parentID uint64, mode uint16) []byte {
	const baseLen = 92
	const xfHeader = 4
	val := make([]byte, baseLen+xfHeader)
	binary.LittleEndian.PutUint64(val[0:8], parentID)
	binary.LittleEndian.PutUint64(val[8:16], oid) // private_id
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(val[16:24], now)
	binary.LittleEndian.PutUint64(val[24:32], now)
	binary.LittleEndian.PutUint64(val[32:40], now)
	binary.LittleEndian.PutUint64(val[40:48], now)
	binary.LittleEndian.PutUint64(val[48:56], 0x8000) // INODE_HAS_FINDER_INFO
	binary.LittleEndian.PutUint32(val[56:60], 1)      // nlink = 1
	binary.LittleEndian.PutUint32(val[60:64], 6)      // APFS_PROTECTION_CLASS_F
	binary.LittleEndian.PutUint32(val[72:76], uint32(os.Geteuid()))
	binary.LittleEndian.PutUint32(val[76:80], uint32(os.Getegid()))
	binary.LittleEndian.PutUint16(val[80:82], mode)
	// xf_blob header: count=0, used_data_len=0.
	binary.LittleEndian.PutUint16(val[baseLen:baseLen+2], 0)
	binary.LittleEndian.PutUint16(val[baseLen+2:baseLen+4], 0)
	return val
}

// encodeXattrKey serialises a J_XATTR key:
//
//	+0   j_key_t (8 bytes; oid in low 60 bits, type=4 in high 4 bits)
//	+8   uint16 name_len (including the trailing NUL)
//	+10  name bytes (NUL-terminated UTF-8)
//
// fsck_apfs validates `name_len` against the actual byte count of the
// stored name including the NUL.
func encodeXattrKey(oid uint64, name string) []byte {
	rawName := append([]byte(name), 0)
	k := make([]byte, 10+len(rawName))
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeXattr)<<60))
	binary.LittleEndian.PutUint16(k[8:10], uint16(len(rawName)))
	copy(k[10:], rawName)
	return k
}

// encodeXattrEmbeddedValue serialises a J_XATTR value with an inline
// (embedded) payload — the standard case for short xattrs like
// `com.apple.fs.symlink`, `com.apple.metadata:_kMDItemUserTags`, etc.:
//
//	+0   uint16 flags  (XATTR_DATA_EMBEDDED = 0x02)
//	+2   uint16 xdata_len
//	+4   xdata bytes
//
// For larger payloads APFS uses a stream xattr (xattrFlagDataStream)
// pointing at a separate dstream; we don't emit that shape yet.
func encodeXattrEmbeddedValue(payload []byte) []byte {
	v := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(v[0:2], xattrFlagDataEmbedded)
	binary.LittleEndian.PutUint16(v[2:4], uint16(len(payload)))
	copy(v[4:], payload)
	return v
}

// SetXAttr sets (or replaces) an embedded extended attribute on the
// inode at oid. Payload sizes up to a few hundred bytes are typical for
// xattrs like `com.apple.FinderInfo` (32 bytes), `com.apple.metadata:*`
// (a few hundred bytes), and `com.apple.quarantine` (variable). For
// payloads that don't fit in a single FS-tree leaf alongside the rest
// of the inode's records, callers should fall back to a stream xattr;
// that path isn't exposed by this writer yet.
//
// Replace semantics: if a J_XATTR record with the same (oid, name)
// already exists, its value is overwritten. Reads via `ListXAttrs`
// after a Commit see the new payload.
func (v *Volume) SetXAttr(oid uint64, name string, payload []byte) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: SetXAttr on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("apfs: SetXAttr: empty name")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: SetXAttr: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	xKey := encodeXattrKey(oid, name)
	xVal := encodeXattrEmbeddedValue(payload)
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		all := append([]fsLeafKV(nil), existing...)
		all = upsertEntry(all, xKey, xVal)
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return fmt.Errorf("apfs: SetXAttr: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return fmt.Errorf("apfs: SetXAttr: write leaf: %w", err)
			}
			return v.reloadRoot(rootPaddr)
		}
		return v.splitRootLeafAndWrite(all, rootPaddr, leafXID)
	}
	leafPaddr, leafOID, _, err := v.descendToLeafForKey(xKey)
	if err != nil {
		return fmt.Errorf("apfs: SetXAttr: descend: %w", err)
	}
	if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{{key: xKey, val: xVal}}, rootPaddr); err != nil {
		return fmt.Errorf("apfs: SetXAttr: insert: %w", err)
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return fmt.Errorf("apfs: SetXAttr: refresh root: %w", err)
		}
	}
	return nil
}

// encodeSibLinkKey serialises a J_SIBLING_LINK key:
//
//	+0   j_key_t (8 bytes; oid in low 60 bits, type=5 in high 4 bits)
//	+8   uint64 sibling_id  (unique per inode; allocated from
//	                          apsb.apfs_next_obj_id)
//
// Multiple J_SIBLING_LINK records share the same oid (the file's inode
// oid) but differ in sibling_id, one per name the inode is linked under.
func encodeSibLinkKey(oid, siblingID uint64) []byte {
	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeSibLink)<<60))
	binary.LittleEndian.PutUint64(k[8:16], siblingID)
	return k
}

// encodeSibLinkValue serialises a J_SIBLING_LINK value:
//
//	+0   uint64 parent_id   (the directory inode this link lives in)
//	+8   uint16 name_len    (including the trailing NUL)
//	+10  name bytes (NUL-terminated UTF-8)
func encodeSibLinkValue(parentID uint64, name string) []byte {
	rawName := append([]byte(name), 0)
	v := make([]byte, 10+len(rawName))
	binary.LittleEndian.PutUint64(v[0:8], parentID)
	binary.LittleEndian.PutUint16(v[8:10], uint16(len(rawName)))
	copy(v[10:], rawName)
	return v
}

// encodeSibMapKey serialises a J_SIBLING_MAP key:
//
//	+0   j_key_t (8 bytes; sibling_id in low 60 bits, type=12 in high 4 bits)
//
// Note that the SIBLING_MAP key uses the sibling_id (not the file_id)
// in the oid slot — fsck cross-checks the map against every link via
// this back-reference.
func encodeSibMapKey(siblingID uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, siblingID|(uint64(jTypeSibMap)<<60))
	return k
}

// encodeSibMapValue serialises a J_SIBLING_MAP value (just file_id).
func encodeSibMapValue(fileID uint64) []byte {
	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, fileID)
	return v
}

// encodeDrecValueWithSiblingID serialises a J_DIR_REC value carrying an
// INO_EXT_TYPE_SIBLING_ID xfield (type=0x01) — required on every drec
// of a hardlinked file (nlink ≥ 2) so the kext can resolve the alias
// back to its sibling record. The base layout is the same as
// encodeDrecValue (file_id + date_added + flags) followed by an xf_blob
// header + 1 entry + the 8-byte sibling_id.
func encodeDrecValueWithSiblingID(fileID uint64, fileType uint16, siblingID uint64) []byte {
	const baseLen = 18
	const xfHeader = 4
	const xfEntry = 4
	const sibIDLen = 8
	v := make([]byte, baseLen+xfHeader+xfEntry+sibIDLen)
	binary.LittleEndian.PutUint64(v[0:8], fileID)
	binary.LittleEndian.PutUint64(v[8:16], 0) // date_added
	binary.LittleEndian.PutUint16(v[16:18], fileType)
	xf := v[baseLen:]
	binary.LittleEndian.PutUint16(xf[0:2], 1)        // count = 1
	binary.LittleEndian.PutUint16(xf[2:4], sibIDLen) // used_data_len
	xf[4] = 0x01                                      // INO_EXT_TYPE_SIBLING_ID
	xf[5] = 0
	binary.LittleEndian.PutUint16(xf[6:8], sibIDLen) // size = 8
	binary.LittleEndian.PutUint64(xf[xfHeader+xfEntry:xfHeader+xfEntry+8], siblingID)
	return v
}

// CreateHardlink adds a second name (alias) for an existing file at
// targetOID under newParentOID. After the call the file has nlink=2:
// it is reachable both through its original drec (the one CreateFile
// installed) and through the freshly added drec named newName under
// newParentOID. Both names show the same inode number to the kernel
// (`stat` returns the same st_ino), and removing either link decrements
// nlink — the inode persists until nlink reaches 0.
//
// Limits in this iteration:
//   - the target's nlink must be exactly 1 (single-name file). The
//     1→2 transition retroactively creates J_SIBLING_LINK records for
//     both the existing primary drec and the new alias.
//   - both the original drec and the new alias must live in the same
//     leaf so the in-place upsert path stays simple. This is the case
//     when the existing drec's parent is the root dir AND newParentOID
//     is also the root dir, which is the common test workload.
func (v *Volume) CreateHardlink(targetOID, newParentOID uint64, newName string) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: CreateHardlink on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if newName == "" {
		return fmt.Errorf("apfs: CreateHardlink: empty name")
	}
	if newParentOID == apfsRootDirParent {
		newParentOID = apfsRootDirInoNum
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: CreateHardlink: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	// Find the target inode + its existing primary drec.
	inodeKey := encodeInodeKey(targetOID)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: CreateHardlink: lookup target inode %d: %w", targetOID, err)
	}
	if len(inodeVal) < 60 {
		return fmt.Errorf("apfs: CreateHardlink: target inode val too short (%d)", len(inodeVal))
	}
	curNlink := binary.LittleEndian.Uint32(inodeVal[56:60])
	if curNlink == 0 {
		return fmt.Errorf("apfs: CreateHardlink: target inode has nlink=0")
	}

	// drec_type for the new alias: read from any existing drec for this
	// inode (they all share the same drec_type).
	primaryDrecType := drecTypeRegFile

	var newRecords []fsLeafKV
	updatedInodeVal := append([]byte(nil), inodeVal...)
	binary.LittleEndian.PutUint32(updatedInodeVal[56:60], curNlink+1)
	// CreateHardlink is a metadata-change op (nlink changes).
	touchInodeTimes(updatedInodeVal, false /* mod */)
	aliasDrecKey := encodeDrecKey(newParentOID, newName)

	if curNlink == 1 {
		// 1→2 transition: retroactively create J_SIBLING_LINK / J_SIBLING_MAP
		// for the existing primary drec AND the new alias drec. We need
		// the primary drec's (parent, name) to populate its sibling-link
		// record; walk the FS-tree to find it.
		primaryParentID := binary.LittleEndian.Uint64(inodeVal[0:8])
		type drecHit struct {
			key  []byte
			val  []byte
			name string
		}
		var primary drecHit
		if err := v.traverseFSTree(func(k, val []byte) error {
			oid, typ, jerr := jKeyHeader(k)
			if jerr != nil {
				return nil
			}
			if oid != primaryParentID || typ != jTypeDirRec {
				return nil
			}
			if len(val) < 8 {
				return nil
			}
			fileID := binary.LittleEndian.Uint64(val[0:8])
			if fileID != targetOID {
				return nil
			}
			if len(k) >= 13 {
				nameBytes := k[12:]
				if i := bytesIndexByte(nameBytes, 0); i >= 0 {
					nameBytes = nameBytes[:i]
				}
				primary = drecHit{
					key:  append([]byte(nil), k...),
					val:  append([]byte(nil), val...),
					name: string(nameBytes),
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("apfs: CreateHardlink: scan for primary drec: %w", err)
		}
		if primary.key == nil {
			return fmt.Errorf("apfs: CreateHardlink: primary drec for inode %d not found", targetOID)
		}
		if len(primary.val) >= 18 {
			primaryDrecType = binary.LittleEndian.Uint16(primary.val[16:18])
		}
		// Two fresh sibling_ids from apsb.apfs_next_obj_id (per
		// linux-apfs convention they share the inode oid namespace).
		sibIDPrimary, err := v.nextInodeOID()
		if err != nil {
			return err
		}
		sibIDAlias, err := v.nextInodeOID()
		if err != nil {
			return err
		}
		updatedPrimaryDrecVal := encodeDrecValueWithSiblingID(targetOID, primaryDrecType, sibIDPrimary)
		aliasDrecVal := encodeDrecValueWithSiblingID(targetOID, primaryDrecType, sibIDAlias)
		newRecords = []fsLeafKV{
			{key: encodeSibLinkKey(targetOID, sibIDPrimary), val: encodeSibLinkValue(primaryParentID, primary.name)},
			{key: encodeSibMapKey(sibIDPrimary), val: encodeSibMapValue(targetOID)},
			{key: encodeSibLinkKey(targetOID, sibIDAlias), val: encodeSibLinkValue(newParentOID, newName)},
			{key: encodeSibMapKey(sibIDAlias), val: encodeSibMapValue(targetOID)},
			{key: aliasDrecKey, val: aliasDrecVal},
			// Replacement: the existing primary drec gains a sibling_id xfield.
			{key: append([]byte(nil), primary.key...), val: updatedPrimaryDrecVal},
			{key: inodeKey, val: updatedInodeVal},
		}
	} else {
		// nlink ≥ 2: incremental hardlink. The inode already has at
		// least two J_SIBLING_LINK records and every existing drec
		// already carries an INO_EXT_TYPE_SIBLING_ID xfield. We just
		// allocate ONE new sibling_id and emit ONE new J_SIBLING_LINK +
		// J_SIBLING_MAP + J_DIR_REC. Existing primary records are
		// untouched (no retroactive rewrite needed).
		//
		// Read drec_type from any existing drec for this inode by
		// scanning the FS-tree. We just need ONE hit to learn the type.
		_ = v.traverseFSTree(func(k, val []byte) error {
			_, typ, jerr := jKeyHeader(k)
			if jerr != nil || typ != jTypeDirRec || len(val) < 18 {
				return nil
			}
			fileID := binary.LittleEndian.Uint64(val[0:8])
			if fileID != targetOID {
				return nil
			}
			primaryDrecType = binary.LittleEndian.Uint16(val[16:18])
			return nil
		})
		sibIDAlias, err := v.nextInodeOID()
		if err != nil {
			return err
		}
		aliasDrecVal := encodeDrecValueWithSiblingID(targetOID, primaryDrecType, sibIDAlias)
		newRecords = []fsLeafKV{
			{key: encodeSibLinkKey(targetOID, sibIDAlias), val: encodeSibLinkValue(newParentOID, newName)},
			{key: encodeSibMapKey(sibIDAlias), val: encodeSibMapValue(targetOID)},
			{key: aliasDrecKey, val: aliasDrecVal},
			{key: inodeKey, val: updatedInodeVal},
		}
	}

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		all := append([]fsLeafKV(nil), existing...)
		for _, ne := range newRecords {
			all = upsertEntry(all, ne.key, ne.val)
		}
		if newParentOID == apfsRootDirInoNum {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, newParentOID)
			if err != nil {
				return fmt.Errorf("apfs: CreateHardlink: patch new parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return fmt.Errorf("apfs: CreateHardlink: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return fmt.Errorf("apfs: CreateHardlink: write leaf: %w", err)
			}
			return v.reloadRoot(rootPaddr)
		}
		return v.splitRootLeafAndWrite(all, rootPaddr, leafXID)
	}

	// Multi-level: dispatch each record to its leaf, then refresh
	// new parent's nchildren.
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return fmt.Errorf("apfs: CreateHardlink: descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return fmt.Errorf("apfs: CreateHardlink: insert: %w", err)
		}
	}
	if newParentOID == apfsRootDirInoNum {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return fmt.Errorf("apfs: CreateHardlink: refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(newParentOID, leafXID, rootPaddr, false); err != nil {
			return fmt.Errorf("apfs: CreateHardlink: refresh new parent: %w", err)
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return fmt.Errorf("apfs: CreateHardlink: refresh root: %w", err)
		}
	}
	return nil
}

// bytesIndexByte returns the index of the first occurrence of c in b,
// or -1 if absent. Used by CreateHardlink to NUL-terminate drec name
// fields without dragging in the bytes package.
func bytesIndexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// CreateDirectory creates a new directory inode under parentOID with
// the given name and POSIX permission bits. Returns the new directory's
// inode oid. The directory starts empty (nchildren = 0); its parent's
// nchildren is incremented to reflect the new dentry.
//
// parentOID may be APFS_ROOT_DIR_PARENT (1) or APFS_ROOT_DIR_INO_NUM (2)
// to bind the dentry under the canonical root directory; both rebind
// to oid 2.
func (v *Volume) CreateDirectory(parentOID uint64, name string, perm uint16) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateDirectory on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateDirectory: empty name")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateDirectory: resolve FS-tree root: %w", err)
	}
	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}

	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}

	// Directory inode val: mode = S_IFDIR | perm, nchildren starts at 0.
	// We carry an INO_EXT_TYPE_NAME xfield with the dir's name (mkapfs's
	// canonical convention; matches what newfs_apfs and the kext write).
	mode := uint16(0o40000) | (perm & 0o7777)
	dirInodeKey := encodeInodeKey(newOID)
	dirInodeVal := encodeDirInodeValue(newOID, parentOID, mode, name, 0)
	drKey := encodeDrecKey(parentOID, name)
	drVal := encodeDrecValue(newOID, drecTypeDir)
	newRecords := []fsLeafKV{
		{key: dirInodeKey, val: dirInodeVal},
		{key: drKey, val: drVal},
	}

	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return 0, err
		}
		all := make([]fsLeafKV, 0, len(existing)+len(newRecords)+2)
		all = append(all, existing...)
		for _, ne := range newRecords {
			all = upsertEntry(all, ne.key, ne.val)
		}
		if rebindToRoot {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, parentOID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateDirectory: patch parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return 0, fmt.Errorf("apfs: CreateDirectory: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return 0, fmt.Errorf("apfs: CreateDirectory: write leaf: %w", err)
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return 0, err
			}
			return newOID, nil
		}
		if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: split: %w", err)
		}
		return newOID, nil
	}

	// Multi-level tree: dispatch records per leaf, then refresh parent's
	// nchildren by counting drecs and patching the parent inode.
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: insert: %w", err)
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: refresh parent: %w", err)
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return 0, fmt.Errorf("apfs: CreateDirectory: refresh root: %w", err)
		}
	}
	return newOID, nil
}

// patchParentNchildrenInList counts the drec entries with parent=parentOID
// in `entries`, looks up the matching inode entry, and patches its
// nchildren field at offset 56. Used by the single-leaf path of
// CreateFile / CreateDirectory when the parent is a non-root directory
// already present in the same leaf.
func patchParentNchildrenInList(entries []fsLeafKV, parentOID uint64) ([]fsLeafKV, error) {
	nchildren := uint32(0)
	for _, e := range entries {
		oid, typ, err := jKeyHeader(e.key)
		if err != nil {
			continue
		}
		if oid == parentOID && typ == jTypeDirRec {
			nchildren++
		}
	}
	parentKey := encodeInodeKey(parentOID)
	for i, e := range entries {
		if !bytesEqual(e.key, parentKey) {
			continue
		}
		if len(e.val) < 60 {
			return entries, fmt.Errorf("parent inode val too short (%d)", len(e.val))
		}
		patched := append([]byte(nil), e.val...)
		binary.LittleEndian.PutUint32(patched[56:60], nchildren)
		entries[i] = fsLeafKV{key: e.key, val: patched}
		return entries, nil
	}
	return entries, fmt.Errorf("parent inode oid %d not in same leaf", parentOID)
}

// refreshNonRootParentNchildren counts every J_DIR_REC under
// parent=parentOID across the entire FS-tree, then updates the parent's
// inode val (offset 56) to match. For parentOID = APFS_ROOT_DIR_INO_NUM
// (2) the existing root_dir record carries an INO_EXT_TYPE_NAME xfield
// — we re-encode via encodeDirInodeValue when isRootDir is set so the
// xfield stays consistent. For other parents we patch the existing val
// in place, preserving timestamps / mode / xfields.
func (v *Volume) refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr uint64, isRootDir bool) error {
	nchildren := uint32(0)
	if err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return nil
		}
		if oid == parentOID && typ == jTypeDirRec {
			nchildren++
		}
		return nil
	}); err != nil {
		return err
	}
	parentKey := encodeInodeKey(parentOID)
	if isRootDir {
		parentVal := encodeDirInodeValue(apfsRootDirInoNum, apfsRootDirParent, 0o40755, "root", nchildren)
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(parentKey)
		if err != nil {
			return err
		}
		return v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
			[]fsLeafKV{{key: parentKey, val: parentVal}}, rootPaddr)
	}
	// For a non-root parent, fetch the existing val and patch nchildren
	// in place so timestamps and xfields are preserved.
	_, existingVal, err := v.lookupFSTreeFirst(parentKey)
	if err != nil {
		return fmt.Errorf("lookup parent inode oid %d: %w", parentOID, err)
	}
	if len(existingVal) < 60 {
		return fmt.Errorf("parent inode val too short (%d)", len(existingVal))
	}
	patched := append([]byte(nil), existingVal...)
	binary.LittleEndian.PutUint32(patched[56:60], nchildren)
	leafPaddr, leafOID, _, err := v.descendToLeafForKey(parentKey)
	if err != nil {
		return err
	}
	return v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
		[]fsLeafKV{{key: parentKey, val: patched}}, rootPaddr)
}

// reloadRoot re-reads the FS-tree root block from rootPaddr and refreshes
// v.rootNode and v.rootInfo. Used after a write that mutates the root.
func (v *Volume) reloadRoot(rootPaddr uint64) error {
	raw, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return err
	}
	root, err := readBTreeNode(raw)
	if err != nil {
		return err
	}
	info, err := readRootBTreeInfo(raw)
	if err != nil {
		return err
	}
	v.rootNode = root
	v.rootInfo = info
	return nil
}

// alignUpU64 rounds n up to the nearest multiple of align.
func alignUpU64(n, align uint64) uint64 {
	if align == 0 {
		return n
	}
	return ((n + align - 1) / align) * align
}

// nextFreeBlock returns the next physical block address the allocator
// will hand out. It is the maximum of:
//   - formatMetadataBlocks (we never reuse the metadata blocks
//     emitted by *our* FormatContainer)
//   - the in-memory bump cursor (allocations made in this session)
//   - one past the highest J_FILE_EXTENT.physBlock currently in the
//     FS-tree (so we don't clobber any existing file's data)
//   - the first block at-or-above all the above whose corresponding
//     bit in the spaceman's chunk-allocation bitmap is CLEAR (so we
//     don't clobber blocks Apple's metadata or any other allocator
//     has reserved on Apple-produced containers — N-5).
func (v *Volume) nextFreeBlock() (uint64, error) {
	candidate := uint64(formatMetadataBlocks)
	if v.allocCursor > candidate {
		candidate = v.allocCursor
	}
	if !v.scannedHighWater {
		highest := uint64(0)
		if err := v.traverseFSTree(func(k, val []byte) error {
			_, typ, jerr := jKeyHeader(k)
			if jerr != nil || typ != jTypeFileExt {
				return nil
			}
			if ext, ok := decodeFileExtent(k, val); ok {
				end := ext.physBlock + (ext.length+v.physicalBlockSize()-1)/v.physicalBlockSize()
				if end > highest {
					highest = end
				}
			}
			return nil
		}); err != nil {
			return 0, err
		}
		if highest > candidate {
			candidate = highest
		}
		v.scannedHighWater = true
	}
	// Consult the spaceman's chunk-allocation bitmap and bump `candidate`
	// past any block that bitmap reports as already allocated. For
	// containers we formatted ourselves the bitmap marks blocks
	// 0..formatChunkUsedBlocks-1 as used and the rest as free, so this
	// returns `candidate` unchanged. For Apple-produced containers Apple
	// allocates additional blocks (apsb.apfs_omap, volume omap root,
	// fs-tree root, snap-meta tree root, extent-ref tree root, plus any
	// previously-written file payloads) that don't fit our hardcoded
	// formatMetadataBlocks assumption, and the bitmap is the only
	// authoritative source for "actually free".
	if free, ok, err := v.c.firstFreeBlockAtOrAfter(candidate); err != nil {
		return 0, err
	} else if ok {
		candidate = free
	}
	v.allocCursor = candidate
	return candidate, nil
}

// firstFreeBlockAtOrAfter scans the chunk-0 allocation bitmap and
// returns the first block number ≥ start whose bitmap bit is clear
// (meaning the spaceman considers it free), or (0, false) on a fresh
// container that has no spaceman / CIB / bitmap yet (the bitmap path
// is purely opportunistic — callers fall back to bump allocation
// when this returns false).
func (c *Container) firstFreeBlockAtOrAfter(start uint64) (uint64, bool, error) {
	loc, err := c.locateChunkZero()
	if err != nil || loc == nil {
		return 0, false, err
	}
	startInChunk := uint64(0)
	if start > loc.chunkAddr {
		startInChunk = start - loc.chunkAddr
	}
	for i := startInChunk; i < loc.chunkBlocks; i++ {
		byteIdx := i / 8
		if byteIdx >= uint64(len(loc.bitmap)) {
			break
		}
		bit := uint8(1) << (i % 8)
		if loc.bitmap[byteIdx]&bit == 0 {
			return loc.chunkAddr + i, true, nil
		}
	}
	return 0, false, nil
}

// markBlocksAllocated records that the spaceman should treat the
// `count` blocks starting at `block` as allocated (not free). It mutates
// the chunk-0 allocation bitmap in place, decrements `ci_free_count` in
// the corresponding chunk_info, and decrements `sm_dev[0].sm_free_count`
// in the live spaceman block. All three blocks are re-Fletcher-sealed
// where applicable (the bitmap block has no obj header so no cksum)
// and written back. Callers invoke this AFTER successfully allocating
// payload blocks via firstFreeBlockAtOrAfter, so the on-disk free
// state stays consistent with the FS-tree's view.
//
// Returns nil if there's nothing to update (e.g. fresh container with
// no spaceman / CIB / bitmap yet — the format-time bitmap already
// covers our hardcoded metadata range).
func (c *Container) markBlocksAllocated(block, count uint64) error {
	if count == 0 {
		return nil
	}
	loc, err := c.locateChunkZero()
	if err != nil || loc == nil {
		return err
	}
	if block < loc.chunkAddr || block+count > loc.chunkAddr+loc.chunkBlocks {
		// Multi-chunk allocs aren't supported yet; for small containers
		// chunk 0 covers the whole device so this never fires.
		return nil
	}
	// Step 1: mutate the bitmap.
	dirtyBitmap := false
	for i := uint64(0); i < count; i++ {
		idx := block - loc.chunkAddr + i
		byteIdx := idx / 8
		bit := uint8(1) << (idx % 8)
		if loc.bitmap[byteIdx]&bit == 0 {
			loc.bitmap[byteIdx] |= bit
			dirtyBitmap = true
		}
	}
	if dirtyBitmap {
		if _, err := c.w.WriteAt(loc.bitmap, int64(loc.bitmapPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: alloc: write chunk bitmap: %w", err)
		}
	}
	// Step 2: decrement ci_free_count in the CIB.
	if loc.cibBlock != nil {
		freeOff := 40 + 20
		freeCount := binary.LittleEndian.Uint32(loc.cibBlock[freeOff : freeOff+4])
		if uint64(freeCount) >= count {
			freeCount -= uint32(count)
		} else {
			freeCount = 0
		}
		binary.LittleEndian.PutUint32(loc.cibBlock[freeOff:freeOff+4], freeCount)
		sealBlock(loc.cibBlock)
		if _, err := c.w.WriteAt(loc.cibBlock, int64(loc.cibPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: alloc: write CIB: %w", err)
		}
	}
	// Step 3: decrement sm_dev[0].sm_free_count in the live spaceman.
	if loc.smBlock != nil {
		const smDev0FreeCountOff = 0x48
		freeCount := binary.LittleEndian.Uint64(loc.smBlock[smDev0FreeCountOff : smDev0FreeCountOff+8])
		if freeCount >= count {
			freeCount -= count
		} else {
			freeCount = 0
		}
		binary.LittleEndian.PutUint64(loc.smBlock[smDev0FreeCountOff:smDev0FreeCountOff+8], freeCount)
		sealBlock(loc.smBlock)
		if _, err := c.w.WriteAt(loc.smBlock, int64(loc.smPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: alloc: write spaceman: %w", err)
		}
	}
	return nil
}

// chunkZeroLocation captures the block addresses + raw bytes of the
// chunk-0 allocation bookkeeping. Fields ending in `Block` hold the
// block contents; fields ending in `Paddr` hold the on-disk paddr of
// that block (so callers can write mutations back).
type chunkZeroLocation struct {
	smPaddr     uint64
	smBlock     []byte
	cibPaddr    uint64
	cibBlock    []byte
	bitmapPaddr uint64
	bitmap      []byte
	chunkAddr   uint64
	chunkBlocks uint64
}

// locateChunkZero resolves the spaceman → CIB[0] → chunk_info[0] →
// bitmap chain and returns the bytes + paddrs of each block. Returns
// (nil, nil) when the chain isn't fully resolvable (e.g. no spaceman,
// no CIB list, ci_bitmap_addr = 0); callers treat that as "no
// allocator info available".
func (c *Container) locateChunkZero() (*chunkZeroLocation, error) {
	if c.sb == nil || c.sb.spacemanOID == 0 {
		return nil, nil
	}
	// Current spaceman: lookup via current CPM.
	cpmBlock, err := c.readBlock(c.sb.xpDescBase + uint64(c.sb.xpDescIndex))
	if err != nil {
		return nil, fmt.Errorf("apfs: alloc: read CheckpointMap: %w", err)
	}
	entries, err := parseCPMEntries(cpmBlock)
	if err != nil {
		return nil, nil
	}
	var smPaddr uint64
	for _, e := range entries {
		if e.oid == c.sb.spacemanOID {
			smPaddr = e.paddr
			break
		}
	}
	if smPaddr == 0 {
		return nil, nil
	}
	smBlock, err := c.readBlock(smPaddr)
	if err != nil {
		return nil, fmt.Errorf("apfs: alloc: read spaceman: %w", err)
	}
	if len(smBlock) < 0x60 {
		return nil, nil
	}
	addrOffset := binary.LittleEndian.Uint32(smBlock[0x50:0x54])
	if addrOffset == 0 || int(addrOffset)+8 > len(smBlock) {
		return nil, nil
	}
	cibPaddr := binary.LittleEndian.Uint64(smBlock[addrOffset : addrOffset+8])
	if cibPaddr == 0 {
		return nil, nil
	}
	cibBlock, err := c.readBlock(cibPaddr)
	if err != nil {
		return nil, fmt.Errorf("apfs: alloc: read CIB at paddr %d: %w", cibPaddr, err)
	}
	if len(cibBlock) < 40+32 {
		return nil, nil
	}
	chunkAddr := binary.LittleEndian.Uint64(cibBlock[40+8 : 40+16])
	chunkBlocks := uint64(binary.LittleEndian.Uint32(cibBlock[40+16 : 40+20]))
	bitmapPaddr := binary.LittleEndian.Uint64(cibBlock[40+24 : 40+32])
	if bitmapPaddr == 0 || chunkBlocks == 0 {
		return nil, nil
	}
	bitmap, err := c.readBlock(bitmapPaddr)
	if err != nil {
		return nil, fmt.Errorf("apfs: alloc: read chunk bitmap at paddr %d: %w", bitmapPaddr, err)
	}
	return &chunkZeroLocation{
		smPaddr:     smPaddr,
		smBlock:     smBlock,
		cibPaddr:    cibPaddr,
		cibBlock:    cibBlock,
		bitmapPaddr: bitmapPaddr,
		bitmap:      bitmap,
		chunkAddr:   chunkAddr,
		chunkBlocks: chunkBlocks,
	}, nil
}

// nextInodeOID returns one greater than the highest J_INODE_VAL oid in
// the FS-tree, or a default starting value when no inodes exist. New
// oids start at 1000 to leave a clean range below for the synthetic
// "root" oid (1) that our writers use as the directory parent for
// freshly-created files.
func (v *Volume) nextInodeOID() (uint64, error) {
	if v.scannedNextOID {
		v.allocOIDCursor++
		return v.allocOIDCursor, nil
	}
	highest := uint64(999) // so the first allocation is 1000
	if err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil || typ != jTypeInode {
			return nil
		}
		if oid > highest {
			highest = oid
		}
		return nil
	}); err != nil {
		return 0, err
	}
	v.allocOIDCursor = highest + 1
	v.scannedNextOID = true
	return v.allocOIDCursor, nil
}

// fsLeafKV is the (key, value) representation used while rebuilding a
// leaf in-memory before re-emitting its bytes.
type fsLeafKV struct {
	key []byte
	val []byte
}

// readAllLeafEntries collects every (key, value) pair from a single
// leaf node in storage order. The caller may then sort, append, and
// re-emit the result into a fresh block.
func readAllLeafEntries(n *btreeNode, info *btreeInfo) ([]fsLeafKV, error) {
	r, err := newNodeReader(n, info)
	if err != nil {
		return nil, err
	}
	out := make([]fsLeafKV, 0, r.EntryCount())
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return nil, err
		}
		val, err := r.valueAt(i)
		if err != nil {
			return nil, err
		}
		out = append(out, fsLeafKV{
			key: append([]byte(nil), k...),
			val: append([]byte(nil), val...),
		})
	}
	return out, nil
}

// emitFSTreeLeaf packs entries (sorted by compareFSKey) into a fresh
// blockSize-byte leaf node. Returns the encoded block. The leaf is
// always tagged root + leaf since the only caller (CreateFile) operates
// on single-leaf FS-trees.
//
// The FS-tree root is a VIRTUAL object — fsck_apfs requires
// `o_oid == defaultFSTreeRootOID` (the virtual oid the volume OMAP
// resolves), NOT zero. FormatContainer uses defaultFSTreeRootOID;
// callers operating on Apple-produced containers must use the actual
// `apsb.apfs_root_tree_oid` value (which differs — Apple uses 1028,
// our format uses 1027).
func emitFSTreeLeaf(entries []fsLeafKV, blockSize int) ([]byte, error) {
	return emitFSTreeLeafExplicit(entries, blockSize, defaultFSTreeRootOID, defaultFormatXID)
}

// emitFSTreeLeafExplicit is emitFSTreeLeaf parameterized by the FS-tree
// root oid and xid. CreateFile uses this when modifying volumes that
// don't follow our default oid/xid scheme (e.g. Apple-produced).
func emitFSTreeLeafExplicit(entries []fsLeafKV, blockSize int, rootOID, xid uint64) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, rootOID, xid, objTypeBTree, uint32(objTypeFSTree), objStorageVirtual)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	// Match mkapfs's variable-shape leaf layout: pre-allocate enough
	// TOC for the actual records; preallocate at least
	// BTREE_TOC_ENTRY_MAX_UNUSED * sizeof(kvloc) = 64 bytes when empty
	// (so an empty leaf still has space to add records without
	// reshuffling). Then emit free_space, free-list pointers, etc. —
	// fsck_apfs rejects btn_key_free_list.off = 0 as a bogus list head.
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
		// Capacity check: TOC + keys + values + trailer must fit.
		need := dataStart + tocLen + keyOff + len(e.key)
		if need > endOfData-valCur-len(e.val) {
			return nil, fmt.Errorf("apfs: emitFSTreeLeaf: leaf overflow at entry %d", i)
		}
		copy(block[keyArea+keyOff:keyArea+keyOff+len(e.key)], e.key)
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(len(e.key)))
		// Variable-shape (kvloc) convention: val.off is the distance
		// from val_end to the value's START (i.e. cumulative byte
		// count of values stored at-and-before this one going backward
		// from val_end). The parser then computes
		// `start = val_end - val.off, end = start + val.len`. fsck_apfs
		// rejects `val.off = 0` for variable-shape entries with
		// "invalid value (0, len)", so the first entry's off MUST be
		// at least `len(val)`.
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+len(e.val)))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(len(e.val)))
		valCur += len(e.val)
		copy(block[endOfData-valCur:endOfData-valCur+len(e.val)], e.val)
		keyOff += len(e.key)
	}
	// btn_free_space / btn_key_free_list / btn_val_free_list:
	// free_space.off = end of populated keys area, free_space.len = the
	// gap between keys and values; free-list heads are APFS_BTOFF_INVALID
	// to mean "no fragmentation" (fsck rejects 0 as a bogus offset).
	freeLen := uint16(endOfData - (keyArea + keyOff) - valCur)
	binary.LittleEndian.PutUint16(block[off+12:off+14], uint16(keyOff))
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	// btreeInfo trailer: bt_flags + bt_node_size + bt_*_size +
	// bt_longest_key/val + bt_key_count + bt_node_count. Apple's fsck
	// validates bt_longest_key/val against the largest entries actually
	// stored — leaving them zero trips
	// "invalid btn_btree.bt_longest_key (expected N, actual 0)".
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
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagKVNonAligned)
	binary.LittleEndian.PutUint32(bi[4:8], uint32(blockSize))
	// bt_key_size / bt_val_size are 0 for variable-shape trees
	// (the per-entry kvloc carries the size). Apple's mkapfs leaves
	// them zero too.
	binary.LittleEndian.PutUint32(bi[16:20], longestKey)
	binary.LittleEndian.PutUint32(bi[20:24], longestVal)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
	sealBlock(block)
	return block, nil
}

// sortLeafEntries arranges entries in canonical APFS sort order so the
// emitted leaf can be searched by readers (lookupFSTreeFirst,
// FindInode, …) using compareFSKey-based binary search.
func sortLeafEntries(entries []fsLeafKV) {
	// Tiny insertion-sort: leaves we deal with in iteration C-2 hold a
	// handful of records, so O(n²) is fine and keeps the dep graph
	// minimal (no `sort` import).
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0; j-- {
			if compareFSKey(entries[j-1].key, entries[j].key) <= 0 {
				break
			}
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}
}

// encodeInodeKey serialises a J_INODE_VAL key (j_key_t prefix only).
func encodeInodeKey(oid uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, oid|(uint64(jTypeInode)<<60))
	return k
}

// encodeInodeValue serialises a minimal J_INODE_VAL for a regular file
// with a single J_DSTREAM xfield carrying the file size. Apple's
// fsck_apfs requires private_id != 0 (uses the inode's own oid by
// convention) and a non-zero default_protection_class.
func encodeInodeValue(oid, parentID, size, allocedSize uint64, mode uint16) []byte {
	const baseLen = 92
	const xfHeader = 4 // count + used_data_len
	const xfEntry = 4  // type + flags + size
	// J_DSTREAM is 40 bytes per Apple's apfs_dstream_t:
	//   size (8) | alloced_size (8) | default_crypto_id (8) |
	//   total_bytes_written (8) | total_bytes_read (8). fsck_apfs
	//   reports "INO_EXT_TYPE_DSTREAM: invalid extended field size 32,
	//   expected 40" when the trailing total_bytes_read is omitted.
	const dstreamLen = 40
	val := make([]byte, baseLen+xfHeader+xfEntry+dstreamLen)
	binary.LittleEndian.PutUint64(val[0:8], parentID)
	binary.LittleEndian.PutUint64(val[8:16], oid) // private_id = own oid
	// Timestamps (create / mod / change / access) at offsets 16/24/32/40
	// are nanoseconds since the Unix epoch. macOS Finder displays a
	// 1970 date when these are zero — set them to "now" so the file
	// looks freshly created (matching what Apple's writers do).
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(val[16:24], now)
	binary.LittleEndian.PutUint64(val[24:32], now)
	binary.LittleEndian.PutUint64(val[32:40], now)
	binary.LittleEndian.PutUint64(val[40:48], now)
	// internal_flags at offset 48: bit 15 (0x8000) =
	// INODE_HAS_FINDER_INFO. fsck_apfs warns when this is missing.
	binary.LittleEndian.PutUint64(val[48:56], 0x8000)
	// nchildren_or_link at offset 56: for regular files this is the
	// link count, default 1.
	binary.LittleEndian.PutUint32(val[56:60], 1)
	// default_protection_class = APFS_PROTECTION_CLASS_F (6 — no
	// protection, non-persistent key). Matches the wrapped_meta_crypto
	// `persistent_class` we put in the APSB.
	binary.LittleEndian.PutUint32(val[60:64], 6)
	// owner / group at offsets 72 / 76 — match the formatting/calling
	// user's uid/gid so files are owned by the user, not root.
	binary.LittleEndian.PutUint32(val[72:76], uint32(os.Geteuid()))
	binary.LittleEndian.PutUint32(val[76:80], uint32(os.Getegid()))
	binary.LittleEndian.PutUint16(val[80:82], mode)
	xf := val[baseLen:]
	binary.LittleEndian.PutUint16(xf[0:2], 1)         // count = 1
	binary.LittleEndian.PutUint16(xf[2:4], dstreamLen) // used_data_len
	xf[4] = 0x08                                       // INO_EXT_TYPE_DSTREAM
	xf[5] = 0
	binary.LittleEndian.PutUint16(xf[6:8], dstreamLen)
	dst := xf[xfHeader+xfEntry:]
	binary.LittleEndian.PutUint64(dst[0:8], size)        // size (logical)
	binary.LittleEndian.PutUint64(dst[8:16], allocedSize) // alloced_size (block-aligned)
	binary.LittleEndian.PutUint64(dst[16:24], 0)         // default_crypto_id
	binary.LittleEndian.PutUint64(dst[24:32], size)      // total_bytes_written
	binary.LittleEndian.PutUint64(dst[32:40], 0)         // total_bytes_read
	return val
}

// encodeDirInodeValue serialises a J_INODE_VAL for a directory carrying
// an INO_EXT_TYPE_NAME xfield (mkapfs's pattern for the synthetic root
// directory). nchildren is the number of dentries the directory holds;
// fsck_apfs's "directory valence check" rejects nchildren that doesn't
// match the actual J_DIR_REC count for this oid.
func encodeDirInodeValue(oid, parentID uint64, mode uint16, name string, nchildren uint32) []byte {
	const baseLen = 92
	const xfHeader = 4 // xf_blob (count + used_data_len)
	const xfEntry = 4  // x_field (type + flags + size)
	rawName := append([]byte(name), 0)
	paddedNameLen := (len(rawName) + 7) &^ 7
	val := make([]byte, baseLen+xfHeader+xfEntry+paddedNameLen)
	binary.LittleEndian.PutUint64(val[0:8], parentID)
	binary.LittleEndian.PutUint64(val[8:16], oid) // private_id
	// Timestamps (create/mod/change/access) — non-zero so Finder shows
	// a sensible date instead of 1970 for the root + private-dir.
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(val[16:24], now)
	binary.LittleEndian.PutUint64(val[24:32], now)
	binary.LittleEndian.PutUint64(val[32:40], now)
	binary.LittleEndian.PutUint64(val[40:48], now)
	// internal_flags at offset 48: bit 15 (0x8000) =
	// INODE_HAS_FINDER_INFO. fsck_apfs warns "need to set internal_flags
	// 0x8000" for the special directory inodes (root + private-dir)
	// when this bit is missing.
	binary.LittleEndian.PutUint64(val[48:56], 0x8000)
	// nchildren_or_link at offset 56: child count for directories.
	binary.LittleEndian.PutUint32(val[56:60], nchildren)
	// default_protection_class = APFS_PROTECTION_CLASS_DIR_NONE (0)
	// for directory inodes — mkapfs's convention.
	binary.LittleEndian.PutUint32(val[60:64], 0)
	// owner / group at offsets 72 / 76 (apfs_inode_val.owner / .group).
	// mkapfs sets these to geteuid()/getegid(); the alternative (zero)
	// produces a root-owned root-dir under the kext mount, blocking the
	// mounting user from writing. fsck doesn't warn either way, but
	// macOS's `Permission denied` on a mounted volume is a kernel-level
	// check against the on-disk values.
	binary.LittleEndian.PutUint32(val[72:76], uint32(os.Geteuid()))
	binary.LittleEndian.PutUint32(val[76:80], uint32(os.Getegid()))
	binary.LittleEndian.PutUint16(val[80:82], mode)
	// One xfield: INO_EXT_TYPE_NAME (4) carrying the directory name.
	xf := val[baseLen:]
	binary.LittleEndian.PutUint16(xf[0:2], 1) // count = 1
	binary.LittleEndian.PutUint16(xf[2:4], uint16(paddedNameLen))
	xf[4] = 0x04 // INO_EXT_TYPE_NAME
	xf[5] = 0x02 // APFS_XF_DO_NOT_COPY
	binary.LittleEndian.PutUint16(xf[6:8], uint16(len(rawName)))
	copy(xf[xfHeader+xfEntry:], rawName)
	return val
}

// encodeFileExtentKey serialises a J_FILE_EXTENT key (j_key_t + uint64
// logical offset).
func encodeFileExtentKey(oid, logical uint64) []byte {
	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k[0:8], oid|(uint64(jTypeFileExt)<<60))
	binary.LittleEndian.PutUint64(k[8:16], logical)
	return k
}

// encodeFileExtentValue serialises a J_FILE_EXTENT value (length |
// flags packed in the low 56 bits, phys_block_num, crypto_id=0).
func encodeFileExtentValue(length, physBlock uint64) []byte {
	v := make([]byte, 24)
	binary.LittleEndian.PutUint64(v[0:8], length&((uint64(1)<<56)-1))
	binary.LittleEndian.PutUint64(v[8:16], physBlock)
	binary.LittleEndian.PutUint64(v[16:24], 0)
	return v
}

// encodeDStreamIDKey serialises a J_DSTREAM_ID key (j_key_t with type=6
// and the file's oid). Apple's fsck_apfs requires a J_DSTREAM_ID
// record to accompany every dstream-bearing inode; "dstream … does not
// have an associated dstream id object" otherwise.
func encodeDStreamIDKey(oid uint64) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint64(k, oid|(uint64(jTypeDStreamID)<<60))
	return k
}

// encodeDStreamIDValue serialises a J_DSTREAM_ID value (uint32 refcnt).
// For a freshly-created file with one extent and one inode, refcnt = 1.
func encodeDStreamIDValue(refcnt uint32) []byte {
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, refcnt)
	return v
}

// encodeDrecKey serialises a J_DIR_REC key in the hashed shape Apple
// uses for case-insensitive volumes (apfs_drec_hashed_key_t):
//
//	+0   j_key_t (8 bytes; oid in low 60 bits, type=9 in high 4 bits)
//	+8   uint32 LE name_len_and_hash:
//	     - low 10 bits  = name_len (including the trailing NUL)
//	     - high 22 bits = name hash (CRC-32C over each char as a
//	                                  zero-padded UTF-32 codepoint)
//	+12  NUL-terminated name bytes
//
// fsck_apfs's `btn: invalid key order: index N is greater than index N+1`
// fires when drec keys are encoded with the simpler unhashed shape
// (apfs_drec_key_t — uint16 name_len) on a volume that advertises
// `apfs_incompatible_features & APFS_INCOMPAT_CASE_INSENSITIVE`. We
// always emit the hashed shape because our APSB sets that bit; the
// parser handles both shapes uniformly via the low-10-bits-of-uint32
// length field (which equals the uint16 length for short names).
func encodeDrecKey(parentOID uint64, name string) []byte {
	tail := append([]byte(name), 0)
	k := make([]byte, 12+len(tail))
	binary.LittleEndian.PutUint64(k[0:8], parentOID|(uint64(jTypeDirRec)<<60))
	hash := drecNameHash(name)
	nameLenAndHash := uint32(len(tail)) | (hash << 10)
	binary.LittleEndian.PutUint32(k[8:12], nameLenAndHash)
	copy(k[12:], tail)
	return k
}

// drecNameHash computes mkapfs's CRC-32C hash of the directory name as
// used by `apfs_drec_hashed_key.name_len_and_hash`'s upper 22 bits.
// Each character is processed as a zero-padded UTF-32 little-endian
// codepoint; the trailing NUL is NOT included in the hash. The result
// is masked to 22 bits.
//
// Case folding: our APSB sets APFS_INCOMPAT_CASE_INSENSITIVE, which
// means apfs.kext + fsck both hash the LOWERCASED form of the name
// (so "fileA.txt" and "filea.txt" produce the same hash and resolve
// to the same drec). For ASCII this is a simple A-Z → a-z fold; full
// Unicode case folding via Apple's `apfs_strncasecmp` table would be
// needed for non-ASCII names but ASCII covers our writer's workload.
//
// fsck rejects a mismatched hash with `directory record (id N):
// invalid hash (X, expected Y) of name (foo)`.
func drecNameHash(name string) uint32 {
	hash := uint32(0xFFFFFFFF)
	var buf [4]byte
	for _, r := range name {
		if r == 0 {
			break
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		// Encode `r` as a zero-padded UTF-32 LE codepoint (the bytes
		// mkapfs feeds to crc32c).
		binary.LittleEndian.PutUint32(buf[:], uint32(r))
		hash = crc32cUpdate(hash, buf[:])
	}
	return hash & 0x3FFFFF
}

// crc32cUpdate processes `buf` through the CRC-32C (Castagnoli) check
// starting from `crc`. Mirrors mkapfs's `lib/checksum.c::crc32c`.
//
// We hand-roll the table here rather than depending on hash/crc32 with
// crc32.MakeTable(crc32.Castagnoli) just to keep the apfs package
// dependency footprint minimal — the table is small and the inner loop
// is trivial.
func crc32cUpdate(crc uint32, buf []byte) uint32 {
	for _, b := range buf {
		crc = crc32cTable[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// crc32cTable is the CRC-32C lookup table as used by mkapfs (and
// matching Castagnoli's polynomial 0x1EDC6F41 reflected). Generated
// from the same source as `lib/checksum.c`.
var crc32cTable = func() [256]uint32 {
	var t [256]uint32
	const poly = uint32(0x82F63B78) // CRC-32C reflected
	for i := uint32(0); i < 256; i++ {
		c := i
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = (c >> 1) ^ poly
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// APFS reserved oids used by the FS-tree bootstrap helpers.
const (
	apfsRootDirParent uint64 = 1 // APFS_ROOT_DIR_PARENT
	apfsRootDirInoNum uint64 = 2 // APFS_ROOT_DIR_INO_NUM
	apfsPrivDirInoNum uint64 = 3 // APFS_PRIV_DIR_INO_NUM
)

// drec_val flags = file type bits (S_IFMT >> 12). Apple's fsck_apfs
// reads this to confirm the directory record's listed type matches
// the inode's mode. mkapfs sets it to S_IFDIR>>12 (4) for directories.
const (
	drecTypeRegFile uint16 = 8 // S_IFREG >> 12
	drecTypeDir     uint16 = 4 // S_IFDIR >> 12
)

// encodeDrecValue serialises a J_DIR_REC value (file_id, date_added=0,
// flags packed with the file type in the low 4 bits per APFS's spec).
func encodeDrecValue(fileID uint64, fileType uint16) []byte {
	v := make([]byte, 18)
	binary.LittleEndian.PutUint64(v[0:8], fileID)
	binary.LittleEndian.PutUint64(v[8:16], 0)
	binary.LittleEndian.PutUint16(v[16:18], fileType)
	return v
}

// upsertRootDir installs (or replaces) the synthetic top-level directory
// records that every APFS volume must contain:
//
//   - J_INODE(oid=2)  + J_DIR_REC(parent=1, name="root")        — the user-visible root
//   - J_INODE(oid=3)  + J_DIR_REC(parent=1, name="private-dir") — the reserved private dir
//
// Apple's apfs.kext walks the FS-tree at mount looking up both special
// directories under the synthetic parent oid 1 (APFS_ROOT_DIR_PARENT).
// Without the private-dir entry the kext returns ENOENT
// (`mount_apfs: volume could not be mounted: No such file or directory`)
// even though fsck accepts the tree. mkapfs's `make_cat_root` mirrors this
// shape exactly: four records (two dentries + two inodes) at format time.
//
// `entries` is the full FS-tree leaf contents being assembled.
func upsertRootDir(entries []fsLeafKV) []fsLeafKV {
	// Count J_DIR_REC entries whose key oid (= parent) is the root dir,
	// for the root inode's nchildren field.
	var nchildren uint32
	for _, e := range entries {
		if len(e.key) < 8 {
			continue
		}
		oidWithType := binary.LittleEndian.Uint64(e.key[:8])
		oid := oidWithType & 0x0FFFFFFFFFFFFFFF
		typ := uint8(oidWithType >> 60)
		if oid == apfsRootDirInoNum && typ == jTypeDirRec {
			nchildren++
		}
	}
	// 1. The root directory's inode.
	rootInodeKey := encodeInodeKey(apfsRootDirInoNum)
	rootInodeVal := encodeDirInodeValue(apfsRootDirInoNum, apfsRootDirParent, 0o40755, "root", nchildren)
	entries = upsertEntry(entries, rootInodeKey, rootInodeVal)
	// 2. The dentry from the synthetic parent (oid=1) → root.
	rootDrecKey := encodeDrecKey(apfsRootDirParent, "root")
	rootDrecVal := encodeDrecValue(apfsRootDirInoNum, drecTypeDir)
	entries = upsertEntry(entries, rootDrecKey, rootDrecVal)
	// 3. The private-dir inode (always empty: nchildren = 0).
	privInodeKey := encodeInodeKey(apfsPrivDirInoNum)
	privInodeVal := encodeDirInodeValue(apfsPrivDirInoNum, apfsRootDirParent, 0o40755, "private-dir", 0)
	entries = upsertEntry(entries, privInodeKey, privInodeVal)
	// 4. The dentry from the synthetic parent (oid=1) → private-dir.
	privDrecKey := encodeDrecKey(apfsRootDirParent, "private-dir")
	privDrecVal := encodeDrecValue(apfsPrivDirInoNum, drecTypeDir)
	entries = upsertEntry(entries, privDrecKey, privDrecVal)
	return entries
}

// upsertEntry replaces the entry whose key equals `key` (byte-for-byte)
// or appends a new (key, val) pair when no matching entry exists.
// Used by upsertRootDir to keep idempotency on repeated CreateFile
// calls within the same volume.
func upsertEntry(entries []fsLeafKV, key, val []byte) []fsLeafKV {
	for i, e := range entries {
		if bytesEqual(e.key, key) {
			entries[i] = fsLeafKV{key: key, val: val}
			return entries
		}
	}
	return append(entries, fsLeafKV{key: key, val: val})
}

// bytesEqual compares two byte slices for equality without dragging in
// the bytes package.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
