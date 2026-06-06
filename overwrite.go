package filesystem_apfs

// overwrite.go adds writer-side `TruncateFile` and `OverwriteFile`
// operations: changing an existing file's content, with extent
// allocation when the new content exceeds the existing capacity, and
// trailing-block freeing when the new size shrinks the file.
//
// Scope:
//   - Multi-extent files are now supported on both paths. The grow path
//     fills existing extents in logical-offset order then appends one
//     fresh contiguous extent for the tail (matching what Apple's writer
//     does for in-place size_setter calls).
//   - Single-link files (`nlink == 1`). Hardlinked file mutation goes
//     through the same paths but cross-link xattr / dstream sharing
//     would need extra invariants.
//
// References:
//   - linux-apfs/file.c::apfs_setattr (truncate path)
//   - linux-apfs/extents.c::apfs_size_setter (grow path)

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// TruncateFile sets the file at `oid` to exactly `newSize` bytes.
//
// Semantics:
//   - newSize ≥ existing logical size: only the inode's size field is
//     bumped. The file becomes sparse past the existing extents — reads
//     past them return zero. No new extents are allocated.
//   - newSize < existing logical size: the inode's size is reduced AND
//     extents that fall entirely past `newSize` are freed (chunk
//     bitmap, ci_free_count, sm_free_count, extent-ref tree, and
//     apfs_fs_alloc_count are all updated). When `newSize` lands in
//     the middle of an extent, that extent is shrunk to the smallest
//     block-aligned size that still contains `newSize`; the tail
//     blocks of that extent are freed individually.
//
// fsck tolerates the case where the surviving extent's last block
// contains bytes past `newSize`: the documented invariant is
// `alloced_size ≥ size`, not `alloced_size == size`.
func (v *Volume) TruncateFile(oid uint64, newSize uint64) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: TruncateFile on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	inodeKey := encodeInodeKey(oid)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: TruncateFile: lookup inode %d: %w", oid, err)
	}
	if len(inodeVal) < 82 {
		return fmt.Errorf("apfs: TruncateFile: inode val too short")
	}
	mode := binary.LittleEndian.Uint16(inodeVal[80:82])
	if mode&0xF000 != 0x8000 {
		return fmt.Errorf("apfs: TruncateFile: inode %d is not a regular file (mode=0o%o)", oid, mode)
	}
	currentSize, currentAlloced := readInodeDStreamSizes(inodeVal)

	// Grow-or-equal path: the existing capacity already covers newSize,
	// so nothing to free. Just patch size (alloced_size stays the same).
	if newSize >= currentSize {
		return v.updateInodeSizeOnDisk(oid, newSize)
	}

	// Shrink path. Walk the existing extents and decide which to keep,
	// shrink, or drop.
	bs := v.physicalBlockSize()
	extents, err := v.collectFileExtents(oid)
	if err != nil {
		return fmt.Errorf("apfs: TruncateFile: enumerate extents: %w", err)
	}
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].logical < extents[j].logical
	})

	// Smallest block-aligned capacity that still holds `newSize` bytes.
	// newSize == 0 → newCap == 0 → all extents go away.
	newCap := uint64(0)
	if newSize > 0 {
		newCap = ((newSize + bs - 1) / bs) * bs
	}

	freedBlocks, err := v.shrinkFileExtents(oid, extents, newCap, bs)
	if err != nil {
		return err
	}
	if freedBlocks > 0 {
		if err := v.bumpFSAllocCount(-int64(freedBlocks)); err != nil {
			return fmt.Errorf("apfs: TruncateFile: bumpFSAllocCount: %w", err)
		}
	}

	// alloced_size after shrink: keep the existing alloced_size if it
	// still ≥ newCap (the boundary block stays allocated even when
	// `newSize` is mid-block); otherwise step down to newCap.
	newAlloced := currentAlloced
	if newAlloced > currentAlloced-uint64(freedBlocks)*bs {
		newAlloced = currentAlloced - uint64(freedBlocks)*bs
	}
	if newAlloced < newCap {
		newAlloced = newCap
	}
	return v.updateInodeSizeAndAllocedOnDisk(oid, newSize, newAlloced)
}

// OverwriteFile replaces the entire content of the file at `oid` with
// `newData`. The file's logical size becomes `len(newData)`. The file
// must be a regular file with at least one existing extent.
//
// Allocation policy:
//   - newData fits in the existing extents' total capacity: payload is
//     written across them in logical-offset order, the partial tail of
//     the boundary extent is zeroed, and the inode size is updated.
//     No new extents are allocated, no extents are freed.
//   - newData EXCEEDS existing capacity: the head fills the existing
//     extents, then a single fresh contiguous extent is allocated at
//     logical offset = old total capacity for the tail. The new
//     J_FILE_EXTENT is inserted, chunk bitmap + ci_free_count +
//     sm_free_count + extent-ref tree + apfs_fs_alloc_count are all
//     updated, and the inode's J_DSTREAM `alloced_size` is bumped.
//   - newData is smaller than the existing logical size: the inode's
//     size is reduced; trailing extent blocks stay allocated. Use
//     `TruncateFile(oid, len(newData))` afterwards if you also want
//     to free the no-longer-used blocks.
//
// Multi-extent files are supported on both the in-place and the grow
// paths.
func (v *Volume) OverwriteFile(oid uint64, newData []byte) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: OverwriteFile on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: OverwriteFile: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	extents, err := v.collectFileExtents(oid)
	if err != nil {
		return fmt.Errorf("apfs: OverwriteFile: enumerate extents: %w", err)
	}
	if len(extents) == 0 {
		return fmt.Errorf("apfs: OverwriteFile: file %d has no extents", oid)
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].logical < extents[j].logical })

	existingCap := uint64(0)
	for _, e := range extents {
		existingCap += e.length
	}
	newLen := uint64(len(newData))
	newCapNeeded := uint64(0)
	if newLen > 0 {
		newCapNeeded = ((newLen + bs - 1) / bs) * bs
	} else {
		newCapNeeded = bs
	}

	// Path A: existing capacity is sufficient — write across the existing
	// extents in logical order. Works the same for single- and
	// multi-extent files.
	if newCapNeeded <= existingCap {
		written := uint64(0)
		for _, e := range extents {
			if written >= newLen {
				break
			}
			chunk := e.length
			if newLen-written < chunk {
				chunk = newLen - written
			}
			if chunk > 0 {
				if _, err := v.c.w.WriteAt(newData[written:written+chunk],
					int64(e.physBlock*bs)); err != nil {
					return fmt.Errorf("apfs: OverwriteFile: write extent at paddr %d: %w",
						e.physBlock, err)
				}
				// Zero any trailing partial-block bytes inside the
				// boundary extent so stale data from the previous
				// content doesn't leak through reads of the last
				// block.
				if rem := chunk % bs; rem != 0 && written+chunk == newLen {
					zeros := make([]byte, bs-rem)
					tailOff := int64(e.physBlock*bs) + int64(chunk)
					if _, err := v.c.w.WriteAt(zeros, tailOff); err != nil {
						return fmt.Errorf("apfs: OverwriteFile: zero tail: %w", err)
					}
				}
				written += chunk
			}
		}
		return v.updateInodeSizeOnDisk(oid, newLen)
	}

	// Path B: grow. Fill existing extents head-to-tail, then allocate
	// one new contiguous extent for the remaining tail.
	written := uint64(0)
	for _, e := range extents {
		if written >= existingCap || written >= newLen {
			break
		}
		chunk := e.length
		if newLen-written < chunk {
			chunk = newLen - written
		}
		if chunk == 0 {
			continue
		}
		if _, err := v.c.w.WriteAt(newData[written:written+chunk],
			int64(e.physBlock*bs)); err != nil {
			return fmt.Errorf("apfs: OverwriteFile: write head at paddr %d: %w",
				e.physBlock, err)
		}
		written += chunk
	}

	extraCap := newCapNeeded - existingCap
	extraBlocks := extraCap / bs
	newPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: OverwriteFile: nextFreeBlock: %w", err)
	}
	if v.allocCursor < newPaddr+extraBlocks {
		v.allocCursor = newPaddr + extraBlocks
	}
	tail := newData[written:]
	if len(tail) > 0 {
		if _, err := v.c.w.WriteAt(tail, int64(newPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: OverwriteFile: write tail at paddr %d: %w",
				newPaddr, err)
		}
	}
	if err := v.c.markBlocksAllocated(newPaddr, extraBlocks); err != nil {
		return fmt.Errorf("apfs: OverwriteFile: markBlocksAllocated: %w", err)
	}
	if err := v.appendExtentRefRecord(newPaddr, extraBlocks, oid); err != nil {
		return fmt.Errorf("apfs: OverwriteFile: extentref insert: %w", err)
	}
	if err := v.bumpFSAllocCount(int64(extraBlocks)); err != nil {
		return fmt.Errorf("apfs: OverwriteFile: bumpFSAllocCount: %w", err)
	}

	newExtKey := encodeFileExtentKey(oid, existingCap)
	newExtVal := encodeFileExtentValue(extraCap, newPaddr)
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		all := append([]fsLeafKV(nil), existing...)
		all = upsertEntry(all, newExtKey, newExtVal)
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return fmt.Errorf("apfs: OverwriteFile: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return fmt.Errorf("apfs: OverwriteFile: write leaf: %w", err)
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return err
			}
		} else if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return fmt.Errorf("apfs: OverwriteFile: split: %w", err)
		}
	} else {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(newExtKey)
		if err != nil {
			return fmt.Errorf("apfs: OverwriteFile: descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
			[]fsLeafKV{{key: newExtKey, val: newExtVal}}, rootPaddr); err != nil {
			return fmt.Errorf("apfs: OverwriteFile: insert extent: %w", err)
		}
		if !v.rootNode.IsLeaf() {
			if err := v.refreshRoot(rootPaddr); err != nil {
				return fmt.Errorf("apfs: OverwriteFile: refresh root: %w", err)
			}
		}
	}

	if err := v.updateInodeSizeAndAllocedOnDisk(oid, newLen, newCapNeeded); err != nil {
		return fmt.Errorf("apfs: OverwriteFile: update inode size: %w", err)
	}
	return nil
}

// updateInodeSizeAndAllocedOnDisk patches both J_DSTREAM.size (offset
// 0 of the dstream xfield) AND J_DSTREAM.alloced_size (offset 8) +
// J_DSTREAM.total_bytes_written (offset 24) inside the inode value's
// xfields. The leaf is rewritten in place at its current paddr.
func (v *Volume) updateInodeSizeAndAllocedOnDisk(oid, newSize, newAllocedSize uint64) error {
	target := encodeInodeKey(oid)
	paddr, leafBytes, entryIdx, err := v.findFSTreeLeafForKey(target)
	if err != nil {
		return fmt.Errorf("apfs: update inode (%d): locate: %w", oid, err)
	}
	leafNode, err := readBTreeNode(leafBytes)
	if err != nil {
		return err
	}
	r, err := newNodeReader(leafNode, nil)
	if err != nil {
		return err
	}
	_, valStart, valEnd, err := nodeValueRange(r, entryIdx)
	if err != nil {
		return err
	}
	val := leafBytes[valStart:valEnd]
	const inodeBaseLen = 92
	if len(val) < inodeBaseLen+4 {
		return fmt.Errorf("apfs: update inode (%d): val too short", oid)
	}
	xfieldRel, ok := findDStreamSizeOffset(val[inodeBaseLen:])
	if !ok {
		return fmt.Errorf("apfs: update inode (%d): no J_DSTREAM xfield", oid)
	}
	binary.LittleEndian.PutUint64(val[inodeBaseLen+xfieldRel:inodeBaseLen+xfieldRel+8], newSize)
	binary.LittleEndian.PutUint64(val[inodeBaseLen+xfieldRel+8:inodeBaseLen+xfieldRel+16], newAllocedSize)
	binary.LittleEndian.PutUint64(val[inodeBaseLen+xfieldRel+24:inodeBaseLen+xfieldRel+32], newSize)
	touchInodeTimes(val, true /* mod */)
	sealBlock(leafBytes)
	if _, err := v.c.w.WriteAt(leafBytes, int64(paddr*v.physicalBlockSize())); err != nil {
		return fmt.Errorf("apfs: update inode (%d): rewrite leaf at paddr %d: %w", oid, paddr, err)
	}
	return nil
}

// fileExtentInfo is the writer's view of a single J_FILE_EXTENT record.
type fileExtentInfo struct {
	logical    uint64
	length     uint64
	physBlock  uint64
	blockCount uint64
}

// collectFileExtents walks the FS-tree and returns every
// non-sparse J_FILE_EXTENT record belonging to `oid`. Sparse holes
// (phys=0) are skipped because the writer paths in this file only
// touch real allocated extents.
func (v *Volume) collectFileExtents(oid uint64) ([]fileExtentInfo, error) {
	bs := v.physicalBlockSize()
	var out []fileExtentInfo
	err := v.traverseFSTree(func(k, val []byte) error {
		oid2, typ, jerr := jKeyHeader(k)
		if jerr != nil || oid2 != oid || typ != jTypeFileExt {
			return nil
		}
		ext, ok := decodeFileExtent(k, val)
		if !ok {
			return nil
		}
		out = append(out, fileExtentInfo{
			logical:    ext.logicalOffset,
			length:     ext.length,
			physBlock:  ext.physBlock,
			blockCount: (ext.length + bs - 1) / bs,
		})
		return nil
	})
	return out, err
}

// readInodeDStreamSizes pulls J_DSTREAM.size and J_DSTREAM.alloced_size
// out of an inode val. Returns (0, 0) when the inode has no dstream
// xfield (e.g. zero-byte file pre-CreateFile).
func readInodeDStreamSizes(val []byte) (size, alloced uint64) {
	const inodeBaseLen = 92
	if len(val) < inodeBaseLen+4 {
		return 0, 0
	}
	xfieldRel, ok := findDStreamSizeOffset(val[inodeBaseLen:])
	if !ok {
		return 0, 0
	}
	if len(val) < inodeBaseLen+xfieldRel+16 {
		return 0, 0
	}
	size = binary.LittleEndian.Uint64(val[inodeBaseLen+xfieldRel : inodeBaseLen+xfieldRel+8])
	alloced = binary.LittleEndian.Uint64(val[inodeBaseLen+xfieldRel+8 : inodeBaseLen+xfieldRel+16])
	return size, alloced
}

// shrinkFileExtents reconciles the file's J_FILE_EXTENT records and
// extent-ref tree with `newCap` (smallest block-aligned capacity that
// still covers the requested newSize). Extents whose logical offset
// lands past `newCap` are dropped entirely; the boundary extent (if
// it crosses `newCap`) is shrunk in place. Returns the number of
// blocks freed (so the caller can decrement apfs_fs_alloc_count).
//
// Only single-leaf FS-trees and single-leaf extent-ref trees are
// supported in this iteration — same constraint the rest of the
// writer paths inherit from the underlying multi-level helpers.
func (v *Volume) shrinkFileExtents(oid uint64, extents []fileExtentInfo, newCap, bs uint64) (uint64, error) {
	type shrinkAction struct {
		ext       fileExtentInfo
		newLength uint64 // 0 = drop entirely
	}
	var actions []shrinkAction
	freedBlocks := uint64(0)
	for _, e := range extents {
		switch {
		case e.logical >= newCap:
			actions = append(actions, shrinkAction{ext: e, newLength: 0})
			freedBlocks += e.blockCount
		case e.logical+e.length > newCap:
			keepLen := newCap - e.logical
			actions = append(actions, shrinkAction{ext: e, newLength: keepLen})
			oldBlocks := e.blockCount
			newBlocks := (keepLen + bs - 1) / bs
			if oldBlocks > newBlocks {
				freedBlocks += oldBlocks - newBlocks
			}
		default:
			// e.logical+e.length ≤ newCap: keep entirely.
		}
	}
	if len(actions) == 0 {
		return 0, nil
	}

	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, fmt.Errorf("apfs: shrinkExtents: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// Per-action: free the trailing blocks, update or remove the
	// extent-ref record, then update or remove the J_FILE_EXTENT.
	for _, a := range actions {
		switch {
		case a.newLength == 0:
			// Free every block in the extent.
			if err := v.c.markBlocksFreed(a.ext.physBlock, a.ext.blockCount); err != nil {
				return 0, fmt.Errorf("apfs: shrinkExtents: free at %d (%d blk): %w",
					a.ext.physBlock, a.ext.blockCount, err)
			}
			if err := v.removeExtentRefRecord(a.ext.physBlock); err != nil {
				return 0, fmt.Errorf("apfs: shrinkExtents: remove extentref %d: %w",
					a.ext.physBlock, err)
			}
		default:
			oldBlocks := a.ext.blockCount
			newBlocks := (a.newLength + bs - 1) / bs
			if oldBlocks > newBlocks {
				freedAt := a.ext.physBlock + newBlocks
				freedCount := oldBlocks - newBlocks
				if err := v.c.markBlocksFreed(freedAt, freedCount); err != nil {
					return 0, fmt.Errorf("apfs: shrinkExtents: free tail at %d (%d blk): %w",
						freedAt, freedCount, err)
				}
				if err := v.updateExtentRefBlockCount(a.ext.physBlock, newBlocks); err != nil {
					return 0, fmt.Errorf("apfs: shrinkExtents: update extentref %d: %w",
						a.ext.physBlock, err)
				}
			}
		}
	}

	// Now update the FS-tree leaf records: drop or replace each
	// J_FILE_EXTENT entry described by an action. Single-leaf path
	// rewrites the root in place; multi-level path dispatches each
	// key to its containing leaf via `descendToLeafForKey`.
	if !v.rootNode.IsLeaf() {
		for _, a := range actions {
			extKey := encodeFileExtentKey(oid, a.ext.logical)
			leafPaddr, leafOID, _, err := v.descendToLeafForKey(extKey)
			if err != nil {
				return 0, fmt.Errorf("apfs: shrinkExtents: descend: %w", err)
			}
			if a.newLength == 0 {
				if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, extKey); err != nil {
					return 0, fmt.Errorf("apfs: shrinkExtents: remove extent: %w", err)
				}
			} else {
				newVal := encodeFileExtentValue(a.newLength, a.ext.physBlock)
				if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
					[]fsLeafKV{{key: extKey, val: newVal}}, rootPaddr); err != nil {
					return 0, fmt.Errorf("apfs: shrinkExtents: replace extent: %w", err)
				}
			}
		}
		if !v.rootNode.IsLeaf() {
			if err := v.refreshRoot(rootPaddr); err != nil {
				return 0, fmt.Errorf("apfs: shrinkExtents: refresh root: %w", err)
			}
		}
		return freedBlocks, nil
	}
	existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
	if err != nil {
		return 0, err
	}
	out := existing[:0]
	for _, kv := range existing {
		dropped := false
		for _, a := range actions {
			if a.newLength == 0 {
				if bytesEqual(kv.key, encodeFileExtentKey(oid, a.ext.logical)) {
					dropped = true
					break
				}
			} else {
				if bytesEqual(kv.key, encodeFileExtentKey(oid, a.ext.logical)) {
					out = append(out, fsLeafKV{
						key: kv.key,
						val: encodeFileExtentValue(a.newLength, a.ext.physBlock),
					})
					dropped = true
					break
				}
			}
		}
		if !dropped {
			out = append(out, kv)
		}
	}
	newLeaf, err := emitFSTreeLeafExplicit(out, int(bs), v.apsb.rootTreeOID, leafXID)
	if err != nil {
		return 0, fmt.Errorf("apfs: shrinkExtents: re-emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return 0, fmt.Errorf("apfs: shrinkExtents: write leaf: %w", err)
	}
	if err := v.reloadRoot(rootPaddr); err != nil {
		return 0, err
	}
	return freedBlocks, nil
}

// updateExtentRefBlockCount finds the j_phys_ext entry for `physBlock`
// in the extent-ref tree and rewrites its length-and-kind field with
// `newBlockCount` while preserving the kind / refcnt / owning-inode.
// Used by the shrink path when only the trailing blocks of an extent
// are freed.
func (v *Volume) updateExtentRefBlockCount(physBlock, newBlockCount uint64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsb == nil || v.apsb.extentRefOID == 0 {
		return nil
	}
	bs := v.physicalBlockSize()
	rootPaddr := v.apsb.extentRefOID
	rawRoot, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref update: read root: %w", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return err
	}
	if !rootNode.IsLeaf() {
		return v.extentRefModifyLeafMultiLevel(rawRoot, rootNode, physBlock, func(existing []fsLeafKV) ([]fsLeafKV, error) {
			target := encodePhysExtKey(physBlock)
			out := make([]fsLeafKV, 0, len(existing))
			for _, kv := range existing {
				if bytesEqual(kv.key, target) {
					if len(kv.val) < 20 {
						return nil, fmt.Errorf("apfs: extentref update (ml): val too short")
					}
					oldLenAndKind := binary.LittleEndian.Uint64(kv.val[0:8])
					kind := oldLenAndKind &^ ((uint64(1) << 60) - 1)
					newLenAndKind := kind | (newBlockCount & ((uint64(1) << 60) - 1))
					newVal := append([]byte(nil), kv.val...)
					binary.LittleEndian.PutUint64(newVal[0:8], newLenAndKind)
					out = append(out, fsLeafKV{key: kv.key, val: newVal})
				} else {
					out = append(out, kv)
				}
			}
			return out, nil
		})
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return err
	}
	existing, err := readAllLeafEntries(rootNode, rootInfo)
	if err != nil {
		return err
	}
	target := encodePhysExtKey(physBlock)
	updated := false
	out := make([]fsLeafKV, 0, len(existing))
	for _, kv := range existing {
		if bytesEqual(kv.key, target) {
			// j_phys_ext_val: u64 len_and_kind, u64 owning_obj_id, u32 refcnt
			if len(kv.val) < 20 {
				return fmt.Errorf("apfs: extentref update: val too short")
			}
			oldLenAndKind := binary.LittleEndian.Uint64(kv.val[0:8])
			kind := oldLenAndKind &^ ((uint64(1) << 60) - 1)
			newLenAndKind := kind | (newBlockCount & ((uint64(1) << 60) - 1))
			newVal := append([]byte(nil), kv.val...)
			binary.LittleEndian.PutUint64(newVal[0:8], newLenAndKind)
			out = append(out, fsLeafKV{key: kv.key, val: newVal})
			updated = true
		} else {
			out = append(out, kv)
		}
	}
	if !updated {
		return nil // record not found — nothing to update
	}
	newLeaf, err := emitPhysicalBTreeLeafExplicit(out, int(bs), rootPaddr, rootNode.hdr.xid, objTypeBlockRefTree)
	if err != nil {
		return fmt.Errorf("apfs: extentref update: re-emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: extentref update: write leaf: %w", err)
	}
	return nil
}
