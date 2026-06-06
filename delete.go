package filesystem_apfs

// delete.go implements `Volume.DeleteFile` — the inverse of CreateFile.
// Removes a regular file's records from the FS-tree, frees its data
// extents (chunk bitmap + free-count counters), removes its entry from
// the extent-ref tree, and decrements the parent directory's nchildren
// + the APSB's apfs_num_files / apfs_fs_alloc_count counters.
//
// Scope:
//   - `nlink == 1`: full deletion (records, extents, counters).
//   - `nlink >  1`: per-name unlink — drops the drec for this name,
//     plus the matching J_SIBLING_LINK + J_SIBLING_MAP records, and
//     decrements the inode's nlink. The inode, its data extents, its
//     xattrs, and the extent-ref records all stay intact because the
//     other names still reference them.
//   - No xattrs on the file, OR all xattrs are EMBEDDED (we drop them
//     along with the inode — STREAM xattrs would need their backing
//     dstream freed separately).
//   - Single-extent files (the only shape CreateFile produces today).
//
// Reference: linux-apfs/dir.c::apfs_unlink for the canonical sequence.

import (
	"encoding/binary"
	"fmt"
)

// DeleteFile removes the file at (parentOID, name) from the volume.
// For nlink==1 files: all four (inode, drec, file_extent, dstream_id)
// records are removed; the file's extent blocks are freed; the
// parent's nchildren is decremented; APSB counters
// (apfs_num_files, apfs_fs_alloc_count) are updated.
// For nlink>1 files: only this name's drec + its matching
// J_SIBLING_LINK + J_SIBLING_MAP records are dropped, and the
// inode's nlink is decremented in place. The inode, its extents,
// xattrs and dstream_id stay because the other names still
// reference them.
func (v *Volume) DeleteFile(parentOID uint64, name string) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.deleteFileLocked(parentOID, name)
}

// deleteFileLocked is the lock-free body of DeleteFile. Callers MUST
// already hold v.c.mu (write lock). Used by DeleteFile (which locks
// then calls this) AND by Rename's overwrite path (which already
// holds the lock for the whole rename operation).
func (v *Volume) deleteFileLocked(parentOID uint64, name string) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: DeleteFile on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("apfs: DeleteFile: empty name")
	}
	if parentOID == apfsRootDirParent {
		parentOID = apfsRootDirInoNum
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// 1. Look up the drec under (parentOID, name) to learn the file's oid.
	drecKey := encodeDrecKey(parentOID, name)
	_, drecVal, err := v.lookupFSTreeFirst(drecKey)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile: drec %q under parent %d: %w", name, parentOID, err)
	}
	if len(drecVal) < 8 {
		return fmt.Errorf("apfs: DeleteFile: drec val too short")
	}
	fileOID := binary.LittleEndian.Uint64(drecVal[0:8])

	// 2. Look up the inode and verify nlink == 1 (the only case we
	//    support in this iteration).
	inodeKey := encodeInodeKey(fileOID)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile: lookup inode %d: %w", fileOID, err)
	}
	if len(inodeVal) < 60 {
		return fmt.Errorf("apfs: DeleteFile: inode val too short")
	}
	nlink := binary.LittleEndian.Uint32(inodeVal[56:60])
	mode := binary.LittleEndian.Uint16(inodeVal[80:82])
	if mode&0xF000 != 0x8000 {
		return fmt.Errorf("apfs: DeleteFile: inode %d is not a regular file (mode=0o%o)", fileOID, mode)
	}
	if nlink > 1 {
		return v.deleteHardlinkAlias(parentOID, name, fileOID, drecKey)
	}

	// 3. Walk the FS-tree to enumerate every record belonging to this
	//    file (file_extent, xattr, dstream_id, ...). We collect them by
	//    key so each can be removed individually below.
	type extentInfo struct {
		physBlock  uint64
		blockCount uint64
	}
	var extents []extentInfo
	type recordToRemove struct {
		key []byte
	}
	var toRemove []recordToRemove
	if err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return nil
		}
		if oid != fileOID {
			return nil
		}
		switch typ {
		case jTypeInode, jTypeFileExt, jTypeDStreamID, jTypeXattr:
			toRemove = append(toRemove, recordToRemove{key: append([]byte(nil), k...)})
		}
		if typ == jTypeFileExt {
			if ext, ok := decodeFileExtent(k, val); ok {
				blocks := (ext.length + bs - 1) / bs
				extents = append(extents, extentInfo{physBlock: ext.physBlock, blockCount: blocks})
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apfs: DeleteFile: enumerate records: %w", err)
	}
	// Add the drec key (keyed under parentOID, not fileOID).
	toRemove = append(toRemove, recordToRemove{key: append([]byte(nil), drecKey...)})

	// 4. Free each extent's blocks: clear chunk bitmap, increment
	//    ci_free_count + sm_free_count. Also remove from extent-ref tree.
	totalFreedBlocks := uint64(0)
	for _, ext := range extents {
		if err := v.c.markBlocksFreed(ext.physBlock, ext.blockCount); err != nil {
			return fmt.Errorf("apfs: DeleteFile: free extent at %d (%d blocks): %w",
				ext.physBlock, ext.blockCount, err)
		}
		if err := v.removeExtentRefRecord(ext.physBlock); err != nil {
			return fmt.Errorf("apfs: DeleteFile: remove extentref for %d: %w", ext.physBlock, err)
		}
		totalFreedBlocks += ext.blockCount
	}

	// 5. Remove all the file's records from the FS-tree. Dispatch each
	//    key to its containing leaf (multi-level safe) and rewrite that
	//    leaf without the matching entry.
	keysOnly := make([][]byte, 0, len(toRemove))
	for _, r := range toRemove {
		keysOnly = append(keysOnly, r.key)
	}
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		filtered := filterOutKeys(existing, keysOnly)
		// Decrement parent's nchildren by 1 for the removed drec (only
		// matters when parent != root because upsertRootDir handles the
		// root specially).
		if parentOID == apfsRootDirInoNum {
			filtered = upsertRootDir(filtered)
		} else {
			var perr error
			filtered, perr = patchParentNchildrenInList(filtered, parentOID)
			if perr != nil {
				return fmt.Errorf("apfs: DeleteFile: patch parent: %w", perr)
			}
		}
		newLeaf, err := emitFSTreeLeafExplicit(filtered, int(bs), v.apsb.rootTreeOID, leafXID)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile: re-emit leaf: %w", err)
		}
		if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: DeleteFile: write leaf: %w", err)
		}
		if err := v.reloadRoot(rootPaddr); err != nil {
			return err
		}
	} else {
		// Multi-level: descend per key, rewrite each affected leaf.
		for _, k := range keysOnly {
			leafPaddr, leafOID, _, err := v.descendToLeafForKey(k)
			if err != nil {
				return fmt.Errorf("apfs: DeleteFile: descend: %w", err)
			}
			if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, k); err != nil {
				return fmt.Errorf("apfs: DeleteFile: remove key from leaf: %w", err)
			}
		}
		// Refresh parent's nchildren via the same per-tree counting we
		// use during creation (ensures correctness after the deletion).
		if parentOID == apfsRootDirInoNum {
			if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
				return fmt.Errorf("apfs: DeleteFile: refresh root inode: %w", err)
			}
		} else {
			if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
				return fmt.Errorf("apfs: DeleteFile: refresh parent: %w", err)
			}
		}
		if !v.rootNode.IsLeaf() {
			if err := v.refreshRoot(rootPaddr); err != nil {
				return fmt.Errorf("apfs: DeleteFile: refresh root: %w", err)
			}
		}
	}

	// 6. Decrement APSB counters: apfs_num_files (-1) and
	//    apfs_fs_alloc_count (- totalFreedBlocks). bumpFSAllocCount
	//    accepts a signed delta; bumpAPSBNumFiles is a small new helper.
	if err := v.bumpFSAllocCount(-int64(totalFreedBlocks)); err != nil {
		return fmt.Errorf("apfs: DeleteFile: decrement fs_alloc_count: %w", err)
	}
	if err := v.bumpAPSBNumFiles(-1); err != nil {
		return fmt.Errorf("apfs: DeleteFile: decrement num_files: %w", err)
	}
	return nil
}

// deleteHardlinkAlias drops one alias of a hardlinked inode: the drec
// for (parentOID, name), the matching J_SIBLING_LINK + J_SIBLING_MAP
// records, and a -1 patch to the inode's nlink. The inode, its data
// extents, extent-ref records, xattrs and dstream_id stay intact
// because the inode's other aliases still reference them.
//
// When the post-delete nlink falls to 1 (the file becomes a plain
// non-hardlinked file again), the surviving alias's residual
// J_SIBLING_LINK / J_SIBLING_MAP records and its drec's
// INO_EXT_TYPE_SIBLING_ID xfield are stripped — `fsck_apfs` strict
// mode flags these as orphans on a non-hardlinked inode.
func (v *Volume) deleteHardlinkAlias(parentOID uint64, name string, fileOID uint64, drecKey []byte) error {
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile (alias): resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// 1. Find the J_SIBLING_LINK record matching (parentOID, name).
	siblingID, err := v.findSiblingID(fileOID, parentOID, name)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile (alias): %w", err)
	}

	// 2. Re-read the inode to compute the updated value (nlink - 1).
	inodeKey := encodeInodeKey(fileOID)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: DeleteFile (alias): re-lookup inode %d: %w", fileOID, err)
	}
	if len(inodeVal) < 60 {
		return fmt.Errorf("apfs: DeleteFile (alias): inode val too short")
	}
	updatedInodeVal := append([]byte(nil), inodeVal...)
	curNlink := binary.LittleEndian.Uint32(inodeVal[56:60])
	binary.LittleEndian.PutUint32(updatedInodeVal[56:60], curNlink-1)
	touchInodeTimes(updatedInodeVal, false /* mod */)

	sibLinkKey := encodeSibLinkKey(fileOID, siblingID)
	sibMapKey := encodeSibMapKey(siblingID)
	toRemove := [][]byte{
		append([]byte(nil), drecKey...),
		sibLinkKey,
		sibMapKey,
	}

	// Strict cleanup: when nlink falls to 1 the inode reverts to a
	// plain non-hardlinked file. Strip the surviving alias's residual
	// sibling records and the SIBLING_ID xfield on its drec.
	var survivorUpserts []fsLeafKV
	if curNlink == 2 {
		survivor, err := v.findSurvivingSibling(fileOID, siblingID)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): find survivor: %w", err)
		}
		toRemove = append(toRemove,
			encodeSibLinkKey(fileOID, survivor.siblingID),
			encodeSibMapKey(survivor.siblingID),
		)
		survivorDrecKey := encodeDrecKey(survivor.parentOID, survivor.name)
		_, survivorDrecVal, err := v.lookupFSTreeFirst(survivorDrecKey)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): lookup survivor drec: %w", err)
		}
		if len(survivorDrecVal) < 18 {
			return fmt.Errorf("apfs: DeleteFile (alias): survivor drec val too short")
		}
		fileType := binary.LittleEndian.Uint16(survivorDrecVal[16:18])
		survivorUpserts = append(survivorUpserts, fsLeafKV{
			key: survivorDrecKey,
			val: encodeDrecValue(fileOID, fileType),
		})
	}

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		filtered := filterOutKeys(existing, toRemove)
		filtered = upsertEntry(filtered, inodeKey, updatedInodeVal)
		for _, su := range survivorUpserts {
			filtered = upsertEntry(filtered, su.key, su.val)
		}
		// Decrement parent's nchildren by 1 (one alias gone).
		if parentOID == apfsRootDirInoNum {
			filtered = upsertRootDir(filtered)
		} else {
			var perr error
			filtered, perr = patchParentNchildrenInList(filtered, parentOID)
			if perr != nil {
				return fmt.Errorf("apfs: DeleteFile (alias): patch parent: %w", perr)
			}
		}
		newLeaf, err := emitFSTreeLeafExplicit(filtered, int(bs), v.apsb.rootTreeOID, leafXID)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): re-emit leaf: %w", err)
		}
		if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): write leaf: %w", err)
		}
		return v.reloadRoot(rootPaddr)
	}

	// Multi-level dispatch: per-key descend + leaf rewrite.
	for _, k := range toRemove {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(k)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): descend: %w", err)
		}
		if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, k); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): remove key: %w", err)
		}
	}
	// Update the inode val in place.
	if leafPaddr, leafOID, _, err := v.descendToLeafForKey(inodeKey); err != nil {
		return fmt.Errorf("apfs: DeleteFile (alias): descend inode: %w", err)
	} else if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
		[]fsLeafKV{{key: inodeKey, val: updatedInodeVal}}, rootPaddr); err != nil {
		return fmt.Errorf("apfs: DeleteFile (alias): update inode: %w", err)
	}
	// Rewrite the surviving drec (strip SIBLING_ID xfield) when applicable.
	for _, su := range survivorUpserts {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(su.key)
		if err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): descend survivor drec: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
			[]fsLeafKV{su}, rootPaddr); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): rewrite survivor drec: %w", err)
		}
	}
	// Refresh parent's nchildren.
	if parentOID == apfsRootDirInoNum {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): refresh parent: %w", err)
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return fmt.Errorf("apfs: DeleteFile (alias): refresh root: %w", err)
		}
	}
	return nil
}

// findSiblingID walks every J_SIBLING_LINK record for `fileOID` and
// returns the sibling_id whose value matches (targetParent, targetName).
func (v *Volume) findSiblingID(fileOID, targetParent uint64, targetName string) (uint64, error) {
	var found uint64
	var hit bool
	err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil || oid != fileOID || typ != jTypeSibLink {
			return nil
		}
		if len(k) < 16 || len(val) < 10 {
			return nil
		}
		parentID := binary.LittleEndian.Uint64(val[0:8])
		nameLen := int(binary.LittleEndian.Uint16(val[8:10]))
		if 10+nameLen > len(val) {
			return nil
		}
		rawName := val[10 : 10+nameLen]
		if i := bytesIndexByte(rawName, 0); i >= 0 {
			rawName = rawName[:i]
		}
		if parentID == targetParent && string(rawName) == targetName {
			found = binary.LittleEndian.Uint64(k[8:16])
			hit = true
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("findSiblingID: traverse: %w", err)
	}
	if !hit {
		return 0, fmt.Errorf("findSiblingID: no J_SIBLING_LINK for inode %d at parent %d name %q",
			fileOID, targetParent, targetName)
	}
	return found, nil
}

// surivingSibling describes the (parentOID, name, siblingID) tuple of
// the J_SIBLING_LINK record that remains after one alias is deleted.
type survivingSibling struct {
	parentOID uint64
	name      string
	siblingID uint64
}

// findSurvivingSibling walks every J_SIBLING_LINK for `fileOID` and
// returns the one whose siblingID is NOT `excludeSibID` (i.e. the one
// being kept after deletion). Errors when zero or more than one
// survivor is found — both indicate inconsistent on-disk state.
func (v *Volume) findSurvivingSibling(fileOID, excludeSibID uint64) (survivingSibling, error) {
	var survivors []survivingSibling
	err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil || oid != fileOID || typ != jTypeSibLink {
			return nil
		}
		if len(k) < 16 || len(val) < 10 {
			return nil
		}
		sibID := binary.LittleEndian.Uint64(k[8:16])
		if sibID == excludeSibID {
			return nil
		}
		parentID := binary.LittleEndian.Uint64(val[0:8])
		nameLen := int(binary.LittleEndian.Uint16(val[8:10]))
		if 10+nameLen > len(val) {
			return nil
		}
		rawName := val[10 : 10+nameLen]
		if i := bytesIndexByte(rawName, 0); i >= 0 {
			rawName = rawName[:i]
		}
		survivors = append(survivors, survivingSibling{
			parentOID: parentID,
			name:      string(rawName),
			siblingID: sibID,
		})
		return nil
	})
	if err != nil {
		return survivingSibling{}, fmt.Errorf("findSurvivingSibling: traverse: %w", err)
	}
	if len(survivors) != 1 {
		return survivingSibling{}, fmt.Errorf("findSurvivingSibling: inode %d has %d survivors, want 1", fileOID, len(survivors))
	}
	return survivors[0], nil
}

// filterOutKeys returns entries with any entry matching one of `keys`
// removed. Comparison is byte-wise (the upsertEntry convention).
func filterOutKeys(entries []fsLeafKV, keys [][]byte) []fsLeafKV {
	out := entries[:0]
	for _, e := range entries {
		drop := false
		for _, k := range keys {
			if bytesEqual(e.key, k) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}

// removeKeyFromLeaf reads the FS-tree leaf at leafPaddr, drops any
// entry whose key matches `key` byte-for-byte, and rewrites the leaf
// in place. Used by the multi-level delete path.
func (v *Volume) removeKeyFromLeaf(leafPaddr, leafOID, leafXID uint64, key []byte) error {
	bs := v.physicalBlockSize()
	rawLeaf, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: read leaf: %w", err)
	}
	leaf, err := readBTreeNode(rawLeaf)
	if err != nil {
		return err
	}
	if !leaf.IsLeaf() {
		return fmt.Errorf("apfs: descended target is not a leaf (level=%d)", leaf.level)
	}
	r, err := newNodeReader(leaf, nil)
	if err != nil {
		return err
	}
	all := make([]fsLeafKV, 0, r.EntryCount())
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return err
		}
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		if bytesEqual(k, key) {
			continue // drop
		}
		all = append(all, fsLeafKV{
			key: append([]byte(nil), k...),
			val: append([]byte(nil), val...),
		})
	}
	newLeaf, err := emitFSTreeLeafNonRoot(all, int(bs), leafOID, leafXID)
	if err != nil {
		return fmt.Errorf("apfs: emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: write leaf at paddr %d: %w", leafPaddr, err)
	}
	return nil
}

// markBlocksFreed is the inverse of markBlocksAllocated: clear the
// bits in the chunk allocation bitmap, increment ci_free_count in the
// CIB, and increment sm_dev[0].sm_free_count in the spaceman.
//
// The chunk bitmap is updated WITHOUT going through the spaceman free
// queue (FQ_MAIN) — i.e. we eagerly mark the blocks free in the live
// state. Apple's design queues frees in the FQ for one xid before
// finalising, but for our writer (which doesn't yet implement free
// queues) eager marking is acceptable: fsck doesn't require the FQ
// path, only that ci_free_count + sm_free_count + bitmap agree.
func (c *Container) markBlocksFreed(block, count uint64) error {
	if count == 0 {
		return nil
	}
	loc, err := c.locateChunkZero()
	if err != nil || loc == nil {
		return err
	}
	if block < loc.chunkAddr || block+count > loc.chunkAddr+loc.chunkBlocks {
		return nil
	}
	dirty := false
	for i := uint64(0); i < count; i++ {
		idx := block - loc.chunkAddr + i
		byteIdx := idx / 8
		bit := uint8(1) << (idx % 8)
		if loc.bitmap[byteIdx]&bit != 0 {
			loc.bitmap[byteIdx] &^= bit
			dirty = true
		}
	}
	if dirty {
		if _, err := c.w.WriteAt(loc.bitmap, int64(loc.bitmapPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: free: write chunk bitmap: %w", err)
		}
	}
	if loc.cibBlock != nil {
		freeOff := 40 + 20
		freeCount := binary.LittleEndian.Uint32(loc.cibBlock[freeOff : freeOff+4])
		freeCount += uint32(count)
		binary.LittleEndian.PutUint32(loc.cibBlock[freeOff:freeOff+4], freeCount)
		sealBlock(loc.cibBlock)
		if _, err := c.w.WriteAt(loc.cibBlock, int64(loc.cibPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: free: write CIB: %w", err)
		}
	}
	if loc.smBlock != nil {
		const smDev0FreeCountOff = 0x48
		freeCount := binary.LittleEndian.Uint64(loc.smBlock[smDev0FreeCountOff : smDev0FreeCountOff+8])
		freeCount += count
		binary.LittleEndian.PutUint64(loc.smBlock[smDev0FreeCountOff:smDev0FreeCountOff+8], freeCount)
		sealBlock(loc.smBlock)
		if _, err := c.w.WriteAt(loc.smBlock, int64(loc.smPaddr*uint64(c.sb.blockSize))); err != nil {
			return fmt.Errorf("apfs: free: write spaceman: %w", err)
		}
	}
	return nil
}

// removeExtentRefRecord finds the j_phys_ext entry for `physBlock` in
// the volume's extent-ref tree (PHYSICAL B-tree at apsb.extentRefOID)
// and removes it. Used by DeleteFile to keep the extent-ref tree
// consistent with the live extent set.
func (v *Volume) removeExtentRefRecord(physBlock uint64) error {
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
		return fmt.Errorf("apfs: extentref free: read root: %w", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return err
	}
	if !rootNode.IsLeaf() {
		return v.extentRefModifyLeafMultiLevel(rawRoot, rootNode, physBlock, func(existing []fsLeafKV) ([]fsLeafKV, error) {
			target := encodePhysExtKey(physBlock)
			out := existing[:0]
			for _, e := range existing {
				if bytesEqual(e.key, target) {
					continue // drop
				}
				out = append(out, e)
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
	out := existing[:0]
	for _, e := range existing {
		if bytesEqual(e.key, target) {
			continue // drop
		}
		out = append(out, e)
	}
	leafXID := rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitPhysicalBTreeLeafExplicit(out, int(bs), rootPaddr, leafXID, objTypeBlockRefTree)
	if err != nil {
		return fmt.Errorf("apfs: extentref free: emit: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: extentref free: write: %w", err)
	}
	return nil
}

// bumpAPSBNumFiles adjusts the APSB's apfs_num_files field (offset
// 0xB8) by `delta`. Reads/mutates/seals/writes the APSB block at the
// container OMAP-resolved paddr.
func (v *Volume) bumpAPSBNumFiles(delta int64) error {
	return v.bumpAPSBCounter64(0xB8, delta)
}

// bumpAPSBNumDirectories adjusts apfs_num_directories (offset 0xC0).
// Apple's fsck excludes the synthetic top-level dirs (apfsRootDirInoNum
// = 2 and apfsPrivDirInoNum = 3) from this counter, so callers should
// pass delta = ±1 only when removing/adding USER-created directories.
func (v *Volume) bumpAPSBNumDirectories(delta int64) error {
	return v.bumpAPSBCounter64(0xC0, delta)
}

// bumpAPSBCounter64 is the shared implementation for the APSB +0xB8/
// 0xC0/0xC8/0xD0 counters (apfs_num_files / num_directories /
// num_symlinks / num_other). Reads the APSB block at the OMAP-resolved
// paddr, patches the uint64 at `offset`, re-seals Fletcher64, writes
// back in place. Clamps at 0 on underflow.
func (v *Volume) bumpAPSBCounter64(offset int, delta int64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.apsbOID == 0 {
		return nil
	}
	bs := v.physicalBlockSize()
	apsbPaddr, err := v.c.omapLookup(v.c.containerOmap, v.apsbOID, ^uint64(0))
	if err != nil {
		return err
	}
	apsbBlock, err := v.c.readBlock(apsbPaddr)
	if err != nil {
		return err
	}
	cur := int64(binary.LittleEndian.Uint64(apsbBlock[offset : offset+8]))
	next := cur + delta
	if next < 0 {
		next = 0
	}
	binary.LittleEndian.PutUint64(apsbBlock[offset:offset+8], uint64(next))
	sealBlock(apsbBlock)
	if _, err := v.c.w.WriteAt(apsbBlock, int64(apsbPaddr*bs)); err != nil {
		return err
	}
	return nil
}

// DeleteDirectory removes an empty directory at (parentOID, name).
// Like POSIX `rmdir(2)`, refuses non-empty directories — counts every
// J_DIR_REC under the target oid first and errors if the count is
// non-zero. Refuses to remove the canonical root or private-dir oids.
//
// On success: drops the directory's J_INODE (+ any J_XATTR records it
// owned), drops the J_DIR_REC under (parentOID, name), refreshes the
// parent's nchildren, and decrements `apfs_num_directories` (APSB
// +0xC0).
func (v *Volume) DeleteDirectory(parentOID uint64, name string) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: DeleteDirectory on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("apfs: DeleteDirectory: empty name")
	}
	if parentOID == apfsRootDirParent {
		parentOID = apfsRootDirInoNum
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// 1. Look up the drec under (parentOID, name) → dirOID.
	drecKey := encodeDrecKey(parentOID, name)
	_, drecVal, err := v.lookupFSTreeFirst(drecKey)
	if err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: lookup drec %q under %d: %w", name, parentOID, err)
	}
	if len(drecVal) < 18 {
		return fmt.Errorf("apfs: DeleteDirectory: drec val too short")
	}
	dirOID := binary.LittleEndian.Uint64(drecVal[0:8])

	// Refuse to remove the synthetic top-level directories.
	if dirOID == apfsRootDirInoNum || dirOID == apfsPrivDirInoNum || dirOID == apfsRootDirParent {
		return fmt.Errorf("apfs: DeleteDirectory: refusing to remove synthetic top-level directory oid %d", dirOID)
	}

	// 2. Read the inode and verify it's a directory (S_IFDIR = 0x4000).
	inodeKey := encodeInodeKey(dirOID)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: lookup inode %d: %w", dirOID, err)
	}
	if len(inodeVal) < 82 {
		return fmt.Errorf("apfs: DeleteDirectory: inode val too short")
	}
	mode := binary.LittleEndian.Uint16(inodeVal[80:82])
	if mode&0xF000 != 0x4000 {
		return fmt.Errorf("apfs: DeleteDirectory: inode %d is not a directory (mode=0o%o)", dirOID, mode)
	}

	// 3. Count children: any J_DIR_REC with parent = dirOID. POSIX
	//    rmdir refuses non-empty directories.
	nchildren := uint32(0)
	if err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return nil
		}
		if oid == dirOID && typ == jTypeDirRec {
			nchildren++
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: count children: %w", err)
	}
	if nchildren > 0 {
		return fmt.Errorf("apfs: DeleteDirectory: directory %q (oid %d) is not empty (%d children)",
			name, dirOID, nchildren)
	}

	// 4. Enumerate the records to remove: the inode + any xattrs. Drec
	//    is added separately below (its key is under parentOID, not dirOID).
	keysOnly := [][]byte{drecKey}
	if err := v.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return nil
		}
		if oid != dirOID {
			return nil
		}
		switch typ {
		case jTypeInode, jTypeXattr:
			keysOnly = append(keysOnly, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: enumerate records: %w", err)
	}

	// 5. Remove records. Single-leaf path: filter + re-emit. Multi-level:
	//    dispatch each key to its containing leaf.
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		filtered := filterOutKeys(existing, keysOnly)
		if parentOID == apfsRootDirInoNum {
			filtered = upsertRootDir(filtered)
		} else {
			var perr error
			filtered, perr = patchParentNchildrenInList(filtered, parentOID)
			if perr != nil {
				return fmt.Errorf("apfs: DeleteDirectory: patch parent: %w", perr)
			}
		}
		newLeaf, err := emitFSTreeLeafExplicit(filtered, int(bs), v.apsb.rootTreeOID, leafXID)
		if err != nil {
			return fmt.Errorf("apfs: DeleteDirectory: re-emit leaf: %w", err)
		}
		if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: DeleteDirectory: write leaf: %w", err)
		}
		if err := v.reloadRoot(rootPaddr); err != nil {
			return err
		}
	} else {
		for _, k := range keysOnly {
			leafPaddr, leafOID, _, err := v.descendToLeafForKey(k)
			if err != nil {
				return fmt.Errorf("apfs: DeleteDirectory: descend: %w", err)
			}
			if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, k); err != nil {
				return fmt.Errorf("apfs: DeleteDirectory: remove key from leaf: %w", err)
			}
		}
		if parentOID == apfsRootDirInoNum {
			if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
				return fmt.Errorf("apfs: DeleteDirectory: refresh root inode: %w", err)
			}
		} else {
			if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
				return fmt.Errorf("apfs: DeleteDirectory: refresh parent: %w", err)
			}
		}
		if !v.rootNode.IsLeaf() {
			if err := v.refreshRoot(rootPaddr); err != nil {
				return fmt.Errorf("apfs: DeleteDirectory: refresh root: %w", err)
			}
		}
	}

	// 6. Decrement APSB.apfs_num_directories.
	if err := v.bumpAPSBNumDirectories(-1); err != nil {
		return fmt.Errorf("apfs: DeleteDirectory: decrement num_directories: %w", err)
	}
	return nil
}
