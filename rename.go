package filesystem_apfs

// rename.go implements `Volume.Rename` — moving an entry from one
// (parentOID, name) to another. Handles both intra-directory renames
// and cross-directory moves. The on-disk effect is:
//   1. Drop the old J_DIR_REC under (oldParentOID, oldName).
//   2. Insert a new J_DIR_REC under (newParentOID, newName) with the
//      same drec_val (so file_id, drec_type, optional sibling_id xfield
//      are preserved).
//   3. Update the inode's parent_id field (offset 0) when the parent
//      directory actually changed.
//   4. Refresh the affected directories' nchildren counters.
//
// Reference: linux-apfs/dir.c::apfs_rename — the kernel-side dance is
// more elaborate (involves fs_snapshot xattr handling, sibling_id
// updates for hardlinks, etc.); for our writer's MVP we only support
// single-link inodes.

import (
	"encoding/binary"
	"fmt"
)

// Rename moves the entry at (oldParentOID, oldName) to
// (newParentOID, newName). The two (parent, name) pairs must differ
// (we reject the no-op case). Both parents may be either
// APFS_ROOT_DIR_PARENT (1) or APFS_ROOT_DIR_INO_NUM (2); they're
// rebound to oid 2 either way.
//
// Overwrite semantics: if `(newParentOID, newName)` already exists
// AND points at a regular file with nlink==1, that file is deleted
// (records dropped, extents freed, APSB counters updated) before the
// rename proceeds — matching POSIX `rename(2)` for the regular-file
// case. Overwriting a directory or a multi-link inode is rejected.
//
// Limit: single-link source inodes only (nlink == 1). Multi-link
// rename requires updating the corresponding J_SIBLING_LINK record's
// stored (parent_id, name) and is left as follow-up work.
func (v *Volume) Rename(oldParentOID uint64, oldName string, newParentOID uint64, newName string) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: Rename on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if oldName == "" || newName == "" {
		return fmt.Errorf("apfs: Rename: empty name")
	}
	if oldParentOID == apfsRootDirParent {
		oldParentOID = apfsRootDirInoNum
	}
	if newParentOID == apfsRootDirParent {
		newParentOID = apfsRootDirInoNum
	}
	if oldParentOID == newParentOID && oldName == newName {
		return fmt.Errorf("apfs: Rename: source and destination are identical")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return fmt.Errorf("apfs: Rename: resolve FS-tree root: %w", err)
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// 1. Look up the old drec → file_id + drec_val.
	oldDrecKey := encodeDrecKey(oldParentOID, oldName)
	_, oldDrecVal, err := v.lookupFSTreeFirst(oldDrecKey)
	if err != nil {
		return fmt.Errorf("apfs: Rename: lookup source drec %q under %d: %w", oldName, oldParentOID, err)
	}
	if len(oldDrecVal) < 18 {
		return fmt.Errorf("apfs: Rename: source drec val too short")
	}
	fileID := binary.LittleEndian.Uint64(oldDrecVal[0:8])

	// 2. Handle the case where the destination already exists. POSIX
	//    rename overwrites a regular-file destination atomically; we
	//    do this in two steps (delete then insert) since the writer
	//    has no atomic-replace primitive. Directory destinations and
	//    multi-link destinations are rejected.
	newDrecKey := encodeDrecKey(newParentOID, newName)
	if _, existingDrecVal, lookErr := v.lookupFSTreeFirst(newDrecKey); lookErr == nil {
		if len(existingDrecVal) < 8 {
			return fmt.Errorf("apfs: Rename: destination drec val too short")
		}
		destFileID := binary.LittleEndian.Uint64(existingDrecVal[0:8])
		if destFileID == fileID {
			// Same inode behind both names (shouldn't happen with
			// nlink==1 but defend against it). Nothing to do.
			return nil
		}
		_, destInodeVal, ierr := v.lookupFSTreeFirst(encodeInodeKey(destFileID))
		if ierr != nil {
			return fmt.Errorf("apfs: Rename: lookup dest inode %d: %w", destFileID, ierr)
		}
		if len(destInodeVal) < 82 {
			return fmt.Errorf("apfs: Rename: dest inode val too short")
		}
		destMode := binary.LittleEndian.Uint16(destInodeVal[80:82])
		if destMode&0xF000 != 0x8000 {
			return fmt.Errorf("apfs: Rename: destination %q is not a regular file (mode=0o%o)", newName, destMode)
		}
		destNlink := binary.LittleEndian.Uint32(destInodeVal[56:60])
		if destNlink != 1 {
			return fmt.Errorf("apfs: Rename: destination %q has nlink=%d (overwrite only supports nlink=1)", newName, destNlink)
		}
		if err := v.deleteFileLocked(newParentOID, newName); err != nil {
			return fmt.Errorf("apfs: Rename: remove existing destination %q: %w", newName, err)
		}
		// DeleteFile may have reloaded v.rootNode and v.rootInfo, so
		// the rest of this function picks up the post-delete state
		// (rootPaddr is stable since the OMAP doesn't move on a
		// single-leaf rewrite).
	}

	// 3. Read the inode and check nlink.
	inodeKey := encodeInodeKey(fileID)
	_, inodeVal, err := v.lookupFSTreeFirst(inodeKey)
	if err != nil {
		return fmt.Errorf("apfs: Rename: lookup inode %d: %w", fileID, err)
	}
	if len(inodeVal) < 60 {
		return fmt.Errorf("apfs: Rename: inode val too short")
	}
	nlink := binary.LittleEndian.Uint32(inodeVal[56:60])
	if nlink != 1 {
		return fmt.Errorf("apfs: Rename: inode %d has nlink=%d (only nlink=1 supported)", fileID, nlink)
	}

	// 4. Build the updated records:
	//    - new drec at (newParentOID, newName) with same val
	//    - inode val with parent_id = newParentOID (when parent changed)
	parentChanged := oldParentOID != newParentOID
	newDrecVal := append([]byte(nil), oldDrecVal...)
	updatedInodeVal := append([]byte(nil), inodeVal...)
	if parentChanged {
		binary.LittleEndian.PutUint64(updatedInodeVal[0:8], newParentOID)
	}
	// Rename is a metadata-change op: ctime updates, mtime/atime stay.
	touchInodeTimes(updatedInodeVal, false /* mod */)

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		// Drop old drec, insert new drec, upsert updated inode.
		filtered := filterOutKeys(existing, [][]byte{oldDrecKey})
		filtered = upsertEntry(filtered, newDrecKey, newDrecVal)
		filtered = upsertEntry(filtered, inodeKey, updatedInodeVal)
		// Refresh affected parents' nchildren in the upsert pass.
		if oldParentOID == apfsRootDirInoNum || newParentOID == apfsRootDirInoNum {
			filtered = upsertRootDir(filtered)
		}
		// Patch any non-root parents that are present in this leaf.
		if oldParentOID != apfsRootDirInoNum {
			filtered, err = patchParentNchildrenInList(filtered, oldParentOID)
			if err != nil {
				return fmt.Errorf("apfs: Rename: patch old parent: %w", err)
			}
		}
		if parentChanged && newParentOID != apfsRootDirInoNum {
			filtered, err = patchParentNchildrenInList(filtered, newParentOID)
			if err != nil {
				return fmt.Errorf("apfs: Rename: patch new parent: %w", err)
			}
		}
		if leafFitsCheck(filtered, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(filtered, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return fmt.Errorf("apfs: Rename: re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return fmt.Errorf("apfs: Rename: write leaf: %w", err)
			}
			return v.reloadRoot(rootPaddr)
		}
		return v.splitRootLeafAndWrite(filtered, rootPaddr, leafXID)
	}

	// Multi-level: dispatch each leaf-touching operation.
	// 4a. Remove the old drec.
	if leafPaddr, leafOID, _, err := v.descendToLeafForKey(oldDrecKey); err != nil {
		return fmt.Errorf("apfs: Rename: descend old drec: %w", err)
	} else if err := v.removeKeyFromLeaf(leafPaddr, leafOID, leafXID, oldDrecKey); err != nil {
		return fmt.Errorf("apfs: Rename: remove old drec: %w", err)
	}
	// 4b. Insert the new drec.
	if leafPaddr, leafOID, _, err := v.descendToLeafForKey(newDrecKey); err != nil {
		return fmt.Errorf("apfs: Rename: descend new drec: %w", err)
	} else if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
		[]fsLeafKV{{key: newDrecKey, val: newDrecVal}}, rootPaddr); err != nil {
		return fmt.Errorf("apfs: Rename: insert new drec: %w", err)
	}
	// 4c. Update the inode val (parent_id) if the parent changed.
	if parentChanged {
		if leafPaddr, leafOID, _, err := v.descendToLeafForKey(inodeKey); err != nil {
			return fmt.Errorf("apfs: Rename: descend inode: %w", err)
		} else if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID,
			[]fsLeafKV{{key: inodeKey, val: updatedInodeVal}}, rootPaddr); err != nil {
			return fmt.Errorf("apfs: Rename: update inode: %w", err)
		}
	}
	// 4d. Refresh nchildren for old + new parents.
	if oldParentOID == apfsRootDirInoNum {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return fmt.Errorf("apfs: Rename: refresh root inode (old): %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(oldParentOID, leafXID, rootPaddr, false); err != nil {
			return fmt.Errorf("apfs: Rename: refresh old parent: %w", err)
		}
	}
	if parentChanged {
		if newParentOID == apfsRootDirInoNum {
			if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
				return fmt.Errorf("apfs: Rename: refresh root inode (new): %w", err)
			}
		} else {
			if err := v.refreshNonRootParentNchildren(newParentOID, leafXID, rootPaddr, false); err != nil {
				return fmt.Errorf("apfs: Rename: refresh new parent: %w", err)
			}
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return fmt.Errorf("apfs: Rename: refresh root: %w", err)
		}
	}
	return nil
}
