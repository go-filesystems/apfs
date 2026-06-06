package filesystem_apfs

// sparse.go adds a writer for fully-sparse files: regular files with a
// declared logical size N but no physical allocation. The on-disk
// shape is a J_INODE_VAL with `size = N`, `alloced_size = N` rounded
// up to a block boundary, plus one J_FILE_EXTENT carrying
// `phys_block_num = 0` (the APFS convention for "this range is a
// sparse hole, return zeros on read").
//
// The reader (ReadFile) already zero-fills phys=0 extents — verified
// by `TestSparseFileZeroFill` in extras_test.go. fsck tolerates
// phys=0 extents because they don't claim any blocks; the chunk
// bitmap stays untouched.

import (
	"encoding/binary"
	"fmt"
)

// CreateSparseFile creates an empty (all-zero) regular file under
// (parentOID, name) with the given declared logical size. The file
// reads as N bytes of zeros without consuming any physical blocks.
// Returns the new inode's oid.
//
// Use case: pre-allocating a file's logical size without paying for
// the storage, e.g. for a sparse VM disk image. Subsequent
// `OverwriteFile` calls would replace the sparse hole with real data
// (the existing OverwriteFile path doesn't yet handle hole-to-real
// transitions; that would need additional extent-replacement logic).
func (v *Volume) CreateSparseFile(parentOID uint64, name string, size uint64) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateSparseFile on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateSparseFile: empty name")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, err
	}
	allocSize := ((size + bs - 1) / bs) * bs
	if allocSize == 0 {
		allocSize = bs
	}
	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}
	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}

	inodeKey := encodeInodeKey(newOID)
	inodeVal := encodeInodeValue(newOID, parentOID, size, allocSize, 0o100644)
	extKey := encodeFileExtentKey(newOID, 0)
	extVal := encodeFileExtentValue(allocSize, 0) // phys=0 → sparse hole
	drKey := encodeDrecKey(parentOID, name)
	drVal := encodeDrecValue(newOID, drecTypeRegFile)
	dstreamIDKey := encodeDStreamIDKey(newOID)
	dstreamIDVal := encodeDStreamIDValue(1)
	newRecords := []fsLeafKV{
		{key: inodeKey, val: inodeVal},
		{key: extKey, val: extVal},
		{key: drKey, val: drVal},
		{key: dstreamIDKey, val: dstreamIDVal},
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
				return 0, err
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return 0, err
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return 0, err
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return 0, err
			}
			return newOID, nil
		}
		if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return 0, err
		}
		return newOID, nil
	}
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return 0, err
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return 0, err
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return 0, err
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return 0, err
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return 0, err
		}
	}
	return newOID, nil
}

// Compile-time use of binary to silence unused-import in case the
// branches are pruned by the optimiser; the function uses it via the
// package-level helpers indirectly.
var _ = binary.LittleEndian
