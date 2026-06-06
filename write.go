package filesystem_apfs

// write.go is iterations "A" and "B" of the APFS read/write roadmap.
//
// Iteration A — WriteFileInPlace:
//   In-place data overwrite of an existing file's already-allocated extents.
//   No metadata is mutated, no blocks are allocated, no B-tree node is
//   re-emitted, no checkpoint cascade is triggered. Semantics:
//     • Extents must be CONTIGUOUS starting at logical offset 0.
//     • len(data) must be ≤ sum of extent lengths (allocated capacity).
//     • inode.Size is NOT updated; readers still see the original size.
//
// Iteration B — WriteFile:
//   In-place data overwrite + size update by rewriting the inode value's
//   J_DSTREAM.size field directly inside its FS-tree leaf. The leaf is
//   re-emitted to the SAME physical block (no checkpoint cascade), which
//   is safe because the inode value's byte length doesn't change — we
//   are mutating bytes in place, not extending the structure. Semantics:
//     • Same extent contiguity / capacity rules as WriteFileInPlace.
//     • inode.Size is updated to len(data) on disk.
//     • Other inode fields (timestamps, mode, parent, …) are untouched.
//     • Iteration C will introduce extent allocation so files can grow
//       beyond their initially allocated capacity, plus a proper
//       checkpoint cascade so multiple-block mutations stay atomic.

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

// WriteFile is iteration B of the read/write roadmap: it performs the
// in-place data overwrite of WriteFileInPlace AND patches the inode's
// J_DSTREAM.size field on disk so subsequent reads see len(data) as the
// file's logical size. The FS-tree leaf carrying the J_INODE_VAL is
// re-emitted to the same physical block (the inode value's length is
// unchanged), so this call does not trigger a checkpoint cascade.
//
// Returns ErrReadOnly when the container has no write capability;
// returns the same capacity / sparsity errors as WriteFileInPlace; and
// returns an error when the on-disk inode value has no J_DSTREAM xfield
// to update (most regular files do).
func (v *Volume) WriteFile(inode Inode, data []byte) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return err
	}
	if err := v.writeFileInPlaceLocked(inode, data); err != nil {
		return err
	}
	return v.updateInodeSizeOnDisk(inode.ID, uint64(len(data)))
}

// updateInodeSizeOnDisk locates the FS-tree leaf carrying the
// J_INODE_VAL for oid, rewrites the J_DSTREAM.size uint64 inside the
// inode value, and writes the modified leaf back to its physical block.
// Pure metadata mutation: extents and other records in the leaf are
// untouched. The leaf's TOC, key area, value area and trailing
// btreeInfo all stay byte-identical to what the parser previously
// loaded.
func (v *Volume) updateInodeSizeOnDisk(oid uint64, newSize uint64) error {
	target := make([]byte, 8)
	binary.LittleEndian.PutUint64(target, oid|(uint64(jTypeInode)<<60))
	paddr, leafBytes, entryIdx, err := v.findFSTreeLeafForKey(target)
	if err != nil {
		return fmt.Errorf("apfs: WriteFile: locate inode %d in FS-tree: %w", oid, err)
	}
	leafNode, err := readBTreeNode(leafBytes)
	if err != nil {
		return err
	}
	r, err := newNodeReader(leafNode, nil) // FS-tree leaves are variable-shape; info is unused
	if err != nil {
		return err
	}
	tocOff, valStart, valEnd, err := nodeValueRange(r, entryIdx)
	if err != nil {
		return err
	}
	_ = tocOff
	val := leafBytes[valStart:valEnd]
	const inodeBaseLen = 92
	if len(val) < inodeBaseLen+4 {
		return fmt.Errorf("apfs: WriteFile: J_INODE_VAL %d too short (%d bytes)", oid, len(val))
	}
	xfieldRel, ok := findDStreamSizeOffset(val[inodeBaseLen:])
	if !ok {
		return fmt.Errorf("apfs: WriteFile: J_INODE_VAL %d has no J_DSTREAM xfield", oid)
	}
	binary.LittleEndian.PutUint64(val[inodeBaseLen+xfieldRel:inodeBaseLen+xfieldRel+8], newSize)
	// Update mod_time + change_time to reflect this content modification.
	// access_time is updated too (POSIX semantics for atime-on-write).
	touchInodeTimes(val, true /* mod */)
	// Re-seal Fletcher64: the in-place mutation invalidates the leaf
	// block's obj_phys cksum. fsck rejects with `invalid o_cksum`
	// otherwise.
	sealBlock(leafBytes)
	if _, err := v.c.w.WriteAt(leafBytes, int64(paddr*v.physicalBlockSize())); err != nil {
		return fmt.Errorf("apfs: WriteFile: rewrite leaf at paddr %d: %w", paddr, err)
	}
	return nil
}

// physicalBlockSize returns the container's block size, defaulting to
// 4096 if the NX superblock did not record one.
func (v *Volume) physicalBlockSize() uint64 {
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	return bs
}

// nodeValueRange resolves the byte range [start, end) inside a node's
// underlying block where entry idx's value lives. Used by the write
// path to locate exactly the bytes to mutate before re-emitting the
// leaf. nodeReader is variable-shape; the function refuses fixed-shape
// nodes because the only callers (FS-tree leaves) are variable-shape.
func nodeValueRange(r *nodeReader, idx int) (tocOff, start, end int, err error) {
	if r.fixed {
		return 0, 0, 0, fmt.Errorf("apfs: nodeValueRange: fixed-shape nodes not supported")
	}
	if idx < 0 || idx >= int(r.node.nKeys) {
		return 0, 0, 0, fmt.Errorf("apfs: nodeValueRange: index %d out of range", idx)
	}
	tocEntryOff := r.tocBase + idx*8
	toc := readKVLoc(r.node.data[tocEntryOff : tocEntryOff+8])
	if toc.val.off == nlocOff {
		return 0, 0, 0, fmt.Errorf("apfs: nodeValueRange: entry %d removed", idx)
	}
	// Apple's kvloc convention: val.off is the distance from val_end to
	// the value's START. Mirror nodeReader.valueAt's interpretation.
	startInData := r.valBase - int(toc.val.off)
	endInData := startInData + int(toc.val.len)
	// Translate from data-relative to block-relative: data starts at
	// objPhysSize + btreeNodeHeaderSize within the block.
	dataBase := objPhysSize + btreeNodeHeaderSize
	return tocEntryOff + dataBase, dataBase + startInData, dataBase + endInData, nil
}

// findFSTreeLeafForKey descends the FS-tree by binary search until it
// lands on the leaf entry whose key compares equal to targetKey. Unlike
// lookupFSTreeFirst, it returns enough state for a writer to rewrite
// the leaf in place: the leaf's physical block address, the leaf's full
// 4 KiB content, and the matching entry's index in the leaf's TOC.
func (v *Volume) findFSTreeLeafForKey(targetKey []byte) (paddr uint64, leafBytes []byte, entryIdx int, err error) {
	return v.findFSTreeLeafForKeyAt(v.rootNode, v.rootInfo, paddrOfRoot(v), targetKey)
}

// paddrOfRoot returns the physical block address of the FS-tree root.
// It is needed so updateInodeSizeOnDisk can write the root back when the
// matching entry happens to live in the root itself (single-leaf tree).
func paddrOfRoot(v *Volume) uint64 {
	// The FS-tree root is the block we resolved at OpenVolume via
	// omapLookup(volOmap, apsb.rootTreeOID, xidLimit). We didn't store
	// the paddr on the volume struct; resolve it now.
	if v.apsb == nil {
		return 0
	}
	paddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0
	}
	return paddr
}

func (v *Volume) findFSTreeLeafForKeyAt(n *btreeNode, info *btreeInfo, paddr uint64, targetKey []byte) (uint64, []byte, int, error) {
	r, err := newNodeReader(n, info)
	if err != nil {
		return 0, nil, 0, err
	}
	nKeys := r.EntryCount()
	if nKeys == 0 {
		return 0, nil, 0, os.ErrNotExist
	}
	cmp := func(i int) int {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return 1
		}
		return compareFSKey(k, targetKey)
	}
	if n.IsLeaf() {
		// Find the entry whose key equals targetKey.
		lo, hi := 0, nKeys
		for lo < hi {
			mid := (lo + hi) / 2
			if cmp(mid) < 0 {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo >= nKeys {
			return 0, nil, 0, os.ErrNotExist
		}
		k, _ := r.keyAt(lo)
		if compareFSKey(k, targetKey) != 0 {
			return 0, nil, 0, os.ErrNotExist
		}
		// We need the FULL leaf block, not just data, because the writer
		// will WriteAt(blockBytes, paddr*blockSize). The block is the
		// underlying storage of n.block.
		return paddr, n.block, lo, nil
	}
	// Internal node: descend.
	lo, hi := 0, nKeys
	for lo < hi {
		mid := (lo + hi) / 2
		if cmp(mid) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	idx := lo - 1
	if idx < 0 {
		idx = 0
	}
	childOID, err := r.childOIDAt(idx)
	if err != nil {
		return 0, nil, 0, err
	}
	childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
	if err != nil {
		return 0, nil, 0, err
	}
	childBytes, err := v.c.readBlock(childPaddr)
	if err != nil {
		return 0, nil, 0, err
	}
	if v.c.verifyHashes {
		if hash, ok := r.childHashAt(idx); ok {
			if err := verifyBlockHash(childBytes, hash); err != nil {
				return 0, nil, 0, err
			}
		}
	}
	child, err := readBTreeNode(childBytes)
	if err != nil {
		return 0, nil, 0, err
	}
	return v.findFSTreeLeafForKeyAt(child, info, childPaddr, targetKey)
}

// WriteFileInPlace overwrites the contents of inode with data, writing
// directly into the physical extents already allocated to the file.
// Returns ErrReadOnly when the container has no write capability;
// returns a descriptive error when the file's extent layout cannot
// accommodate the requested write.
//
// The caller is expected to read inode via FindInode (which populates
// dataExtents); a stale Inode whose extents no longer match the
// on-disk layout will silently corrupt unrelated blocks. Read first,
// write second, in the same session, with no intervening mutation.
func (v *Volume) WriteFileInPlace(inode Inode, data []byte) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.writeFileInPlaceLocked(inode, data)
}

// writeFileInPlaceLocked is the lock-free body of WriteFileInPlace.
// Callers MUST already hold v.c.mu (write lock). Used by both
// WriteFileInPlace and WriteFile.
func (v *Volume) writeFileInPlaceLocked(inode Inode, data []byte) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if inode.IsDir {
		return fmt.Errorf("apfs: WriteFileInPlace on directory %q", inode.Name)
	}
	if v.xidLimit != ^uint64(0) {
		// xidLimit < ^uint64(0) means we are looking at a snapshot view —
		// writing through it would mutate the live volume's blocks while
		// pretending to operate on history. Refuse to be implicit.
		return fmt.Errorf("apfs: WriteFileInPlace on a snapshot view (xidLimit=%d) is not supported", v.xidLimit)
	}
	if len(inode.dataExtents) == 0 {
		if len(data) == 0 {
			return nil
		}
		return fmt.Errorf("apfs: WriteFileInPlace: inode %d has no allocated extents (need %d bytes)", inode.ID, len(data))
	}
	extents := make([]containerExtent, len(inode.dataExtents))
	copy(extents, inode.dataExtents)
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].logicalOffset < extents[j].logicalOffset
	})
	var capacity uint64
	var expected uint64
	for i, ext := range extents {
		if ext.logicalOffset != expected {
			return fmt.Errorf("apfs: WriteFileInPlace: inode %d has a sparse hole at logical %d (extent %d starts at %d)", inode.ID, expected, i, ext.logicalOffset)
		}
		capacity += ext.length
		expected += ext.length
	}
	if uint64(len(data)) > capacity {
		return fmt.Errorf("apfs: WriteFileInPlace: %d bytes exceed allocated capacity %d for inode %d", len(data), capacity, inode.ID)
	}
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	cursor := 0
	for _, ext := range extents {
		if cursor >= len(data) {
			break
		}
		chunk := data[cursor:]
		if uint64(len(chunk)) > ext.length {
			chunk = chunk[:ext.length]
		}
		if _, err := v.c.w.WriteAt(chunk, int64(ext.physBlock*bs)); err != nil {
			return fmt.Errorf("apfs: WriteFileInPlace: write extent at phys %d: %w", ext.physBlock, err)
		}
		cursor += len(chunk)
	}
	return nil
}
