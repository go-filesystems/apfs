package filesystem_apfs

// Extent-ref level-3 write support. Mirrors the level-2 path in
// extent_ref_multilevel.go (promoteExtentRefToLevel2 /
// extentRefAppendLevel2 / scanExtentRefLevel2Counts) with one more
// internal descent layer.
//
// At level 3 the tree shape is:
//
//   root (level 3, kept at v.apsb.extentRefOID)
//    │
//    ├── L2 internal (level 2, fresh paddr)
//    │    ├── L1 internal (level 1, fresh paddr)
//    │    │    ├── leaf (level 0)
//    │    │    └── leaf
//    │    └── L1 internal
//    │         └── leaf …
//    └── L2 internal …
//
// Production cap (~122 children per internal) means level 3 fits
// ~122³ ≈ 1.8M phys_ext entries — past anything cloud-image
// workloads hit, but real APFS containers from populated user
// volumes live here.

import "fmt"

// extentRefAppendLevel3 inserts one j_phys_ext into a level-3 tree.
// Descends through L3 root → L2 internal → L1 internal → L0 leaf,
// rewrites the leaf in place, and on overflow propagates splits up
// through the internals all the way to the root. Mirrors
// extentRefAppendLevel2 with one more layer.
func (v *Volume) extentRefAppendLevel3(rootBytes []byte, rootNode *btreeNode, physBlock, blockCount, owningInode uint64) error {
	bs := int(v.physicalBlockSize())
	rootPaddr := v.apsb.extentRefOID
	rootXID := rootNode.hdr.xid
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	rootIdx, err := readExtentRefInternalEntries(rootNode, rootBytes)
	if err != nil {
		return err
	}

	// Descend root → L2.
	rIdx := pickExtentRefChildIndex(rootIdx, physBlock)
	l2Paddr := rootIdx[rIdx].childPaddr
	rawL2, err := v.c.readBlock(l2Paddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 read L2: %w", err)
	}
	l2Node, err := readBTreeNode(rawL2)
	if err != nil {
		return err
	}
	if l2Node.IsLeaf() || l2Node.level != 2 {
		return fmt.Errorf("apfs: extentref L3 descend: L2 child level=%d, want 2", l2Node.level)
	}
	l2Idx, err := readExtentRefInternalEntries(l2Node, rawL2)
	if err != nil {
		return err
	}

	// Descend L2 → L1.
	l1L2Pos := pickExtentRefChildIndex(l2Idx, physBlock)
	l1Paddr := l2Idx[l1L2Pos].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 read L1: %w", err)
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	if l1Node.IsLeaf() || l1Node.level != 1 {
		return fmt.Errorf("apfs: extentref L3 descend: L1 child level=%d, want 1", l1Node.level)
	}
	l1Idx, err := readExtentRefInternalEntries(l1Node, rawL1)
	if err != nil {
		return err
	}

	// Descend L1 → leaf.
	lL1Pos := pickExtentRefChildIndex(l1Idx, physBlock)
	leafPaddr := l1Idx[lL1Pos].childPaddr
	leafRaw, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return err
	}
	leafNode, err := readBTreeNode(leafRaw)
	if err != nil {
		return err
	}
	leafInfo, _ := readRootBTreeInfo(leafRaw)
	existing, err := readAllLeafEntries(leafNode, leafInfo)
	if err != nil {
		return err
	}
	all := append([]fsLeafKV(nil), existing...)
	all = append(all, fsLeafKV{
		key: encodePhysExtKey(physBlock),
		val: encodePhysExtValue(blockCount, owningInode, 1),
	})
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// Try in-place leaf rewrite first.
	if newLeaf, lerr := emitExtentRefLeafNonRoot(leafPaddr, leafXID, all, bs); lerr == nil {
		if _, werr := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); werr != nil {
			return werr
		}
		sortLeafEntries(all)
		newFirst := decodePhysExtKey(all[0].key)
		if l1Idx[lL1Pos].firstKey != newFirst {
			l1Idx[lL1Pos].firstKey = newFirst
			if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, l1Idx, 1, bs); err != nil {
				return err
			}
			if l2Idx[l1L2Pos].firstKey != l1Idx[0].firstKey {
				l2Idx[l1L2Pos].firstKey = l1Idx[0].firstKey
				if err := v.writeExtentRefInternalNonRoot(l2Paddr, rootXID, l2Idx, 2, bs); err != nil {
					return err
				}
				if rootIdx[rIdx].firstKey != l2Idx[0].firstKey {
					rootIdx[rIdx].firstKey = l2Idx[0].firstKey
					return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 3, bs)
				}
			}
		}
		return nil
	}

	// Leaf full: split + propagate up.
	sortLeafEntries(all)
	mid := len(all) / 2
	leftEntries := all[:mid]
	rightEntries := all[mid:]
	newRightLeafPaddr, err := v.nextFreeBlock()
	if err != nil {
		return err
	}
	if v.allocCursor < newRightLeafPaddr+1 {
		v.allocCursor = newRightLeafPaddr + 1
	}
	if err := v.c.markBlocksAllocated(newRightLeafPaddr, 1); err != nil {
		return err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return err
	}
	leftBlock, err := emitExtentRefLeafNonRoot(leafPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return err
	}
	rightBlock, err := emitExtentRefLeafNonRoot(newRightLeafPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(newRightLeafPaddr)*int64(bs)); err != nil {
		return err
	}

	// Update L1 with the split's new index entries.
	l1Idx[lL1Pos].firstKey = decodePhysExtKey(leftEntries[0].key)
	newL1 := make([]extentRefIndexEntry, 0, len(l1Idx)+1)
	newL1 = append(newL1, l1Idx[:lL1Pos+1]...)
	newL1 = append(newL1, extentRefIndexEntry{
		firstKey:   decodePhysExtKey(rightEntries[0].key),
		childPaddr: newRightLeafPaddr,
	})
	newL1 = append(newL1, l1Idx[lL1Pos+1:]...)

	if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, newL1, 1, bs); err == nil {
		if l2Idx[l1L2Pos].firstKey != newL1[0].firstKey {
			l2Idx[l1L2Pos].firstKey = newL1[0].firstKey
			if err := v.writeExtentRefInternalNonRoot(l2Paddr, rootXID, l2Idx, 2, bs); err != nil {
				return err
			}
			if rootIdx[rIdx].firstKey != l2Idx[0].firstKey {
				rootIdx[rIdx].firstKey = l2Idx[0].firstKey
				return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 3, bs)
			}
		}
		return nil
	}

	// L1 internal overflow: split, propagate to L2.
	l1Mid := len(newL1) / 2
	l1Left := newL1[:l1Mid]
	l1Right := newL1[l1Mid:]
	newL1RightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return err
	}
	if v.allocCursor < newL1RightPaddr+1 {
		v.allocCursor = newL1RightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(newL1RightPaddr, 1); err != nil {
		return err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return err
	}
	if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, l1Left, 1, bs); err != nil {
		return err
	}
	if err := v.writeExtentRefInternalNonRoot(newL1RightPaddr, rootXID, l1Right, 1, bs); err != nil {
		return err
	}
	l2Idx[l1L2Pos].firstKey = l1Left[0].firstKey
	newL2 := make([]extentRefIndexEntry, 0, len(l2Idx)+1)
	newL2 = append(newL2, l2Idx[:l1L2Pos+1]...)
	newL2 = append(newL2, extentRefIndexEntry{
		firstKey:   l1Right[0].firstKey,
		childPaddr: newL1RightPaddr,
	})
	newL2 = append(newL2, l2Idx[l1L2Pos+1:]...)

	if err := v.writeExtentRefInternalNonRoot(l2Paddr, rootXID, newL2, 2, bs); err == nil {
		if rootIdx[rIdx].firstKey != newL2[0].firstKey {
			rootIdx[rIdx].firstKey = newL2[0].firstKey
			return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 3, bs)
		}
		return nil
	}

	// L2 internal overflow: split, propagate to L3 root.
	l2Mid := len(newL2) / 2
	l2Left := newL2[:l2Mid]
	l2Right := newL2[l2Mid:]
	newL2RightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return err
	}
	if v.allocCursor < newL2RightPaddr+1 {
		v.allocCursor = newL2RightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(newL2RightPaddr, 1); err != nil {
		return err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return err
	}
	if err := v.writeExtentRefInternalNonRoot(l2Paddr, rootXID, l2Left, 2, bs); err != nil {
		return err
	}
	if err := v.writeExtentRefInternalNonRoot(newL2RightPaddr, rootXID, l2Right, 2, bs); err != nil {
		return err
	}
	rootIdx[rIdx].firstKey = l2Left[0].firstKey
	newRoot := make([]extentRefIndexEntry, 0, len(rootIdx)+1)
	newRoot = append(newRoot, rootIdx[:rIdx+1]...)
	newRoot = append(newRoot, extentRefIndexEntry{
		firstKey:   l2Right[0].firstKey,
		childPaddr: newL2RightPaddr,
	})
	newRoot = append(newRoot, rootIdx[rIdx+1:]...)
	if err := v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, newRoot, 3, bs); err != nil {
		if isExtentRefRootOverflow(err) {
			return fmt.Errorf("apfs: extentref L3 root overflow at %d index entries — level-4 promotion not supported", len(newRoot))
		}
		return err
	}
	return nil
}

// promoteExtentRefToLevel3 takes an overflowing set of level-2 index
// entries, splits them in half, writes each half as a level-2 non-
// root internal at a freshly-allocated paddr, and rewrites
// rootPaddr as a level-3 root with two children. Mirrors
// promoteExtentRefToLevel2 one layer up.
func (v *Volume) promoteExtentRefToLevel3(rootPaddr, rootXID uint64, entries []extentRefIndexEntry, bs int) error {
	if len(entries) < 2 {
		return fmt.Errorf("apfs: extentref L3 promote: too few entries (%d)", len(entries))
	}
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]
	leftPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: alloc left: %w", err)
	}
	if v.allocCursor < leftPaddr+1 {
		v.allocCursor = leftPaddr + 1
	}
	rightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: alloc right: %w", err)
	}
	if v.allocCursor < rightPaddr+1 {
		v.allocCursor = rightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(leftPaddr, 1); err != nil {
		return err
	}
	if err := v.c.markBlocksAllocated(rightPaddr, 1); err != nil {
		return err
	}
	if err := v.bumpFSAllocCount(2); err != nil {
		return err
	}
	leftBlock, err := emitExtentRefInternalNonRoot(leftPaddr, rootXID, left, 2, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: emit left: %w", err)
	}
	rightBlock, err := emitExtentRefInternalNonRoot(rightPaddr, rootXID, right, 2, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr)*int64(bs)); err != nil {
		return err
	}
	rootIdx := []extentRefIndexEntry{
		{firstKey: left[0].firstKey, childPaddr: leftPaddr},
		{firstKey: right[0].firstKey, childPaddr: rightPaddr},
	}
	totalKeys, nodeCount := v.scanExtentRefLevel3Counts(rootIdx)
	rootBlock, err := emitExtentRefInternalRootAtLevel(rootPaddr, rootXID, rootIdx, 3, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: emit root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref L3 promote: write root: %w", err)
	}
	return nil
}

// scanExtentRefLevel3Counts walks every level-0 leaf under each
// level-2 → level-1 internal chain and returns (totalKeys,
// nodeCount). nodeCount = 1 (L3 root) + len(rootIdx) (L2 internals)
// + sum L1-counts (L1 internals) + sum L0-counts (leaves).
func (v *Volume) scanExtentRefLevel3Counts(rootIdx []extentRefIndexEntry) (uint64, uint64) {
	totalKeys := uint64(0)
	l2Count := uint64(0)
	l1Count := uint64(0)
	leafCount := uint64(0)
	for _, e := range rootIdx {
		l2Raw, err := v.c.readBlock(e.childPaddr)
		if err != nil {
			continue
		}
		l2Node, err := readBTreeNode(l2Raw)
		if err != nil {
			continue
		}
		l2Count++
		l2Idx, err := readExtentRefInternalEntries(l2Node, l2Raw)
		if err != nil {
			continue
		}
		for _, l2e := range l2Idx {
			l1Raw, l1err := v.c.readBlock(l2e.childPaddr)
			if l1err != nil {
				continue
			}
			l1Node, l1err := readBTreeNode(l1Raw)
			if l1err != nil {
				continue
			}
			l1Count++
			l1Idx, l1err := readExtentRefInternalEntries(l1Node, l1Raw)
			if l1err != nil {
				continue
			}
			for _, le := range l1Idx {
				lraw, lerr := v.c.readBlock(le.childPaddr)
				if lerr != nil {
					continue
				}
				lnode, lerr := readBTreeNode(lraw)
				if lerr != nil {
					continue
				}
				totalKeys += uint64(lnode.nKeys)
				leafCount++
			}
		}
	}
	return totalKeys, 1 + l2Count + l1Count + leafCount
}
