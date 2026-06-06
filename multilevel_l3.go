package filesystem_apfs

// Volume-OMAP level-3 write support. Mirrors the level-2 path in
// multilevel.go (promoteOMAPRootToLevel2 / upsertVolumeOMAPLevel2 /
// scanOMAPLevel2Counts / refreshOMAPLevel2RootCounts) with one more
// internal descent layer.
//
// At level 3 the tree shape is:
//
//   root (level 3, kept at rootPaddr — the APSB-pointed paddr)
//    │
//    ├── L2 internal (level 2, fresh paddr)
//    │    ├── L1 internal (level 1, fresh paddr)
//    │    │    ├── leaf (level 0)
//    │    │    └── leaf
//    │    └── L1 internal
//    │         └── leaf …
//    └── L2 internal …
//
// Capacity at level 3 with omapInternalRootCap ≈ 122 is roughly
// 122 × 122 × 122 ≈ 1.8M leaves — well past anything cloud-image
// workloads would hit, but a real APFS container with millions of
// distinct objects (e.g. a populated user volume) lives here.

import (
	"encoding/binary"
	"fmt"
)

// upsertVolumeOMAPLevel3 descends a level-3 OMAP: root → L2 → L1 →
// leaf. Mirrors upsertVolumeOMAPLevel2's split-propagation cascade
// with one more layer.
func (v *Volume) upsertVolumeOMAPLevel3(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, oid, xid, paddr uint64) error {
	bs := v.physicalBlockSize()
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return err
	}
	rootIdx, err := readOMAPInternalIndex(rootNode, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 root index: %w", err)
	}

	// Descend root → L2.
	l2RootIdxPos := pickOMAPChildIndex(rootIdx, oid, xid)
	l2Paddr := rootIdx[l2RootIdxPos].childPaddr
	rawL2, err := v.c.readBlock(l2Paddr)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 read L2: %w", err)
	}
	l2Node, err := readBTreeNode(rawL2)
	if err != nil {
		return err
	}
	if l2Node.IsLeaf() || l2Node.level != 2 {
		return fmt.Errorf("apfs: OMAP L3 descend: L2 child level=%d, want 2", l2Node.level)
	}
	l2Idx, err := readOMAPInternalIndex(l2Node, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 L2 internal index: %w", err)
	}

	// Descend L2 → L1.
	l1L2IdxPos := pickOMAPChildIndex(l2Idx, oid, xid)
	l1Paddr := l2Idx[l1L2IdxPos].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 read L1: %w", err)
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	if l1Node.IsLeaf() || l1Node.level != 1 {
		return fmt.Errorf("apfs: OMAP L3 descend: L1 child level=%d, want 1", l1Node.level)
	}
	l1Idx, err := readOMAPInternalIndex(l1Node, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 L1 internal index: %w", err)
	}

	// Descend L1 → leaf.
	leafL1IdxPos := pickOMAPChildIndex(l1Idx, oid, xid)
	leafPaddr := l1Idx[leafL1IdxPos].childPaddr
	rawLeaf, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 read leaf: %w", err)
	}
	leafNode, err := readBTreeNode(rawLeaf)
	if err != nil {
		return err
	}
	if !leafNode.IsLeaf() {
		return fmt.Errorf("apfs: OMAP L3 descend: leaf has level=%d", leafNode.level)
	}
	lr, err := newNodeReader(leafNode, rootInfo)
	if err != nil {
		return err
	}
	entries := make([]omapKV, 0, lr.EntryCount()+1)
	for i := 0; i < lr.EntryCount(); i++ {
		k, kerr := lr.keyAt(i)
		if kerr != nil {
			return kerr
		}
		val, verr := lr.valueAt(i)
		if verr != nil {
			return verr
		}
		entries = append(entries, omapKV{
			oid:   binary.LittleEndian.Uint64(k[0:8]),
			xid:   binary.LittleEndian.Uint64(k[8:16]),
			paddr: binary.LittleEndian.Uint64(val[8:16]),
		})
	}
	entries = upsertOMAPEntry(entries, oid, xid, paddr)
	sortOMAPEntries(entries)

	// Leaf fits in place.
	if 56+448+len(entries)*32 <= int(bs) {
		leafBlock := emitOMAPNonRootLeaf(leafPaddr, leafNode.hdr.xid, omapKVsToEntries(entries))
		if _, err := v.c.w.WriteAt(leafBlock, int64(leafPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: OMAP L3 write leaf: %w", err)
		}
		return v.refreshOMAPLevel3RootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}

	// Leaf overflow → split, update L1 index.
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]
	rightLeafPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 alloc leaf split: %w", err)
	}
	leftLeafBlock := emitOMAPNonRootLeaf(leafPaddr, leafNode.hdr.xid, omapKVsToEntries(left))
	rightLeafBlock := emitOMAPNonRootLeaf(rightLeafPaddr, leafNode.hdr.xid, omapKVsToEntries(right))
	if _, err := v.c.w.WriteAt(leftLeafBlock, int64(leafPaddr*bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightLeafBlock, int64(rightLeafPaddr*bs)); err != nil {
		return err
	}
	newL1 := make([]omapIndexEntry, 0, len(l1Idx)+1)
	for _, e := range l1Idx {
		if e.childPaddr == leafPaddr {
			newL1 = append(newL1, omapIndexEntry{oid: left[0].oid, xid: left[0].xid, childPaddr: leafPaddr})
		} else {
			newL1 = append(newL1, e)
		}
	}
	newL1 = append(newL1, omapIndexEntry{oid: right[0].oid, xid: right[0].xid, childPaddr: rightLeafPaddr})
	sortOMAPIndexEntries(newL1)

	// L1 fits → rewrite L1 in place + refresh root counts.
	if len(newL1) <= omapInternalRootCap {
		l1Block := emitOMAPInternalNonRoot(l1Paddr, l1Node.hdr.xid, newL1, 1)
		if _, err := v.c.w.WriteAt(l1Block, int64(l1Paddr*bs)); err != nil {
			return err
		}
		return v.refreshOMAPLevel3RootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}

	// L1 overflow → split, update L2 index.
	l1Mid := len(newL1) / 2
	l1Left := newL1[:l1Mid]
	l1Right := newL1[l1Mid:]
	newL1RightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 alloc L1 split: %w", err)
	}
	l1LeftBlock := emitOMAPInternalNonRoot(l1Paddr, l1Node.hdr.xid, l1Left, 1)
	l1RightBlock := emitOMAPInternalNonRoot(newL1RightPaddr, l1Node.hdr.xid, l1Right, 1)
	if _, err := v.c.w.WriteAt(l1LeftBlock, int64(l1Paddr*bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(l1RightBlock, int64(newL1RightPaddr*bs)); err != nil {
		return err
	}
	newL2 := make([]omapIndexEntry, 0, len(l2Idx)+1)
	for _, e := range l2Idx {
		if e.childPaddr == l1Paddr {
			newL2 = append(newL2, omapIndexEntry{oid: l1Left[0].oid, xid: l1Left[0].xid, childPaddr: l1Paddr})
		} else {
			newL2 = append(newL2, e)
		}
	}
	newL2 = append(newL2, omapIndexEntry{oid: l1Right[0].oid, xid: l1Right[0].xid, childPaddr: newL1RightPaddr})
	sortOMAPIndexEntries(newL2)

	// L2 fits → rewrite L2 in place + refresh root counts.
	if len(newL2) <= omapInternalRootCap {
		l2Block := emitOMAPInternalNonRoot(l2Paddr, l2Node.hdr.xid, newL2, 2)
		if _, err := v.c.w.WriteAt(l2Block, int64(l2Paddr*bs)); err != nil {
			return err
		}
		return v.refreshOMAPLevel3RootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}

	// L2 overflow → split, update root index.
	l2Mid := len(newL2) / 2
	l2Left := newL2[:l2Mid]
	l2Right := newL2[l2Mid:]
	newL2RightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP L3 alloc L2 split: %w", err)
	}
	l2LeftBlock := emitOMAPInternalNonRoot(l2Paddr, l2Node.hdr.xid, l2Left, 2)
	l2RightBlock := emitOMAPInternalNonRoot(newL2RightPaddr, l2Node.hdr.xid, l2Right, 2)
	if _, err := v.c.w.WriteAt(l2LeftBlock, int64(l2Paddr*bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(l2RightBlock, int64(newL2RightPaddr*bs)); err != nil {
		return err
	}
	newRoot := make([]omapIndexEntry, 0, len(rootIdx)+1)
	for _, e := range rootIdx {
		if e.childPaddr == l2Paddr {
			newRoot = append(newRoot, omapIndexEntry{oid: l2Left[0].oid, xid: l2Left[0].xid, childPaddr: l2Paddr})
		} else {
			newRoot = append(newRoot, e)
		}
	}
	newRoot = append(newRoot, omapIndexEntry{oid: l2Right[0].oid, xid: l2Right[0].xid, childPaddr: newL2RightPaddr})
	sortOMAPIndexEntries(newRoot)
	if len(newRoot) > omapInternalRootCap {
		return fmt.Errorf("apfs: OMAP level-3 root overflow at %d index entries — level-4 promotion not supported", len(newRoot))
	}
	totalKeys, nodeCount, err := v.scanOMAPLevel3Counts(newRoot)
	if err != nil {
		return err
	}
	rootBlock := emitOMAPInternalRootAtLevel(rootPaddr, rootNode.hdr.xid, newRoot, 3, totalKeys, nodeCount)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP L3 write root: %w", err)
	}
	return nil
}

// promoteOMAPRootToLevel3 converts a level-2 root that just
// overflowed (cap exceeded after the latest split-propagation cycle
// in upsertVolumeOMAPLevel2) into a level-3 tree:
//
//   - split the overflowed level-2 root's index entries into two halves,
//   - allocate two new physical blocks for the resulting level-2 non-root
//     internals,
//   - write a fresh level-3 root at the OMAP's stable rootPaddr (so the
//     APSB-stored om_tree_oid does not need to change).
//
// indexEntries is the post-split, post-sort entry slice the caller
// produced when level-2 root would have overflowed. It always has
// >= cap+1 entries.
func (v *Volume) promoteOMAPRootToLevel3(rootPaddr, rootXID uint64, indexEntries []omapIndexEntry) error {
	bs := v.physicalBlockSize()
	if len(indexEntries) < 2 {
		return fmt.Errorf("apfs: OMAP level-3 promote: too few entries (%d)", len(indexEntries))
	}
	sortOMAPIndexEntries(indexEntries)
	mid := len(indexEntries) / 2
	left := indexEntries[:mid]
	right := indexEntries[mid:]

	leftPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: alloc left: %w", err)
	}
	rightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: alloc right: %w", err)
	}
	leftBlock := emitOMAPInternalNonRoot(leftPaddr, rootXID, left, 2)
	rightBlock := emitOMAPInternalNonRoot(rightPaddr, rootXID, right, 2)
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: write left: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: write right: %w", err)
	}

	// Recompute tree-wide totals by walking every leaf under both halves.
	rootIdx := []omapIndexEntry{
		{oid: left[0].oid, xid: left[0].xid, childPaddr: leftPaddr},
		{oid: right[0].oid, xid: right[0].xid, childPaddr: rightPaddr},
	}
	totalKeys, nodeCount, err := v.scanOMAPLevel3Counts(rootIdx)
	if err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: scan counts: %w", err)
	}

	rootBlock := emitOMAPInternalRootAtLevel(rootPaddr, rootXID, rootIdx, 3, totalKeys, nodeCount)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-3 promote: write root: %w", err)
	}
	return nil
}

// scanOMAPLevel3Counts walks every leaf under each level-2 → level-1
// internal chain, returning (totalKeys, totalNodeCount) for the
// whole level-3 tree. The +1 in nodeCount is the level-3 root itself.
func (v *Volume) scanOMAPLevel3Counts(rootIdx []omapIndexEntry) (uint64, uint64, error) {
	totalKeys := uint64(0)
	nodeCount := uint64(1) // the level-3 root
	rootInfo, err := readRootBTreeInfoFor(v, rootIdx)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range rootIdx {
		l2Raw, rerr := v.c.readBlock(e.childPaddr)
		if rerr != nil {
			return 0, 0, rerr
		}
		l2Node, nerr := readBTreeNode(l2Raw)
		if nerr != nil {
			return 0, 0, nerr
		}
		nodeCount++ // this level-2 internal
		l2Idx, ierr := readOMAPInternalIndex(l2Node, rootInfo)
		if ierr != nil {
			return 0, 0, ierr
		}
		for _, l2e := range l2Idx {
			l1Raw, rerr := v.c.readBlock(l2e.childPaddr)
			if rerr != nil {
				return 0, 0, rerr
			}
			l1Node, nerr := readBTreeNode(l1Raw)
			if nerr != nil {
				return 0, 0, nerr
			}
			nodeCount++ // this level-1 internal
			l1Idx, ierr := readOMAPInternalIndex(l1Node, rootInfo)
			if ierr != nil {
				return 0, 0, ierr
			}
			for _, le := range l1Idx {
				leafRaw, lerr := v.c.readBlock(le.childPaddr)
				if lerr != nil {
					return 0, 0, lerr
				}
				leafNode, lerr := readBTreeNode(leafRaw)
				if lerr != nil {
					return 0, 0, lerr
				}
				totalKeys += uint64(leafNode.nKeys)
				nodeCount++
			}
		}
	}
	return totalKeys, nodeCount, nil
}

// refreshOMAPLevel3RootCounts rewrites the level-3 root's btreeInfo
// trailer (totalKeys + nodeCount) after a deeper mutation that
// changed leaf entry counts but kept the root index entries
// unchanged. Same shape as refreshOMAPLevel2RootCounts.
func (v *Volume) refreshOMAPLevel3RootCounts(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, rootInfo *btreeInfo) error {
	bs := v.physicalBlockSize()
	rootIdx, err := readOMAPInternalIndex(rootNode, rootInfo)
	if err != nil {
		return err
	}
	totalKeys, nodeCount, err := v.scanOMAPLevel3Counts(rootIdx)
	if err != nil {
		return err
	}
	out := make([]byte, len(rawRoot))
	copy(out, rawRoot)
	bi := out[len(out)-btreeInfoSize:]
	binary.LittleEndian.PutUint64(bi[24:32], totalKeys)
	binary.LittleEndian.PutUint64(bi[32:40], nodeCount)
	sealBlock(out)
	if _, err := v.c.w.WriteAt(out, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: refresh OMAP L3 root counts: %w", err)
	}
	return nil
}
