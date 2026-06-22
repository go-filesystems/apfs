package filesystem_apfs

// extent_ref_multilevel.go — multi-level extent-ref tree support.
//
// The volume's extent-ref tree (a PHYSICAL BLOCKREFTREE rooted at
// `apsb.apfs_extentref_tree_oid`) starts as a single leaf when a
// container is freshly formatted. Each `j_phys_ext` entry occupies
// 36 bytes (8-byte TOC kvloc + 8-byte key + 20-byte value), so a
// 4 KiB block holds at most ~108 entries before append-time encoding
// fails with the "leaf overflow" error.
//
// This file lifts the cap to 3 levels:
//
//   - level 0 → level 1: when an append would overflow the root leaf,
//     the entries split across two non-root leaves at fresh paddrs and
//     the original root paddr is rewritten as a level=1 internal node.
//   - level 1 → level 2: when the level-1 internal root's index can no
//     longer accept one more child (cap ≈ 122 children, hit at ~13 000
//     unique extents), promotion splits the index across two level-1
//     non-root internals at fresh paddrs and rewrites the original
//     root paddr as a level=2 internal. Subsequent inserts descend
//     level-2 → level-1 → level-0 and propagate splits up.
//
// Level-3 (root-overflow at the level-2 index) is not implemented;
// at cap² × 108 ≈ 1.6M entries it is far past any realistic disk-image
// workload.
//
// Internal node format: same variable-shape kvloc layout as the leaf
// (KVNonAligned + 8-byte TOC entries). Keys are 8-byte phys_block
// values (the smallest key in each child subtree); values are 8-byte
// child paddrs. Sticking with NonAligned keeps the internal byte-
// compatible with our own reader (which uses readBTreeNode + the
// generic kvloc decoder for both leaves and internals); a byte-for-
// byte match with what Apple's kext would emit at this level would
// need a separate probe pass against a real overflowed extent-ref
// tree from an Apple-authored container.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// extentRefInternalNonRootCapEntries, when > 0, caps the index-entry
// count a non-root L1 internal node will accept before reporting
// overflow. Production leaves this at 0 (use the natural per-block
// byte cap); tests lower it to force the post-L2 L1-internal-split
// path without writing tens of thousands of files.
var extentRefInternalNonRootCapEntries = 0

// extentRefInternalCapEntries, when > 0, caps the index-entry count an
// extent-ref internal-root will accept before reporting overflow.
// Production leaves this at 0 (use the natural per-block byte cap);
// tests lower it to force the level-2 promotion path without the
// 13 000-extent workload that would naturally trigger it.
var extentRefInternalCapEntries = 0

// extentRefIndexEntry is one (smallest_key, child_paddr) pair carried
// by a level=1 BLOCKREFTREE internal node.
type extentRefIndexEntry struct {
	firstKey   uint64 // smallest phys_block key in the child subtree
	childPaddr uint64
}

// extentRefDescendToLeaf binary-searches the level-1 internal root for
// the leaf paddr that does (or would) contain `physBlock`. Returns the
// leaf's paddr, the index of the matching child entry in the root, and
// the full set of index entries (so the caller can re-emit the root).
func (v *Volume) extentRefDescendToLeaf(rootBytes []byte, rootNode *btreeNode, physBlock uint64) (leafPaddr uint64, childIdx int, indexEntries []extentRefIndexEntry, err error) {
	indexEntries, err = readExtentRefInternalEntries(rootNode, rootBytes)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(indexEntries) == 0 {
		return 0, 0, nil, fmt.Errorf("apfs: extentref descend: internal root has no entries")
	}
	// Pick the LAST entry whose firstKey ≤ physBlock. Index entries
	// are sorted by firstKey ascending.
	idx := 0
	for i, e := range indexEntries {
		if e.firstKey <= physBlock {
			idx = i
		} else {
			break
		}
	}
	return indexEntries[idx].childPaddr, idx, indexEntries, nil
}

// readExtentRefInternalEntries extracts the (firstKey, childPaddr)
// pairs from a level-1 BLOCKREFTREE internal node. The node is
// expected to use the variable-shape NonAligned layout this file
// emits (kvloc TOC entries, 8-byte keys, 8-byte values).
func readExtentRefInternalEntries(n *btreeNode, raw []byte) ([]extentRefIndexEntry, error) {
	info, _ := readRootBTreeInfo(raw) // may be nil for non-root, ok
	r, err := newNodeReader(n, info)
	if err != nil {
		return nil, err
	}
	// Bound the pre-allocation: n.nKeys is attacker-controlled. The TOC was
	// validated in readBTreeNode (nKeys*entrySize <= tableSpace.len), but
	// cap the slice capacity at the number of 8-byte kvloc entries that can
	// actually fit in the table space so a corrupt nKeys can't drive a huge
	// allocation. (Finding M1.)
	capHint := int(n.nKeys)
	if maxEntries := int(n.tableSpace.len) / 8; capHint > maxEntries {
		capHint = maxEntries
	}
	out := make([]extentRefIndexEntry, 0, capHint)
	for i := 0; i < int(n.nKeys); i++ {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return nil, fmt.Errorf("apfs: extentref internal: key %d: %w", i, kerr)
		}
		val, verr := r.valueAt(i)
		if verr != nil {
			return nil, fmt.Errorf("apfs: extentref internal: val %d: %w", i, verr)
		}
		if len(k) < 8 || len(val) < 8 {
			return nil, fmt.Errorf("apfs: extentref internal: entry %d short (k=%d, v=%d)", i, len(k), len(val))
		}
		out = append(out, extentRefIndexEntry{
			firstKey:   binary.LittleEndian.Uint64(k[:8]) & ((uint64(1) << 60) - 1),
			childPaddr: binary.LittleEndian.Uint64(val[:8]),
		})
	}
	return out, nil
}

// emitExtentRefInternalRoot writes a level=1 BLOCKREFTREE root with the
// given (firstKey, childPaddr) index entries. The TOC and entry layout
// mirror the leaf (NonAligned + 8-byte TOC kvloc entries); the value
// size is 8 bytes (child paddr) instead of 20.
func emitExtentRefInternalRoot(ownPaddr, xid uint64, entries []extentRefIndexEntry, treeKeyCount, treeNodeCount uint64, blockSize int) ([]byte, error) {
	return emitExtentRefInternalRootAtLevel(ownPaddr, xid, entries, 1, treeKeyCount, treeNodeCount, blockSize)
}

// emitExtentRefInternalRootAtLevel is emitExtentRefInternalRoot with
// an explicit level field. level=2 children point at level-1 non-root
// internals; level=1 children point at level-0 leaves.
func emitExtentRefInternalRootAtLevel(ownPaddr, xid uint64, entries []extentRefIndexEntry, level uint16, treeKeyCount, treeNodeCount uint64, blockSize int) ([]byte, error) {
	if extentRefInternalCapEntries > 0 && len(entries) > extentRefInternalCapEntries {
		return nil, fmt.Errorf("apfs: extentref internal: root overflow at entry %d (cap=%d)", extentRefInternalCapEntries, extentRefInternalCapEntries)
	}
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTree, uint32(objTypeBlockRefTree), objStoragePhysical)
	off := objPhysSize
	flags := uint16(btnFlagRoot)
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], level)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
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
	const internalKeyLen = 8
	const internalValLen = 8
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + internalKeyLen
		if need > endOfData-valCur-internalValLen {
			return nil, fmt.Errorf("apfs: extentref internal: root overflow at entry %d", i)
		}
		k := block[keyArea+keyOff : keyArea+keyOff+internalKeyLen]
		binary.LittleEndian.PutUint64(k, e.firstKey|(uint64(jTypeExtent)<<60))
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(internalKeyLen))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+internalValLen))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(internalValLen))
		valCur += internalValLen
		val := block[endOfData-valCur : endOfData-valCur+internalValLen]
		binary.LittleEndian.PutUint64(val, e.childPaddr)
		keyOff += internalKeyLen
	}
	freeLen := uint16(endOfData - (keyArea + keyOff) - valCur)
	binary.LittleEndian.PutUint16(block[off+12:off+14], uint16(keyOff))
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	bi := block[blockSize-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical|btreeFlagKVNonAligned)
	binary.LittleEndian.PutUint32(bi[4:8], uint32(blockSize))
	// Longest key/val are leaf-shape (8/20) — what every level-0 leaf
	// uses for j_phys_ext records. Apple's fsck cross-checks treat
	// these as tree-wide maxima.
	binary.LittleEndian.PutUint32(bi[16:20], 8)
	binary.LittleEndian.PutUint32(bi[20:24], 20)
	binary.LittleEndian.PutUint64(bi[24:32], treeKeyCount)
	binary.LittleEndian.PutUint64(bi[32:40], treeNodeCount)
	sealBlock(block)
	return block, nil
}

// emitExtentRefLeafNonRoot writes a level-0 BLOCKREFTREE leaf that
// does NOT carry the root flag (so it omits the btreeInfo trailer).
// Same TOC / key area / value area layout as
// emitPhysicalBTreeLeafExplicit minus the trailer + root flag.
func emitExtentRefLeafNonRoot(ownPaddr, xid uint64, entries []fsLeafKV, blockSize int) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeBlockRefTree), objStoragePhysical)
	off := objPhysSize
	flags := uint16(btnFlagLeaf)
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := len(entries) * 8
	if tocLen < 64 {
		tocLen = 64
	}
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], uint16(tocLen))
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + tocLen
	endOfData := blockSize
	keyOff := 0
	valCur := 0
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + len(e.key)
		if need > endOfData-valCur-len(e.val) {
			return nil, fmt.Errorf("apfs: extentref leaf non-root: overflow at entry %d", i)
		}
		copy(block[keyArea+keyOff:keyArea+keyOff+len(e.key)], e.key)
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(len(e.key)))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+len(e.val)))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(len(e.val)))
		valCur += len(e.val)
		copy(block[endOfData-valCur:endOfData-valCur+len(e.val)], e.val)
		keyOff += len(e.key)
	}
	freeLen := uint16(endOfData - (keyArea + keyOff) - valCur)
	binary.LittleEndian.PutUint16(block[off+12:off+14], uint16(keyOff))
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	sealBlock(block)
	return block, nil
}

// promoteExtentRefToTwoLevel splits the entries currently held by the
// single-leaf root and emits two new non-root leaves at fresh paddrs;
// the original root paddr is then rewritten as a level=1 internal
// node pointing to the two leaves. New entry that triggered the
// promotion is included before splitting.
func (v *Volume) promoteExtentRefToTwoLevel(rootPaddr, rootXID uint64, allEntries []fsLeafKV) error {
	bs := int(v.physicalBlockSize())
	sortLeafEntries(allEntries)
	mid := len(allEntries) / 2
	if mid == 0 || mid == len(allEntries) {
		return fmt.Errorf("apfs: extentref promote: too few entries to split (%d)", len(allEntries))
	}
	leftEntries := allEntries[:mid]
	rightEntries := allEntries[mid:]

	leftPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref promote: alloc left leaf: %w", err)
	}
	if v.allocCursor < leftPaddr+1 {
		v.allocCursor = leftPaddr + 1
	}
	rightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref promote: alloc right leaf: %w", err)
	}
	if v.allocCursor < rightPaddr+1 {
		v.allocCursor = rightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(leftPaddr, 1); err != nil {
		return fmt.Errorf("apfs: extentref promote: mark left allocated: %w", err)
	}
	if err := v.c.markBlocksAllocated(rightPaddr, 1); err != nil {
		return fmt.Errorf("apfs: extentref promote: mark right allocated: %w", err)
	}
	// Volume metadata blocks contribute to apfs_fs_alloc_count too;
	// without this fsck reports the counter as drifted.
	if err := v.bumpFSAllocCount(2); err != nil {
		return fmt.Errorf("apfs: extentref promote: bumpFSAllocCount: %w", err)
	}

	leafXID := rootXID
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	leftBlock, err := emitExtentRefLeafNonRoot(leftPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref promote: emit left: %w", err)
	}
	rightBlock, err := emitExtentRefLeafNonRoot(rightPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref promote: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref promote: write left: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref promote: write right: %w", err)
	}

	leftFirstKey := decodePhysExtKey(leftEntries[0].key)
	rightFirstKey := decodePhysExtKey(rightEntries[0].key)
	indexEntries := []extentRefIndexEntry{
		{firstKey: leftFirstKey, childPaddr: leftPaddr},
		{firstKey: rightFirstKey, childPaddr: rightPaddr},
	}
	rootBlock, err := emitExtentRefInternalRoot(rootPaddr, leafXID,
		indexEntries, uint64(len(allEntries)), 3, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref promote: emit root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref promote: write root: %w", err)
	}
	return nil
}

// decodePhysExtKey extracts the phys_block uint64 from a j_phys_ext
// key (8 bytes total; type tag in the top 4 bits).
func decodePhysExtKey(k []byte) uint64 {
	if len(k) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(k) & ((uint64(1) << 60) - 1)
}

// extentRefAppendMultiLevel appends a new j_phys_ext entry into a
// multi-level extent-ref tree. Dispatches to the per-level append
// routine based on rootNode.level:
//
//   - level == 1 (handled in this function): rewrite the leaf in
//     place; on overflow split, propagate up to the level-1 root,
//     and call rewriteExtentRefRoot which promotes to level 2 via
//     promoteExtentRefToLevel2 when needed.
//   - level == 2: extentRefAppendLevel2, which propagates splits
//     through the L1 internal up to the L2 root; on L2 root
//     overflow it calls promoteExtentRefToLevel3.
//   - level == 3: extentRefAppendLevel3, mirror of L2 with one
//     more layer; on L3 root overflow it returns a
//     "level-4 not supported" error (next-step).
//   - level >= 4: not yet implemented.
func (v *Volume) extentRefAppendMultiLevel(rootBytes []byte, rootNode *btreeNode, physBlock, blockCount, owningInode uint64) error {
	if rootNode.level >= 4 {
		return fmt.Errorf("apfs: extentref level=%d > 3 not yet supported for writes", rootNode.level)
	}
	if rootNode.level == 3 {
		return v.extentRefAppendLevel3(rootBytes, rootNode, physBlock, blockCount, owningInode)
	}
	if rootNode.level == 2 {
		return v.extentRefAppendLevel2(rootBytes, rootNode, physBlock, blockCount, owningInode)
	}
	bs := int(v.physicalBlockSize())
	rootPaddr := v.apsb.extentRefOID
	leafPaddr, idx, indexEntries, err := v.extentRefDescendToLeaf(rootBytes, rootNode, physBlock)
	if err != nil {
		return fmt.Errorf("apfs: extentref append (ml): descend: %w", err)
	}
	leafRaw, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref append (ml): read leaf %d: %w", leafPaddr, err)
	}
	leafNode, err := readBTreeNode(leafRaw)
	if err != nil {
		return err
	}
	leafInfo, _ := readRootBTreeInfo(leafRaw) // may be nil for non-root, ok
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
	newLeaf, err := emitExtentRefLeafNonRoot(leafPaddr, leafXID, all, bs)
	if err == nil {
		if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); err != nil {
			return fmt.Errorf("apfs: extentref append (ml): write leaf: %w", err)
		}
		// Update root's index entry's firstKey if our insert changed the
		// leaf's smallest key. (Cheap and important — fsck relies on the
		// index to find records.)
		sortLeafEntries(all)
		newFirst := decodePhysExtKey(all[0].key)
		if indexEntries[idx].firstKey != newFirst {
			indexEntries[idx].firstKey = newFirst
			return v.rewriteExtentRefRoot(rootPaddr, rootNode.hdr.xid, indexEntries, bs)
		}
		return nil
	}

	// Leaf overflow: split into two non-root leaves, then add one entry
	// to the index root.
	sortLeafEntries(all)
	mid := len(all) / 2
	leftEntries := all[:mid]
	rightEntries := all[mid:]
	newRightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref append (ml): alloc right leaf: %w", err)
	}
	if v.allocCursor < newRightPaddr+1 {
		v.allocCursor = newRightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(newRightPaddr, 1); err != nil {
		return fmt.Errorf("apfs: extentref append (ml): mark right allocated: %w", err)
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return fmt.Errorf("apfs: extentref append (ml): bumpFSAllocCount: %w", err)
	}
	leftBlock, err := emitExtentRefLeafNonRoot(leafPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref append (ml): emit left after split: %w", err)
	}
	rightBlock, err := emitExtentRefLeafNonRoot(newRightPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref append (ml): emit right after split: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(newRightPaddr)*int64(bs)); err != nil {
		return err
	}

	// Patch the root's index: replace the [idx] entry's firstKey with the
	// left side's new smallest key, and insert a new entry after it for
	// the right side.
	indexEntries[idx].firstKey = decodePhysExtKey(leftEntries[0].key)
	newIndex := make([]extentRefIndexEntry, 0, len(indexEntries)+1)
	newIndex = append(newIndex, indexEntries[:idx+1]...)
	newIndex = append(newIndex, extentRefIndexEntry{
		firstKey:   decodePhysExtKey(rightEntries[0].key),
		childPaddr: newRightPaddr,
	})
	newIndex = append(newIndex, indexEntries[idx+1:]...)
	return v.rewriteExtentRefRoot(rootPaddr, rootNode.hdr.xid, newIndex, bs)
}

// scanExtentRefLevel1Counts walks each child leaf referenced by the
// supplied level-1 index entries and returns (totalKeys, nodeCount).
// nodeCount = 1 (root) + len(entries) (level-0 leaves).
func (v *Volume) scanExtentRefLevel1Counts(entries []extentRefIndexEntry) (uint64, uint64) {
	var totalKeys uint64
	for _, e := range entries {
		raw, err := v.c.readBlock(e.childPaddr)
		if err != nil {
			continue
		}
		n, err := readBTreeNode(raw)
		if err != nil {
			continue
		}
		totalKeys += uint64(n.nKeys)
	}
	return totalKeys, uint64(1 + len(entries))
}

// scanExtentRefLevel2Counts walks every level-0 leaf under each
// level-1 internal child and returns (totalKeys, nodeCount).
// nodeCount = 1 (L2 root) + len(rootIdx) (L1 internals) + sum(L1
// child counts) (L0 leaves).
func (v *Volume) scanExtentRefLevel2Counts(rootIdx []extentRefIndexEntry) (uint64, uint64) {
	totalKeys := uint64(0)
	leafCount := uint64(0)
	for _, e := range rootIdx {
		raw, err := v.c.readBlock(e.childPaddr)
		if err != nil {
			continue
		}
		l1Node, err := readBTreeNode(raw)
		if err != nil {
			continue
		}
		l1Idx, err := readExtentRefInternalEntries(l1Node, raw)
		if err != nil {
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
	return totalKeys, 1 + uint64(len(rootIdx)) + leafCount
}

// rewriteExtentRefRoot emits a fresh level-1 root block from the
// supplied index entries and writes it back at rootPaddr. If the
// supplied entries don't fit, the tree is promoted to level-2 in
// place at the same paddr.
func (v *Volume) rewriteExtentRefRoot(rootPaddr, rootXID uint64, entries []extentRefIndexEntry, bs int) error {
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	totalKeys, nodeCount := v.scanExtentRefLevel1Counts(entries)
	block, err := emitExtentRefInternalRoot(rootPaddr, rootXID, entries, totalKeys, nodeCount, bs)
	if err != nil {
		if isExtentRefRootOverflow(err) {
			return v.promoteExtentRefToLevel2(rootPaddr, rootXID, entries, bs)
		}
		return fmt.Errorf("apfs: extentref rewrite root: %w", err)
	}
	if _, err := v.c.w.WriteAt(block, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref rewrite root: write: %w", err)
	}
	return nil
}

// isExtentRefRootOverflow reports whether err is the "internal: root
// overflow" sentinel emitted when too many index entries are supplied
// to emitExtentRefInternalRoot{,AtLevel}.
func isExtentRefRootOverflow(err error) bool {
	return err != nil && strings.Contains(err.Error(), "extentref internal: root overflow")
}

// emitExtentRefInternalNonRoot writes a level-≥1 BLOCKREFTREE
// internal node without the root flag and without the btreeInfo
// trailer. Same TOC + key/val layout as the root.
func emitExtentRefInternalNonRoot(ownPaddr, xid uint64, entries []extentRefIndexEntry, level uint16, blockSize int) ([]byte, error) {
	if extentRefInternalNonRootCapEntries > 0 && len(entries) > extentRefInternalNonRootCapEntries {
		return nil, fmt.Errorf("apfs: extentref internal: non-root overflow at entry %d (cap=%d)", len(entries), extentRefInternalNonRootCapEntries)
	}
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeBlockRefTree), objStoragePhysical)
	off := objPhysSize
	flags := uint16(0)
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], level)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := len(entries) * 8
	if tocLen < 64 {
		tocLen = 64
	}
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], uint16(tocLen))
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + tocLen
	endOfData := blockSize // non-root: no trailer
	keyOff := 0
	valCur := 0
	const internalKeyLen = 8
	const internalValLen = 8
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + internalKeyLen
		if need > endOfData-valCur-internalValLen {
			return nil, fmt.Errorf("apfs: extentref internal non-root: overflow at entry %d", i)
		}
		k := block[keyArea+keyOff : keyArea+keyOff+internalKeyLen]
		binary.LittleEndian.PutUint64(k, e.firstKey|(uint64(jTypeExtent)<<60))
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(internalKeyLen))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+internalValLen))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(internalValLen))
		valCur += internalValLen
		val := block[endOfData-valCur : endOfData-valCur+internalValLen]
		binary.LittleEndian.PutUint64(val, e.childPaddr)
		keyOff += internalKeyLen
	}
	freeLen := uint16(endOfData - (keyArea + keyOff) - valCur)
	binary.LittleEndian.PutUint16(block[off+12:off+14], uint16(keyOff))
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	sealBlock(block)
	return block, nil
}

// promoteExtentRefToLevel2 takes an overflowing set of level-1 index
// entries, splits them in half, writes each half as a level-1 non-
// root internal at a freshly-allocated paddr, and rewrites rootPaddr
// as a level-2 root with two children.
func (v *Volume) promoteExtentRefToLevel2(rootPaddr, rootXID uint64, entries []extentRefIndexEntry, bs int) error {
	if len(entries) < 2 {
		return fmt.Errorf("apfs: extentref L2 promote: too few entries (%d)", len(entries))
	}
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]
	leftPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: alloc left: %w", err)
	}
	if v.allocCursor < leftPaddr+1 {
		v.allocCursor = leftPaddr + 1
	}
	rightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: alloc right: %w", err)
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
	leftBlock, err := emitExtentRefInternalNonRoot(leftPaddr, rootXID, left, 1, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: emit left: %w", err)
	}
	rightBlock, err := emitExtentRefInternalNonRoot(rightPaddr, rootXID, right, 1, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: emit right: %w", err)
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
	totalKeys, nodeCount := v.scanExtentRefLevel2Counts(rootIdx)
	rootBlock, err := emitExtentRefInternalRootAtLevel(rootPaddr, rootXID, rootIdx, 2, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: emit root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref L2 promote: write root: %w", err)
	}
	return nil
}

// pickExtentRefChildIndex returns the rightmost child whose firstKey
// ≤ physBlock.
func pickExtentRefChildIndex(entries []extentRefIndexEntry, physBlock uint64) int {
	idx := 0
	for i, e := range entries {
		if e.firstKey <= physBlock {
			idx = i
		} else {
			break
		}
	}
	return idx
}

// extentRefAppendLevel2 inserts one j_phys_ext into a level-2 tree.
// Descends through L2 root → L1 internal → L0 leaf, rewriting the
// leaf in place; on overflow splits and propagates the new index
// entry up through the L1 internal (splitting it if needed) and
// finally the L2 root.
func (v *Volume) extentRefAppendLevel2(rootBytes []byte, rootNode *btreeNode, physBlock, blockCount, owningInode uint64) error {
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
	rIdx := pickExtentRefChildIndex(rootIdx, physBlock)
	l1Paddr := rootIdx[rIdx].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return fmt.Errorf("apfs: extentref L2 read L1: %w", err)
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	if l1Node.IsLeaf() || l1Node.level != 1 {
		return fmt.Errorf("apfs: extentref L2 descend: child level=%d, want 1", l1Node.level)
	}
	l1Idx, err := readExtentRefInternalEntries(l1Node, rawL1)
	if err != nil {
		return err
	}
	lIdx := pickExtentRefChildIndex(l1Idx, physBlock)
	leafPaddr := l1Idx[lIdx].childPaddr
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

	if newLeaf, lerr := emitExtentRefLeafNonRoot(leafPaddr, leafXID, all, bs); lerr == nil {
		if _, werr := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); werr != nil {
			return werr
		}
		sortLeafEntries(all)
		newFirst := decodePhysExtKey(all[0].key)
		if l1Idx[lIdx].firstKey != newFirst {
			l1Idx[lIdx].firstKey = newFirst
			if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, l1Idx, 1, bs); err != nil {
				return err
			}
			if rootIdx[rIdx].firstKey != l1Idx[0].firstKey {
				rootIdx[rIdx].firstKey = l1Idx[0].firstKey
				return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
			}
		}
		return nil
	}

	// Leaf full: split + propagate.
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
	l1Idx[lIdx].firstKey = decodePhysExtKey(leftEntries[0].key)
	newL1 := make([]extentRefIndexEntry, 0, len(l1Idx)+1)
	newL1 = append(newL1, l1Idx[:lIdx+1]...)
	newL1 = append(newL1, extentRefIndexEntry{
		firstKey:   decodePhysExtKey(rightEntries[0].key),
		childPaddr: newRightLeafPaddr,
	})
	newL1 = append(newL1, l1Idx[lIdx+1:]...)

	if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, newL1, 1, bs); err == nil {
		if rootIdx[rIdx].firstKey != newL1[0].firstKey {
			rootIdx[rIdx].firstKey = newL1[0].firstKey
			return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
		}
		return nil
	}

	// L1 internal overflow: split + add to L2 root.
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
	rootIdx[rIdx].firstKey = l1Left[0].firstKey
	newRoot := make([]extentRefIndexEntry, 0, len(rootIdx)+1)
	newRoot = append(newRoot, rootIdx[:rIdx+1]...)
	newRoot = append(newRoot, extentRefIndexEntry{
		firstKey:   l1Right[0].firstKey,
		childPaddr: newL1RightPaddr,
	})
	newRoot = append(newRoot, rootIdx[rIdx+1:]...)
	if err := v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, newRoot, 2, bs); err != nil {
		if isExtentRefRootOverflow(err) {
			// L2 root overflow → promote to level 3. The cascade
			// above wrote both halves of the L1 internals and
			// produced `newRoot` (the L2 index that no longer fits
			// in a single root). promoteExtentRefToLevel3 splits
			// `newRoot`, allocates two L2 non-root internals at
			// fresh paddrs, emits each, and rewrites the
			// extent-ref root paddr as a level-3 root with two
			// index entries pointing to those L2 internals.
			return v.promoteExtentRefToLevel3(rootPaddr, rootXID, newRoot, bs)
		}
		return err
	}
	return nil
}

// writeExtentRefInternalNonRoot serialises and writes a level-≥1 non-
// root extent-ref internal node at paddr.
func (v *Volume) writeExtentRefInternalNonRoot(paddr, xid uint64, entries []extentRefIndexEntry, level uint16, bs int) error {
	block, err := emitExtentRefInternalNonRoot(paddr, xid, entries, level, bs)
	if err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(block, int64(paddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref write internal: %w", err)
	}
	return nil
}

// extentRefModifyLeafLevel2 descends a level-2 extent-ref tree to
// the leaf containing physBlock, applies modify, and writes the leaf
// back. Used by the remove and length-update paths.
func (v *Volume) extentRefModifyLeafLevel2(rootBytes []byte, rootNode *btreeNode, physBlock uint64, modify func([]fsLeafKV) ([]fsLeafKV, error)) error {
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
	rIdx := pickExtentRefChildIndex(rootIdx, physBlock)
	l1Paddr := rootIdx[rIdx].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return err
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	l1Idx, err := readExtentRefInternalEntries(l1Node, rawL1)
	if err != nil {
		return err
	}
	lIdx := pickExtentRefChildIndex(l1Idx, physBlock)
	leafPaddr := l1Idx[lIdx].childPaddr
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
	modified, err := modify(existing)
	if err != nil {
		return err
	}
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	// Collapse: empty leaf is dropped from the L1 internal when the
	// internal has another sibling to keep. We don't currently collapse
	// the L1 internal itself when it becomes single-child or empty.
	if len(modified) == 0 && len(l1Idx) >= 2 {
		if err := v.c.markBlocksFreed(leafPaddr, 1); err != nil {
			return fmt.Errorf("apfs: extentref modify L2: free empty leaf: %w", err)
		}
		if err := v.bumpFSAllocCount(-1); err != nil {
			return fmt.Errorf("apfs: extentref modify L2: decrement alloc count: %w", err)
		}
		newL1 := make([]extentRefIndexEntry, 0, len(l1Idx)-1)
		newL1 = append(newL1, l1Idx[:lIdx]...)
		newL1 = append(newL1, l1Idx[lIdx+1:]...)
		if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, newL1, 1, bs); err != nil {
			return err
		}
		if rootIdx[rIdx].firstKey != newL1[0].firstKey {
			rootIdx[rIdx].firstKey = newL1[0].firstKey
			return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
		}
		return nil
	}
	newLeaf, err := emitExtentRefLeafNonRoot(leafPaddr, leafXID, modified, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref modify L2: emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref modify L2: write leaf: %w", err)
	}
	if len(modified) > 0 {
		newFirst := decodePhysExtKey(modified[0].key)
		if l1Idx[lIdx].firstKey != newFirst {
			l1Idx[lIdx].firstKey = newFirst
			if err := v.writeExtentRefInternalNonRoot(l1Paddr, rootXID, l1Idx, 1, bs); err != nil {
				return err
			}
			if rootIdx[rIdx].firstKey != l1Idx[0].firstKey {
				rootIdx[rIdx].firstKey = l1Idx[0].firstKey
				return v.rewriteExtentRefRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
			}
		}
	}
	return nil
}

// rewriteExtentRefRootAtLevel rewrites the extent-ref root at the
// given level (1 or 2). Tree-wide totalKeys / nodeCount are computed
// by scanning the leaves under the supplied index entries so the
// trailer's bt_key_count / bt_node_count match what fsck cross-checks.
func (v *Volume) rewriteExtentRefRootAtLevel(rootPaddr, rootXID uint64, entries []extentRefIndexEntry, level uint16, bs int) error {
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	var totalKeys, nodeCount uint64
	switch level {
	case 1:
		totalKeys, nodeCount = v.scanExtentRefLevel1Counts(entries)
	case 2:
		totalKeys, nodeCount = v.scanExtentRefLevel2Counts(entries)
	default:
		nodeCount = uint64(len(entries) + 1)
	}
	block, err := emitExtentRefInternalRootAtLevel(rootPaddr, rootXID, entries, level, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref rewrite root (level=%d): %w", level, err)
	}
	if _, err := v.c.w.WriteAt(block, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref rewrite root: write: %w", err)
	}
	return nil
}

// extentRefModifyLeafMultiLevel descends the 2-level tree to the leaf
// containing `physBlock`, applies the supplied `modify` callback to the
// leaf's entries, and writes the modified leaf back. Used by the
// remove and length-update paths.
func (v *Volume) extentRefModifyLeafMultiLevel(rootBytes []byte, rootNode *btreeNode, physBlock uint64, modify func([]fsLeafKV) ([]fsLeafKV, error)) error {
	if rootNode.level >= 2 {
		return v.extentRefModifyLeafLevel2(rootBytes, rootNode, physBlock, modify)
	}
	bs := int(v.physicalBlockSize())
	rootPaddr := v.apsb.extentRefOID
	leafPaddr, idx, indexEntries, err := v.extentRefDescendToLeaf(rootBytes, rootNode, physBlock)
	if err != nil {
		return err
	}
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
	modified, err := modify(existing)
	if err != nil {
		return err
	}
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	// Collapse: when a modify empties the leaf and the level-1 root has
	// at least one other child, drop this child's index entry and free
	// the leaf's block. Keeping ≥1 child preserves the level-1 shape;
	// the back-to-single-leaf collapse path is intentionally not
	// implemented here (the tree just stays at level=1 with fewer
	// children — a benign on-disk state).
	if len(modified) == 0 && len(indexEntries) >= 2 {
		if err := v.c.markBlocksFreed(leafPaddr, 1); err != nil {
			return fmt.Errorf("apfs: extentref modify (ml): free empty leaf: %w", err)
		}
		if err := v.bumpFSAllocCount(-1); err != nil {
			return fmt.Errorf("apfs: extentref modify (ml): decrement alloc count: %w", err)
		}
		newIdx := make([]extentRefIndexEntry, 0, len(indexEntries)-1)
		newIdx = append(newIdx, indexEntries[:idx]...)
		newIdx = append(newIdx, indexEntries[idx+1:]...)
		return v.rewriteExtentRefRoot(rootPaddr, rootNode.hdr.xid, newIdx, bs)
	}
	newLeaf, err := emitExtentRefLeafNonRoot(leafPaddr, leafXID, modified, bs)
	if err != nil {
		return fmt.Errorf("apfs: extentref modify (ml): emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: extentref modify (ml): write leaf: %w", err)
	}
	if len(modified) > 0 {
		newFirst := decodePhysExtKey(modified[0].key)
		if indexEntries[idx].firstKey != newFirst {
			indexEntries[idx].firstKey = newFirst
			return v.rewriteExtentRefRoot(rootPaddr, rootNode.hdr.xid, indexEntries, bs)
		}
	}
	return nil
}
