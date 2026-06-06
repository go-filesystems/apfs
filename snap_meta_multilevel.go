package filesystem_apfs

// snap_meta_multilevel.go — multi-level snap-meta tree support.
//
// The volume's snap-meta tree (a PHYSICAL BLOCKREFTREE-flavoured tree
// rooted at `apsb.apfs_snap_meta_tree_oid`) starts as a single leaf at
// volume format time. Each `CreateSnapshot` inserts ≥ 1 record; once
// the leaf would overflow at append time, this file's helpers split
// the leaf into two non-root leaves at fresh paddrs and rewrite the
// original root paddr as a level-1 internal node carrying two index
// entries pointing at the children.
//
// The tree shape mirrors the extent-ref tree: PHYSICAL (oid = paddr),
// NonAligned KV layout, variable-shape entries. Internal node values
// are 8-byte child paddrs.
//
// Compared to extent_ref_multilevel.go, the only structural
// differences are:
//   - subtype = `objTypeSnapMetaTree` instead of `objTypeBlockRefTree`
//   - keys are FS-tree-style `j_key_t`-prefixed records (J_SNAP_META
//     uses 8-byte keys keyed by xid; J_SNAP_NAME uses a variable-
//     length key starting with `(oid=0, type=jTypeSnapName)` and
//     followed by the snapshot name). We compare keys via
//     `compareFSKey` so the descent works for both record types.
//
// Level-1 → level-2 promotion fires when the level-1 root's index can
// no longer accommodate one more child. The level-2 root keeps the
// original APSB-pointed paddr; its two children are level-1 non-root
// internals carrying the previous root's index entries split into
// two halves. Subsequent appends descend through level-2 → level-1 →
// level-0 and propagate splits back up.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// snapMetaInternalNonRootCapEntries, when > 0, caps the index-entry
// count a non-root L1 internal node will accept before reporting
// overflow. Production leaves this at 0 (use the natural per-block
// byte cap); tests lower it to force the post-L2 L1-internal-split
// path without writing tens of thousands of snap-meta records.
var snapMetaInternalNonRootCapEntries = 0

// snapMetaInternalCapEntries, when > 0, caps the number of index
// entries a snap-meta internal node will accept before reporting
// overflow. Production leaves this at 0 (use the natural per-block
// byte cap); tests lower it to force the level-1 → level-2 promotion
// path without writing thousands of snapshots.
var snapMetaInternalCapEntries = 0


// snapMetaIndexEntry is one (firstKey, child_paddr) pair carried by a
// level-1 snap-meta internal node.
type snapMetaIndexEntry struct {
	firstKey   []byte // first FS-tree key in the child subtree (variable-length)
	childPaddr uint64
}

// emitSnapMetaInternalRoot writes a level-1 snap-meta root using the
// same NonAligned variable-shape kvloc layout as the leaves, with
// 8-byte values (child paddrs). Subtype = SnapMetaTree.
func emitSnapMetaInternalRoot(ownPaddr, xid uint64, entries []snapMetaIndexEntry, treeKeyCount, treeNodeCount uint64, blockSize int) ([]byte, error) {
	return emitSnapMetaInternalRootAtLevel(ownPaddr, xid, entries, 1, treeKeyCount, treeNodeCount, blockSize)
}

// emitSnapMetaInternalRootAtLevel is emitSnapMetaInternalRoot with an
// explicit level field. level=2 children point at level-1 non-root
// internals; level=1 children point at level-0 leaves.
func emitSnapMetaInternalRootAtLevel(ownPaddr, xid uint64, entries []snapMetaIndexEntry, level uint16, treeKeyCount, treeNodeCount uint64, blockSize int) ([]byte, error) {
	if snapMetaInternalCapEntries > 0 && len(entries) > snapMetaInternalCapEntries {
		return nil, fmt.Errorf("apfs: snap-meta internal: root overflow at entry %d (cap=%d)", snapMetaInternalCapEntries, snapMetaInternalCapEntries)
	}
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTree, uint32(objTypeSnapMetaTree), objStoragePhysical)
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
	const internalValLen = 8
	maxKeyLen := uint32(0)
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + len(e.firstKey)
		if need > endOfData-valCur-internalValLen {
			return nil, fmt.Errorf("apfs: snap-meta internal: root overflow at entry %d", i)
		}
		copy(block[keyArea+keyOff:keyArea+keyOff+len(e.firstKey)], e.firstKey)
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(len(e.firstKey)))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+internalValLen))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(internalValLen))
		valCur += internalValLen
		val := block[endOfData-valCur : endOfData-valCur+internalValLen]
		binary.LittleEndian.PutUint64(val, e.childPaddr)
		keyOff += len(e.firstKey)
		if uint32(len(e.firstKey)) > maxKeyLen {
			maxKeyLen = uint32(len(e.firstKey))
		}
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
	binary.LittleEndian.PutUint32(bi[16:20], maxKeyLen)
	binary.LittleEndian.PutUint32(bi[20:24], 50) // typical J_SNAP_META val len
	binary.LittleEndian.PutUint64(bi[24:32], treeKeyCount)
	binary.LittleEndian.PutUint64(bi[32:40], treeNodeCount)
	sealBlock(block)
	return block, nil
}

// emitSnapMetaLeafNonRoot writes a level-0 snap-meta leaf without the
// root flag (no btreeInfo trailer).
func emitSnapMetaLeafNonRoot(ownPaddr, xid uint64, entries []fsLeafKV, blockSize int) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeSnapMetaTree), objStoragePhysical)
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
			return nil, fmt.Errorf("apfs: snap-meta leaf non-root: overflow at entry %d", i)
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

// promoteSnapMetaToTwoLevel splits all current entries between two
// new non-root leaves at fresh paddrs and rewrites the original root
// paddr as a level-1 internal node pointing at them.
func (v *Volume) promoteSnapMetaToTwoLevel(rootPaddr, rootXID uint64, allEntries []fsLeafKV) error {
	bs := int(v.physicalBlockSize())
	sortLeafEntries(allEntries)
	mid := len(allEntries) / 2
	if mid == 0 || mid == len(allEntries) {
		return fmt.Errorf("apfs: snap-meta promote: too few entries to split (%d)", len(allEntries))
	}
	leftEntries := allEntries[:mid]
	rightEntries := allEntries[mid:]

	leftPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: snap-meta promote: alloc left: %w", err)
	}
	if v.allocCursor < leftPaddr+1 {
		v.allocCursor = leftPaddr + 1
	}
	rightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: snap-meta promote: alloc right: %w", err)
	}
	if v.allocCursor < rightPaddr+1 {
		v.allocCursor = rightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(leftPaddr, 1); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: mark left allocated: %w", err)
	}
	if err := v.c.markBlocksAllocated(rightPaddr, 1); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: mark right allocated: %w", err)
	}
	if err := v.bumpFSAllocCount(2); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: bumpFSAllocCount: %w", err)
	}

	leafXID := rootXID
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	leftBlock, err := emitSnapMetaLeafNonRoot(leftPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta promote: emit left: %w", err)
	}
	rightBlock, err := emitSnapMetaLeafNonRoot(rightPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta promote: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: write left: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: write right: %w", err)
	}

	indexEntries := []snapMetaIndexEntry{
		{firstKey: append([]byte(nil), leftEntries[0].key...), childPaddr: leftPaddr},
		{firstKey: append([]byte(nil), rightEntries[0].key...), childPaddr: rightPaddr},
	}
	rootBlock, err := emitSnapMetaInternalRoot(rootPaddr, leafXID,
		indexEntries, uint64(len(allEntries)), 3, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta promote: emit root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta promote: write root: %w", err)
	}
	return nil
}

// snapMetaDescendToLeaf finds the leaf paddr that does (or should)
// contain `targetKey` in a 2-level snap-meta tree.
func (v *Volume) snapMetaDescendToLeaf(rootBytes []byte, rootNode *btreeNode, targetKey []byte) (leafPaddr uint64, childIdx int, indexEntries []snapMetaIndexEntry, err error) {
	indexEntries, err = readSnapMetaInternalEntries(rootNode, rootBytes)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(indexEntries) == 0 {
		return 0, 0, nil, fmt.Errorf("apfs: snap-meta descend: internal root has no entries")
	}
	idx := 0
	for i, e := range indexEntries {
		if compareFSKey(e.firstKey, targetKey) <= 0 {
			idx = i
		} else {
			break
		}
	}
	return indexEntries[idx].childPaddr, idx, indexEntries, nil
}

// readSnapMetaInternalEntries decodes the (firstKey, childPaddr) pairs
// from a level-1 snap-meta internal node.
func readSnapMetaInternalEntries(n *btreeNode, raw []byte) ([]snapMetaIndexEntry, error) {
	info, _ := readRootBTreeInfo(raw)
	r, err := newNodeReader(n, info)
	if err != nil {
		return nil, err
	}
	out := make([]snapMetaIndexEntry, 0, int(n.nKeys))
	for i := 0; i < int(n.nKeys); i++ {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return nil, fmt.Errorf("apfs: snap-meta internal: key %d: %w", i, kerr)
		}
		val, verr := r.valueAt(i)
		if verr != nil {
			return nil, fmt.Errorf("apfs: snap-meta internal: val %d: %w", i, verr)
		}
		if len(val) < 8 {
			return nil, fmt.Errorf("apfs: snap-meta internal: val %d short (%d)", i, len(val))
		}
		out = append(out, snapMetaIndexEntry{
			firstKey:   append([]byte(nil), k...),
			childPaddr: binary.LittleEndian.Uint64(val[:8]),
		})
	}
	return out, nil
}

// rewriteSnapMetaRoot re-emits the level-1 snap-meta root with the
// supplied index entries. Tree-wide totalKeys / nodeCount are scanned
// from the child leaves so fsck's trailer cross-check stays clean.
func (v *Volume) rewriteSnapMetaRoot(rootPaddr, rootXID uint64, entries []snapMetaIndexEntry, bs int) error {
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	totalKeys, nodeCount := v.scanSnapMetaLevel1Counts(entries)
	block, err := emitSnapMetaInternalRoot(rootPaddr, rootXID, entries, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta rewrite root: %w", err)
	}
	if _, err := v.c.w.WriteAt(block, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta rewrite root: write: %w", err)
	}
	return nil
}

// snapMetaAppendOneRecordMultiLevel inserts a single (key, val) entry
// into a 2-level snap-meta tree. Descends to the target leaf, rewrites
// it in place if the new entry fits, otherwise splits the leaf and
// adds one entry to the level-1 root.
func (v *Volume) snapMetaAppendOneRecordMultiLevel(rootBytes []byte, rootNode *btreeNode, key, val []byte) error {
	if rootNode.level >= 2 {
		return v.snapMetaAppendOneRecordLevel2(rootBytes, rootNode, key, val)
	}
	bs := int(v.physicalBlockSize())
	rootPaddr := v.apsb.snapMetaOID
	leafPaddr, idx, indexEntries, err := v.snapMetaDescendToLeaf(rootBytes, rootNode, key)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): descend: %w", err)
	}
	leafRaw, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): read leaf %d: %w", leafPaddr, err)
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
	all = upsertEntry(all, key, val)
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitSnapMetaLeafNonRoot(leafPaddr, leafXID, all, bs)
	if err == nil {
		if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); err != nil {
			return fmt.Errorf("apfs: snap-meta append (ml): write leaf: %w", err)
		}
		sortLeafEntries(all)
		if compareFSKey(all[0].key, indexEntries[idx].firstKey) != 0 {
			indexEntries[idx].firstKey = append([]byte(nil), all[0].key...)
			return v.rewriteSnapMetaRoot(rootPaddr, rootNode.hdr.xid, indexEntries, bs)
		}
		return nil
	}

	// Leaf overflow: split, allocate new right paddr, add to root index.
	sortLeafEntries(all)
	mid := len(all) / 2
	leftEntries := all[:mid]
	rightEntries := all[mid:]
	newRightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): alloc right: %w", err)
	}
	if v.allocCursor < newRightPaddr+1 {
		v.allocCursor = newRightPaddr + 1
	}
	if err := v.c.markBlocksAllocated(newRightPaddr, 1); err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): mark allocated: %w", err)
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): bumpFSAllocCount: %w", err)
	}
	leftBlock, err := emitSnapMetaLeafNonRoot(leafPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): emit left: %w", err)
	}
	rightBlock, err := emitSnapMetaLeafNonRoot(newRightPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta append (ml): emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(newRightPaddr)*int64(bs)); err != nil {
		return err
	}
	indexEntries[idx].firstKey = append([]byte(nil), leftEntries[0].key...)
	newIndex := make([]snapMetaIndexEntry, 0, len(indexEntries)+1)
	newIndex = append(newIndex, indexEntries[:idx+1]...)
	newIndex = append(newIndex, snapMetaIndexEntry{
		firstKey:   append([]byte(nil), rightEntries[0].key...),
		childPaddr: newRightPaddr,
	})
	newIndex = append(newIndex, indexEntries[idx+1:]...)
	// Try to keep the level-1 root; promote to level-2 if it overflows.
	if err := v.rewriteSnapMetaRoot(rootPaddr, rootNode.hdr.xid, newIndex, bs); err != nil {
		if isSnapMetaRootOverflow(err) {
			return v.promoteSnapMetaToLevel2(rootPaddr, rootNode.hdr.xid, newIndex, bs)
		}
		return err
	}
	return nil
}

// isSnapMetaRootOverflow reports whether err is the "internal: root
// overflow" sentinel emitted by emitSnapMetaInternalRoot when the
// supplied index entries don't fit in a single block.
func isSnapMetaRootOverflow(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "snap-meta internal: root overflow") ||
		strings.Contains(msg, "root overflow")
}

// emitSnapMetaInternalNonRoot writes a level-≥1 snap-meta internal
// node without the root flag and without the btreeInfo trailer.
func emitSnapMetaInternalNonRoot(ownPaddr, xid uint64, entries []snapMetaIndexEntry, level uint16, blockSize int) ([]byte, error) {
	if snapMetaInternalNonRootCapEntries > 0 && len(entries) > snapMetaInternalNonRootCapEntries {
		return nil, fmt.Errorf("apfs: snap-meta internal: non-root overflow at entry %d (cap=%d)", len(entries), snapMetaInternalNonRootCapEntries)
	}
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeSnapMetaTree), objStoragePhysical)
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
	const internalValLen = 8
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + len(e.firstKey)
		if need > endOfData-valCur-internalValLen {
			return nil, fmt.Errorf("apfs: snap-meta internal non-root: overflow at entry %d", i)
		}
		copy(block[keyArea+keyOff:keyArea+keyOff+len(e.firstKey)], e.firstKey)
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], uint16(keyOff))
		binary.LittleEndian.PutUint16(block[base+2:base+4], uint16(len(e.firstKey)))
		binary.LittleEndian.PutUint16(block[base+4:base+6], uint16(valCur+internalValLen))
		binary.LittleEndian.PutUint16(block[base+6:base+8], uint16(internalValLen))
		valCur += internalValLen
		val := block[endOfData-valCur : endOfData-valCur+internalValLen]
		binary.LittleEndian.PutUint64(val, e.childPaddr)
		keyOff += len(e.firstKey)
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

// promoteSnapMetaToLevel2 takes the (overflowing) set of index entries
// destined for a level-1 root, splits them in half, writes each half
// as a level-1 non-root internal at a freshly-allocated paddr, and
// rewrites `rootPaddr` as a level-2 root with two children.
func (v *Volume) promoteSnapMetaToLevel2(rootPaddr, rootXID uint64, entries []snapMetaIndexEntry, bs int) error {
	if len(entries) < 2 {
		return fmt.Errorf("apfs: snap-meta L2 promote: too few entries (%d)", len(entries))
	}
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]

	leftPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: alloc left: %w", err)
	}
	if v.allocCursor < leftPaddr+1 {
		v.allocCursor = leftPaddr + 1
	}
	rightPaddr, err := v.nextFreeBlock()
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: alloc right: %w", err)
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

	leftBlock, err := emitSnapMetaInternalNonRoot(leftPaddr, rootXID, left, 1, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: emit left: %w", err)
	}
	rightBlock, err := emitSnapMetaInternalNonRoot(rightPaddr, rootXID, right, 1, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr)*int64(bs)); err != nil {
		return err
	}

	totalKeys, nodeCount := v.scanSnapMetaLevel2Counts(entries)

	rootIdx := []snapMetaIndexEntry{
		{firstKey: append([]byte(nil), left[0].firstKey...), childPaddr: leftPaddr},
		{firstKey: append([]byte(nil), right[0].firstKey...), childPaddr: rightPaddr},
	}
	rootBlock, err := emitSnapMetaInternalRootAtLevel(rootPaddr, rootXID, rootIdx, 2, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: emit root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta L2 promote: write root: %w", err)
	}
	return nil
}

// scanSnapMetaLevel1Counts walks each child leaf referenced by the
// supplied level-1 index entries and returns (totalKeys, nodeCount).
// nodeCount = 1 (root) + len(entries) (level-0 leaves).
func (v *Volume) scanSnapMetaLevel1Counts(entries []snapMetaIndexEntry) (uint64, uint64) {
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

// scanSnapMetaLevel2Counts walks every level-0 leaf under the supplied
// level-1 internal index entries and returns (totalKeys, nodeCount)
// for the tree post-promotion. nodeCount counts the level-2 root +
// the 2 level-1 internals + every level-0 leaf.
func (v *Volume) scanSnapMetaLevel2Counts(entries []snapMetaIndexEntry) (uint64, uint64) {
	totalKeys := uint64(0)
	leafCount := uint64(0)
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
		leafCount++
	}
	return totalKeys, 1 + 2 + leafCount
}

// snapMetaAppendOneRecordLevel2 inserts (key, val) into a level-2
// snap-meta tree. Descends through the L2 root index → L1 internal
// → L0 leaf, rewrites the leaf, and propagates leaf/internal splits
// up the chain. Errors when the L2 root itself overflows (level-3
// promotion deferred — would require ~14 000+ snapshots).
func (v *Volume) snapMetaAppendOneRecordLevel2(rootBytes []byte, rootNode *btreeNode, key, val []byte) error {
	bs := int(v.physicalBlockSize())
	rootPaddr := v.apsb.snapMetaOID
	rootXID := rootNode.hdr.xid
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	rootIdx, err := readSnapMetaInternalEntries(rootNode, rootBytes)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 root index: %w", err)
	}
	rIdx := pickSnapMetaChildIndex(rootIdx, key)
	l1Paddr := rootIdx[rIdx].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 read L1: %w", err)
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	if l1Node.IsLeaf() || l1Node.level != 1 {
		return fmt.Errorf("apfs: snap-meta L2 descend: child level=%d, want 1", l1Node.level)
	}
	l1Idx, err := readSnapMetaInternalEntries(l1Node, rawL1)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 L1 index: %w", err)
	}
	lIdx := pickSnapMetaChildIndex(l1Idx, key)
	leafPaddr := l1Idx[lIdx].childPaddr
	leafRaw, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 read leaf: %w", err)
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
	all = upsertEntry(all, key, val)
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	// Try to rewrite the leaf in place; fall back to a split when full.
	newLeaf, lerr := emitSnapMetaLeafNonRoot(leafPaddr, leafXID, all, bs)
	if lerr == nil {
		if _, werr := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); werr != nil {
			return werr
		}
		sortLeafEntries(all)
		// Refresh the L1 internal's firstKey for this child if needed.
		if compareFSKey(all[0].key, l1Idx[lIdx].firstKey) != 0 {
			l1Idx[lIdx].firstKey = append([]byte(nil), all[0].key...)
			if err := v.writeSnapMetaInternalNonRoot(l1Paddr, rootXID, l1Idx, 1, bs); err != nil {
				return err
			}
			// Refresh L2 root's firstKey for L1 if needed too.
			if compareFSKey(l1Idx[0].firstKey, rootIdx[rIdx].firstKey) != 0 {
				rootIdx[rIdx].firstKey = append([]byte(nil), l1Idx[0].firstKey...)
				return v.rewriteSnapMetaRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
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
	leftBlock, err := emitSnapMetaLeafNonRoot(leafPaddr, leafXID, leftEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 emit left leaf: %w", err)
	}
	rightBlock, err := emitSnapMetaLeafNonRoot(newRightLeafPaddr, leafXID, rightEntries, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta L2 emit right leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr)*int64(bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(newRightLeafPaddr)*int64(bs)); err != nil {
		return err
	}

	l1Idx[lIdx].firstKey = append([]byte(nil), leftEntries[0].key...)
	newL1 := make([]snapMetaIndexEntry, 0, len(l1Idx)+1)
	newL1 = append(newL1, l1Idx[:lIdx+1]...)
	newL1 = append(newL1, snapMetaIndexEntry{
		firstKey:   append([]byte(nil), rightEntries[0].key...),
		childPaddr: newRightLeafPaddr,
	})
	newL1 = append(newL1, l1Idx[lIdx+1:]...)

	// Try to write the L1 internal in place; if it overflows, split it.
	if err := v.writeSnapMetaInternalNonRoot(l1Paddr, rootXID, newL1, 1, bs); err == nil {
		if compareFSKey(newL1[0].firstKey, rootIdx[rIdx].firstKey) != 0 {
			rootIdx[rIdx].firstKey = append([]byte(nil), newL1[0].firstKey...)
			return v.rewriteSnapMetaRootAtLevel(rootPaddr, rootXID, rootIdx, 2, bs)
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
	if err := v.writeSnapMetaInternalNonRoot(l1Paddr, rootXID, l1Left, 1, bs); err != nil {
		return fmt.Errorf("apfs: snap-meta L2: write L1 left: %w", err)
	}
	if err := v.writeSnapMetaInternalNonRoot(newL1RightPaddr, rootXID, l1Right, 1, bs); err != nil {
		return fmt.Errorf("apfs: snap-meta L2: write L1 right: %w", err)
	}
	rootIdx[rIdx].firstKey = append([]byte(nil), l1Left[0].firstKey...)
	newRoot := make([]snapMetaIndexEntry, 0, len(rootIdx)+1)
	newRoot = append(newRoot, rootIdx[:rIdx+1]...)
	newRoot = append(newRoot, snapMetaIndexEntry{
		firstKey:   append([]byte(nil), l1Right[0].firstKey...),
		childPaddr: newL1RightPaddr,
	})
	newRoot = append(newRoot, rootIdx[rIdx+1:]...)

	if err := v.rewriteSnapMetaRootAtLevel(rootPaddr, rootXID, newRoot, 2, bs); err != nil {
		if isSnapMetaRootOverflow(err) {
			return fmt.Errorf("apfs: snap-meta L2 root overflow at %d index entries — level-3 promotion not supported", len(newRoot))
		}
		return err
	}
	return nil
}

// pickSnapMetaChildIndex returns the rightmost child whose firstKey ≤
// targetKey, matching the descent convention used at level=1.
func pickSnapMetaChildIndex(entries []snapMetaIndexEntry, targetKey []byte) int {
	idx := 0
	for i, e := range entries {
		if compareFSKey(e.firstKey, targetKey) <= 0 {
			idx = i
		} else {
			break
		}
	}
	return idx
}

// writeSnapMetaInternalNonRoot serialises and writes a level-≥1 non-
// root snap-meta internal node at paddr.
func (v *Volume) writeSnapMetaInternalNonRoot(paddr, xid uint64, entries []snapMetaIndexEntry, level uint16, bs int) error {
	block, err := emitSnapMetaInternalNonRoot(paddr, xid, entries, level, bs)
	if err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(block, int64(paddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta write internal: %w", err)
	}
	return nil
}

// rewriteSnapMetaRootAtLevel rewrites the snap-meta root at a given
// level (1 or 2). Used after a successful insert that may have
// changed the root's index keys or counts.
func (v *Volume) rewriteSnapMetaRootAtLevel(rootPaddr, rootXID uint64, entries []snapMetaIndexEntry, level uint16, bs int) error {
	if rootXID == 0 {
		rootXID = defaultFormatXID
	}
	var totalKeys, nodeCount uint64
	switch level {
	case 1:
		totalKeys, nodeCount = v.scanSnapMetaLevel1Counts(entries)
	case 2:
		totalKeys, nodeCount = v.scanSnapMetaLevel2Counts(entries)
	default:
		nodeCount = uint64(len(entries) + 1)
	}
	block, err := emitSnapMetaInternalRootAtLevel(rootPaddr, rootXID, entries, level, totalKeys, nodeCount, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta rewrite root (level=%d): %w", level, err)
	}
	if _, err := v.c.w.WriteAt(block, int64(rootPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta rewrite root: write: %w", err)
	}
	return nil
}
