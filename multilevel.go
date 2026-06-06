package filesystem_apfs

// multilevel.go — iteration "C-3" of the read/write roadmap.
//
// CreateFile previously refused two cases:
//   - the FS-tree root is not a leaf (multi-level tree)
//   - the rebuilt single leaf would overflow a 4 KiB block
//
// This file lifts both restrictions for the practical-N-files path:
//
//   1. Single-leaf overflow → root-leaf split into a 2-level tree
//      (a fresh internal root pointing to two new leaves, the old
//      root's paddr re-used as the new internal root's storage).
//
//   2. Multi-level (level >= 1) insert → descend to the target leaf,
//      modify it in place; if the leaf would overflow, split it and
//      add a new entry in the parent index node. Recursion up the
//      tree is supported only as deep as the root is internal AND the
//      root has space for one more entry — sufficient for ~100 files
//      under our test load. A second-level split would need an
//      internal-node split, which is out of scope here.
//
// Volume OMAP updates: every newly-allocated leaf is registered with
// (oid, xid, paddr) in the volume OMAP so subsequent traversals find
// the new leaf. The OMAP itself is a single fixed-shape leaf
// (`encodeOMAPLeaf`), and we re-encode it in place with the appended
// entries — overflow there would need its own split, also out of scope.

import (
	"encoding/binary"
	"fmt"
)

// omapInternalRootCap is the maximum number of index entries that fit
// in a level-1 OMAP internal root before the tree promotes to level-2.
// Derived from (blockSize - headLen - omapInternalTOCLen - bt_info)
// / (keySize + valSize) = (4096 - 56 - 576 - 40) / (16 + 8). Declared
// as a var (not a const) so tests can lower it to force the level-2
// promotion path without writing 13 800-entry workloads.
var omapInternalRootCap = 122

// allocVirtualOID returns a fresh virtual oid for a new tree node.
// Bumps an in-memory cursor seeded from the on-disk nx_next_oid;
// Commit (D-7) writes the cursor back into block 0.
func (c *Container) allocVirtualOID() uint64 {
	if c.allocOIDCursor == 0 {
		// Seed from nx_next_oid the first time we allocate. The +1 leaves
		// the as-read value as the "next" hint for the rest of the
		// container (matching how Apple's writers consume this counter).
		c.allocOIDCursor = c.sb.nextOID
		if c.allocOIDCursor < 1100 {
			// Safety floor above the ephemeral / format constants
			// (1024..1029 + APSB at 1026 + FS-tree root at 1027).
			c.allocOIDCursor = 1100
		}
	}
	oid := c.allocOIDCursor
	c.allocOIDCursor++
	if c.allocOIDCursor > c.sb.nextOID {
		c.sb.nextOID = c.allocOIDCursor
	}
	return oid
}

// omapKV is one (oid, xid) → paddr triple from a volume OMAP leaf.
// Internal helper struct shared between the single-leaf and split
// paths of the OMAP upsert / promote logic.
type omapKV struct {
	oid, xid, paddr uint64
}

// upsertVolumeOMAPEntry inserts or updates a (oid, xid, paddr) triple
// in the volume's OMAP. Handles both the single-leaf case (entries
// fit in one block; rewrite in place) and the level-1 split case
// (single leaf overflows; promote to a 2-level tree). Multi-level
// trees that ALREADY exist are descended via `omapLookupForUpsert`,
// the target leaf is modified, and a leaf split during multi-level
// insert promotes the parent-of-leaf when needed.
func (v *Volume) upsertVolumeOMAPEntry(oid, xid, paddr uint64) error {
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.volOmap == nil || v.volOmap.treeOID == 0 {
		return fmt.Errorf("apfs: upsertVolumeOMAPEntry: no volume OMAP")
	}
	rootPaddr := v.volOmap.treeOID
	rawRoot, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return fmt.Errorf("apfs: read volume OMAP root: %w", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return fmt.Errorf("apfs: parse volume OMAP root: %w", err)
	}
	if rootNode.IsLeaf() {
		return v.upsertVolumeOMAPSingleLeaf(rootPaddr, rootNode, rawRoot, oid, xid, paddr)
	}
	// Multi-level OMAP: descend to find the target leaf, modify it
	// in place, split if overflow.
	return v.upsertVolumeOMAPMultiLevel(rootPaddr, rawRoot, rootNode, oid, xid, paddr)
}

// upsertVolumeOMAPSingleLeaf handles the case where the volume OMAP
// is a single root+leaf node. Either the entries fit (rewrite in
// place) or they don't (promote to a 2-level tree).
func (v *Volume) upsertVolumeOMAPSingleLeaf(rootPaddr uint64, leafNode *btreeNode, rawLeaf []byte, oid, xid, paddr uint64) error {
	bs := v.physicalBlockSize()
	leafInfo, err := readRootBTreeInfo(rawLeaf)
	if err != nil {
		return fmt.Errorf("apfs: parse OMAP info: %w", err)
	}
	r, err := newNodeReader(leafNode, leafInfo)
	if err != nil {
		return err
	}
	entries := make([]omapKV, 0, r.EntryCount()+1)
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return err
		}
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		entries = append(entries, omapKV{
			oid:   binary.LittleEndian.Uint64(k[0:8]),
			xid:   binary.LittleEndian.Uint64(k[8:16]),
			paddr: binary.LittleEndian.Uint64(val[8:16]),
		})
	}
	entries = upsertOMAPEntry(entries, oid, xid, paddr)
	sortOMAPEntries(entries)

	// Capacity check (matches encodeOMAPLeaf's TOC-fixed-448 layout):
	// 56-byte head + 448-byte TOC reservation + 32 bytes/entry +
	// 40-byte trailer.
	if 56+448+len(entries)*32+btreeInfoSize > int(bs) {
		// Promote to 2-level tree.
		return v.promoteVolumeOMAPToTwoLevel(rootPaddr, leafNode.hdr.xid, entries)
	}
	out := make([]byte, bs)
	omapEntries := make([]omapEntry, len(entries))
	for i, e := range entries {
		omapEntries[i] = omapEntry{oid: e.oid, xid: e.xid, paddr: e.paddr}
	}
	encodeOMAPLeaf(out, rootPaddr, omapEntries)
	binary.LittleEndian.PutUint64(out[16:24], leafNode.hdr.xid)
	sealBlock(out)
	if _, err := v.c.w.WriteAt(out, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: write volume OMAP leaf: %w", err)
	}
	return nil
}

// upsertOMAPEntry inserts or replaces (oid, xid, paddr) in entries.
// Returns the (possibly extended) slice.
func upsertOMAPEntry(entries []omapKV, oid, xid, paddr uint64) []omapKV {
	for i := range entries {
		if entries[i].oid == oid && entries[i].xid == xid {
			entries[i].paddr = paddr
			return entries
		}
	}
	return append(entries, omapKV{oid: oid, xid: xid, paddr: paddr})
}

// sortOMAPEntries sorts in place by (oid asc, xid asc) — Apple's
// canonical OMAP key order.
func sortOMAPEntries(entries []omapKV) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0; j-- {
			a, b := entries[j-1], entries[j]
			if a.oid < b.oid || (a.oid == b.oid && a.xid <= b.xid) {
				break
			}
			entries[j-1], entries[j] = b, a
		}
	}
}

// promoteVolumeOMAPToTwoLevel converts a single-leaf volume OMAP
// into a 2-level B-tree (level-1 root + 2 level-0 leaves). Triggered
// by upsertVolumeOMAPSingleLeaf when entries don't fit in one block.
//
// Plan:
//  1. Allocate two fresh paddrs P_L, P_R (both PHYSICAL).
//  2. Split entries into halves; left half → leaf at P_L, right half → P_R.
//  3. Rewrite the original rootPaddr as a level-1 internal root with
//     two index entries: (left[0].oid, left[0].xid) → P_L,
//     (right[0].oid, right[0].xid) → P_R.
//  4. Mark P_L + P_R allocated in the chunk bitmap.
//
// The rootPaddr stays the same — apsb.omap_oid keeps pointing at the
// same physical block; only the block's CONTENT (leaf → internal
// root) changes.
func (v *Volume) promoteVolumeOMAPToTwoLevel(rootPaddr, rootXID uint64, entries []omapKV) error {
	bs := v.physicalBlockSize()
	if len(entries) < 2 {
		return fmt.Errorf("apfs: promote OMAP: need ≥ 2 entries, got %d", len(entries))
	}
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]

	// Allocate two fresh paddrs for the new leaves. Skip past the
	// existing format-time metadata (formatMetadataBlocks) and any
	// payload data the volume already references.
	leftPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: promote OMAP: alloc left leaf: %w", err)
	}
	rightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: promote OMAP: alloc right leaf: %w", err)
	}

	// Emit the two non-root leaves (no btreeInfo trailer; they're
	// non-root nodes of the OMAP B-tree).
	leftBlock := emitOMAPNonRootLeaf(leftPaddr, rootXID, omapKVsToEntries(left))
	rightBlock := emitOMAPNonRootLeaf(rightPaddr, rootXID, omapKVsToEntries(right))
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promote OMAP: write left leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promote OMAP: write right leaf: %w", err)
	}

	// Build the new internal root at rootPaddr (level=1) with 2 index
	// entries pointing at P_L and P_R.
	rootIndex := []omapIndexEntry{
		{oid: left[0].oid, xid: left[0].xid, childPaddr: leftPaddr},
		{oid: right[0].oid, xid: right[0].xid, childPaddr: rightPaddr},
	}
	rootBlock := emitOMAPInternalRoot(rootPaddr, rootXID, rootIndex, uint64(len(entries)), 3 /* root + 2 leaves */)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promote OMAP: write new root: %w", err)
	}
	return nil
}

func omapKVsToEntries(kvs []omapKV) []omapEntry {
	out := make([]omapEntry, len(kvs))
	for i, k := range kvs {
		out[i] = omapEntry{oid: k.oid, xid: k.xid, paddr: k.paddr}
	}
	return out
}

// upsertVolumeOMAPMultiLevel handles the case where the volume OMAP
// has already been promoted to a multi-level tree (root.level > 0).
// Descends through the index node(s) to find the target leaf, modifies
// it in place (re-emitting the leaf with the upserted entry), and
// promotes again if the leaf overflows.
//
// Limit: only handles a 2-level OMAP for now (root.level == 1). 3+
// level OMAP writes would need recursive index updates.
func (v *Volume) upsertVolumeOMAPMultiLevel(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, oid, xid, paddr uint64) error {
	bs := v.physicalBlockSize()
	if rootNode.level > 3 {
		return fmt.Errorf("apfs: volume OMAP level=%d > 3 not yet supported for writes", rootNode.level)
	}
	if rootNode.level == 3 {
		return v.upsertVolumeOMAPLevel3(rootPaddr, rawRoot, rootNode, oid, xid, paddr)
	}
	if rootNode.level == 2 {
		return v.upsertVolumeOMAPLevel2(rootPaddr, rawRoot, rootNode, oid, xid, paddr)
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return err
	}
	r, err := newNodeReader(rootNode, rootInfo)
	if err != nil {
		return err
	}
	// Find target leaf via "rightmost index entry with key ≤ (oid, xid)".
	// OMAP keys are 16 bytes (oid + xid), fixed-shape. compareOMAPKey
	// orders by (oid asc, xid asc) to match canonical convention.
	idx := 0
	for i := 0; i < r.EntryCount(); i++ {
		ik, err := r.keyAt(i)
		if err != nil {
			return err
		}
		iOID := binary.LittleEndian.Uint64(ik[0:8])
		iXID := binary.LittleEndian.Uint64(ik[8:16])
		if iOID < oid || (iOID == oid && iXID <= xid) {
			idx = i
		} else {
			break
		}
	}
	val, err := r.valueAt(idx)
	if err != nil {
		return err
	}
	leafPaddr := binary.LittleEndian.Uint64(val[0:8])
	rawLeaf, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: read OMAP leaf: %w", err)
	}
	leafNode, err := readBTreeNode(rawLeaf)
	if err != nil {
		return err
	}
	if !leafNode.IsLeaf() {
		return fmt.Errorf("apfs: descended OMAP child is not a leaf (level=%d)", leafNode.level)
	}
	// Non-root OMAP leaves don't carry their own btreeInfo trailer;
	// they share the tree-wide one from the root. Pass `rootInfo` so
	// newNodeReader knows the key/val sizes (16/16).
	lr, err := newNodeReader(leafNode, rootInfo)
	if err != nil {
		return err
	}
	entries := make([]omapKV, 0, lr.EntryCount()+1)
	for i := 0; i < lr.EntryCount(); i++ {
		k, err := lr.keyAt(i)
		if err != nil {
			return err
		}
		v, err := lr.valueAt(i)
		if err != nil {
			return err
		}
		entries = append(entries, omapKV{
			oid:   binary.LittleEndian.Uint64(k[0:8]),
			xid:   binary.LittleEndian.Uint64(k[8:16]),
			paddr: binary.LittleEndian.Uint64(v[8:16]),
		})
	}
	entries = upsertOMAPEntry(entries, oid, xid, paddr)
	sortOMAPEntries(entries)
	// Non-root leaf capacity: headLen + TOC + entries + NO trailer.
	const omapLeafCapBytes = 56 + 448
	if 56+448+len(entries)*32 <= int(bs) {
		// Fits in the existing leaf — just rewrite it.
		leafBlock := emitOMAPNonRootLeaf(leafPaddr, leafNode.hdr.xid, omapKVsToEntries(entries))
		if _, err := v.c.w.WriteAt(leafBlock, int64(leafPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: write OMAP leaf: %w", err)
		}
		return v.refreshOMAPRootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}
	// Leaf overflow: split into two non-root leaves and insert a new
	// index entry into the level-1 root. Cap at level-1: ~122 children
	// (4096 - 56 - 576 - 40) / 28 — beyond that splitOMAPLeafAndInsertIndex
	// promotes the root to level-2 via promoteOMAPRootToLevel2.
	_ = omapLeafCapBytes
	return v.splitOMAPLeafAndInsertIndex(rootPaddr, rawRoot, rootNode, rootInfo,
		leafPaddr, leafNode.hdr.xid, entries)
}

// splitOMAPLeafAndInsertIndex splits the supplied entries between the
// existing leaf paddr (left half) and a freshly-allocated paddr (right
// half), then rewrites the level-1 root with one extra index entry
// pointing at the new leaf. When the root would itself overflow, the
// tree is promoted to level-2 in place at the same paddr.
func (v *Volume) splitOMAPLeafAndInsertIndex(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, rootInfo *btreeInfo, leafPaddr, leafXID uint64, entries []omapKV) error {
	bs := v.physicalBlockSize()
	if len(entries) < 2 {
		return fmt.Errorf("apfs: split OMAP leaf: too few entries (%d)", len(entries))
	}
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]

	rightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: split OMAP leaf: alloc right: %w", err)
	}
	leftBlock := emitOMAPNonRootLeaf(leafPaddr, leafXID, omapKVsToEntries(left))
	rightBlock := emitOMAPNonRootLeaf(rightPaddr, leafXID, omapKVsToEntries(right))
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: split OMAP leaf: write left: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: split OMAP leaf: write right: %w", err)
	}

	// Read the level-1 root's existing index entries, then insert a
	// new entry for the right-half leaf in sorted order.
	r, err := newNodeReader(rootNode, rootInfo)
	if err != nil {
		return err
	}
	indexEntries := make([]omapIndexEntry, 0, r.EntryCount()+1)
	for i := 0; i < r.EntryCount(); i++ {
		ik, kerr := r.keyAt(i)
		if kerr != nil {
			return kerr
		}
		iv, verr := r.valueAt(i)
		if verr != nil {
			return verr
		}
		curPaddr := binary.LittleEndian.Uint64(iv[0:8])
		curOID := binary.LittleEndian.Uint64(ik[0:8])
		curXID := binary.LittleEndian.Uint64(ik[8:16])
		// The split leaf is the one whose paddr matches `leafPaddr`.
		// Update its key to left[0] so it stays consistent (typically
		// already correct because left[0] equals the old index key).
		if curPaddr == leafPaddr {
			curOID = left[0].oid
			curXID = left[0].xid
		}
		indexEntries = append(indexEntries, omapIndexEntry{
			oid:        curOID,
			xid:        curXID,
			childPaddr: curPaddr,
		})
	}
	indexEntries = append(indexEntries, omapIndexEntry{
		oid:        right[0].oid,
		xid:        right[0].xid,
		childPaddr: rightPaddr,
	})
	sortOMAPIndexEntries(indexEntries)

	// Capacity check: the level-1 root has ~122 child slots before
	// itself overflowing. Beyond that we promote to level-2.
	if len(indexEntries) > omapInternalRootCap {
		return v.promoteOMAPRootToLevel2(rootPaddr, rootNode.hdr.xid, indexEntries)
	}

	// Walk every leaf to recompute total key/node counts (fsck strict).
	totalKeys := uint64(0)
	for _, e := range indexEntries {
		raw, rerr := v.c.readBlock(e.childPaddr)
		if rerr != nil {
			return rerr
		}
		n, nerr := readBTreeNode(raw)
		if nerr != nil {
			return nerr
		}
		totalKeys += uint64(n.nKeys)
	}
	nodeCount := uint64(len(indexEntries) + 1)
	rootBlock := emitOMAPInternalRoot(rootPaddr, rootNode.hdr.xid, indexEntries, totalKeys, nodeCount)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: split OMAP leaf: rewrite root: %w", err)
	}
	return nil
}

// sortOMAPIndexEntries sorts by (oid asc, xid asc), matching the
// canonical OMAP key order used by upsert / lookup.
func sortOMAPIndexEntries(entries []omapIndexEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0; j-- {
			a, b := entries[j-1], entries[j]
			if a.oid < b.oid || (a.oid == b.oid && a.xid <= b.xid) {
				break
			}
			entries[j-1], entries[j] = b, a
		}
	}
}

// promoteOMAPRootToLevel2 converts a level-1 root that just overflowed
// into a level-2 root in place at `rootPaddr`. The supplied
// `indexEntries` are the (already sorted) child references that would
// have populated the level-1 root; they are split into two halves,
// each written as a level-1 non-root internal at a freshly-allocated
// paddr. The original `rootPaddr` is then rewritten as a level-2 root
// holding 2 index entries pointing at those level-1 internals.
//
// The level-2 root keeps the original APSB-pointed paddr so the
// volume OMAP's om_tree_oid does not need to change.
func (v *Volume) promoteOMAPRootToLevel2(rootPaddr, rootXID uint64, indexEntries []omapIndexEntry) error {
	bs := v.physicalBlockSize()
	if len(indexEntries) < 2 {
		return fmt.Errorf("apfs: OMAP level-2 promote: too few entries (%d)", len(indexEntries))
	}
	sortOMAPIndexEntries(indexEntries)
	mid := len(indexEntries) / 2
	left := indexEntries[:mid]
	right := indexEntries[mid:]

	leftPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP level-2 promote: alloc left: %w", err)
	}
	rightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP level-2 promote: alloc right: %w", err)
	}
	leftBlock := emitOMAPInternalNonRoot(leftPaddr, rootXID, left, 1)
	rightBlock := emitOMAPInternalNonRoot(rightPaddr, rootXID, right, 1)
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-2 promote: write left: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-2 promote: write right: %w", err)
	}

	// Walk every level-0 leaf under both halves to recompute tree-wide
	// totals (fsck strict cross-check).
	totalKeys := uint64(0)
	leafCount := uint64(0)
	for _, e := range indexEntries {
		raw, rerr := v.c.readBlock(e.childPaddr)
		if rerr != nil {
			return fmt.Errorf("apfs: OMAP level-2 promote: read leaf %d: %w", e.childPaddr, rerr)
		}
		n, nerr := readBTreeNode(raw)
		if nerr != nil {
			return nerr
		}
		totalKeys += uint64(n.nKeys)
		leafCount++
	}
	// Node count: 1 (level-2 root) + 2 (level-1 non-root internals) + leafCount.
	nodeCount := uint64(1) + 2 + leafCount

	rootIdx := []omapIndexEntry{
		{oid: left[0].oid, xid: left[0].xid, childPaddr: leftPaddr},
		{oid: right[0].oid, xid: right[0].xid, childPaddr: rightPaddr},
	}
	rootBlock := emitOMAPInternalRootAtLevel(rootPaddr, rootXID, rootIdx, 2, totalKeys, nodeCount)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP level-2 promote: write root: %w", err)
	}
	return nil
}

// upsertVolumeOMAPLevel2 descends a level-2 OMAP: pick the level-1
// internal child whose key range covers (oid, xid), then pick the
// level-0 leaf under it, rewrite the leaf in place. When the leaf
// overflows, split it and add an index entry to the level-1 internal;
// when the level-1 internal overflows, split it and add an index
// entry to the level-2 root; if the level-2 root would itself
// overflow, return an error (level-3 promotion deferred).
func (v *Volume) upsertVolumeOMAPLevel2(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, oid, xid, paddr uint64) error {
	bs := v.physicalBlockSize()
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return err
	}
	rootIdx, err := readOMAPInternalIndex(rootNode, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L2 root index: %w", err)
	}
	rIdx := pickOMAPChildIndex(rootIdx, oid, xid)
	l1Paddr := rootIdx[rIdx].childPaddr
	rawL1, err := v.c.readBlock(l1Paddr)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L2 read L1: %w", err)
	}
	l1Node, err := readBTreeNode(rawL1)
	if err != nil {
		return err
	}
	if l1Node.IsLeaf() || l1Node.level != 1 {
		return fmt.Errorf("apfs: OMAP L2 descend: child level=%d, want 1", l1Node.level)
	}
	// Non-root internals share the tree-wide info from the root.
	l1Idx, err := readOMAPInternalIndex(l1Node, rootInfo)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L1 internal index: %w", err)
	}
	lIdx := pickOMAPChildIndex(l1Idx, oid, xid)
	leafPaddr := l1Idx[lIdx].childPaddr
	rawLeaf, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: OMAP L2 read leaf: %w", err)
	}
	leafNode, err := readBTreeNode(rawLeaf)
	if err != nil {
		return err
	}
	if !leafNode.IsLeaf() {
		return fmt.Errorf("apfs: OMAP L2 descend: leaf has level=%d", leafNode.level)
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
	if 56+448+len(entries)*32 <= int(bs) {
		// Fits — just rewrite the leaf and refresh root counts.
		leafBlock := emitOMAPNonRootLeaf(leafPaddr, leafNode.hdr.xid, omapKVsToEntries(entries))
		if _, err := v.c.w.WriteAt(leafBlock, int64(leafPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: OMAP L2 write leaf: %w", err)
		}
		return v.refreshOMAPLevel2RootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}
	// Leaf overflow: split + add index entry to the level-1 internal.
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]
	rightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP L2 alloc split: %w", err)
	}
	leftBlock := emitOMAPNonRootLeaf(leafPaddr, leafNode.hdr.xid, omapKVsToEntries(left))
	rightBlock := emitOMAPNonRootLeaf(rightPaddr, leafNode.hdr.xid, omapKVsToEntries(right))
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr*bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return err
	}
	// Update the level-1 internal: replace the entry for leafPaddr with
	// left[0]'s key, then add a new entry for right[0]+rightPaddr.
	newL1 := make([]omapIndexEntry, 0, len(l1Idx)+1)
	for _, e := range l1Idx {
		if e.childPaddr == leafPaddr {
			newL1 = append(newL1, omapIndexEntry{oid: left[0].oid, xid: left[0].xid, childPaddr: leafPaddr})
		} else {
			newL1 = append(newL1, e)
		}
	}
	newL1 = append(newL1, omapIndexEntry{oid: right[0].oid, xid: right[0].xid, childPaddr: rightPaddr})
	sortOMAPIndexEntries(newL1)

	if len(newL1) <= omapInternalRootCap {
		// Rewrite the level-1 internal in place; refresh root counts.
		l1Block := emitOMAPInternalNonRoot(l1Paddr, l1Node.hdr.xid, newL1, 1)
		if _, err := v.c.w.WriteAt(l1Block, int64(l1Paddr*bs)); err != nil {
			return err
		}
		return v.refreshOMAPLevel2RootCounts(rootPaddr, rawRoot, rootNode, rootInfo)
	}
	// Level-1 internal overflow: split it, add a new entry to the L2 root.
	l1Mid := len(newL1) / 2
	l1Left := newL1[:l1Mid]
	l1Right := newL1[l1Mid:]
	newL1RightPaddr, _, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: OMAP L2 alloc L1 split: %w", err)
	}
	l1LeftBlock := emitOMAPInternalNonRoot(l1Paddr, l1Node.hdr.xid, l1Left, 1)
	l1RightBlock := emitOMAPInternalNonRoot(newL1RightPaddr, l1Node.hdr.xid, l1Right, 1)
	if _, err := v.c.w.WriteAt(l1LeftBlock, int64(l1Paddr*bs)); err != nil {
		return err
	}
	if _, err := v.c.w.WriteAt(l1RightBlock, int64(newL1RightPaddr*bs)); err != nil {
		return err
	}
	newRoot := make([]omapIndexEntry, 0, len(rootIdx)+1)
	for _, e := range rootIdx {
		if e.childPaddr == l1Paddr {
			newRoot = append(newRoot, omapIndexEntry{oid: l1Left[0].oid, xid: l1Left[0].xid, childPaddr: l1Paddr})
		} else {
			newRoot = append(newRoot, e)
		}
	}
	newRoot = append(newRoot, omapIndexEntry{oid: l1Right[0].oid, xid: l1Right[0].xid, childPaddr: newL1RightPaddr})
	sortOMAPIndexEntries(newRoot)
	if len(newRoot) > omapInternalRootCap {
		// Level-2 root overflow → promote to level 3. The cascade
		// above already wrote both halves of the L1 internals and
		// produced `newRoot` (the L2-index that no longer fits in a
		// single root). promoteOMAPRootToLevel3 splits `newRoot`,
		// allocates two L2 non-root internals at fresh paddrs,
		// emits each, and rewrites the OMAP root paddr as a
		// level-3 root with two index entries pointing to those L2
		// internals — same convention as promoteOMAPRootToLevel2,
		// one layer deeper.
		return v.promoteOMAPRootToLevel3(rootPaddr, rootNode.hdr.xid, newRoot)
	}
	// Walk every leaf to recompute tree-wide totals.
	totalKeys, nodeCount, err := v.scanOMAPLevel2Counts(newRoot)
	if err != nil {
		return err
	}
	rootBlock := emitOMAPInternalRootAtLevel(rootPaddr, rootNode.hdr.xid, newRoot, 2, totalKeys, nodeCount)
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: OMAP L2 write root: %w", err)
	}
	return nil
}

// readOMAPInternalIndex decodes an OMAP internal node's index entries.
// Works for both the level-1 root and level-1 / level-2 non-root
// internals — they all use the same kvoff fixed-shape layout with
// 16-byte keys and 8-byte child paddrs.
func readOMAPInternalIndex(n *btreeNode, info *btreeInfo) ([]omapIndexEntry, error) {
	r, err := newNodeReader(n, info)
	if err != nil {
		return nil, err
	}
	out := make([]omapIndexEntry, 0, r.EntryCount())
	for i := 0; i < r.EntryCount(); i++ {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return nil, kerr
		}
		val, verr := r.valueAt(i)
		if verr != nil {
			return nil, verr
		}
		out = append(out, omapIndexEntry{
			oid:        binary.LittleEndian.Uint64(k[0:8]),
			xid:        binary.LittleEndian.Uint64(k[8:16]),
			childPaddr: binary.LittleEndian.Uint64(val[0:8]),
		})
	}
	return out, nil
}

// pickOMAPChildIndex returns the index of the rightmost entry whose
// key ≤ (oid, xid). Matches the OMAP descent convention used by
// omapLookupInNode.
func pickOMAPChildIndex(entries []omapIndexEntry, oid, xid uint64) int {
	idx := 0
	for i, e := range entries {
		if e.oid < oid || (e.oid == oid && e.xid <= xid) {
			idx = i
		} else {
			break
		}
	}
	return idx
}

// scanOMAPLevel2Counts walks every level-0 leaf under each level-1
// internal child and returns (totalKeys, totalNodeCount) for the
// tree, used to refresh the level-2 root's btreeInfo trailer.
func (v *Volume) scanOMAPLevel2Counts(rootIdx []omapIndexEntry) (uint64, uint64, error) {
	totalKeys := uint64(0)
	nodeCount := uint64(1) // the level-2 root
	rootInfo, err := readRootBTreeInfoFor(v, rootIdx)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range rootIdx {
		raw, rerr := v.c.readBlock(e.childPaddr)
		if rerr != nil {
			return 0, 0, rerr
		}
		l1Node, nerr := readBTreeNode(raw)
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
	return totalKeys, nodeCount, nil
}

// readRootBTreeInfoFor returns the tree-wide btreeInfo descriptor by
// reading the volume OMAP's root. The level-2 helpers need this when
// they walk non-root internals (which don't carry their own trailer).
func readRootBTreeInfoFor(v *Volume, _ []omapIndexEntry) (*btreeInfo, error) {
	if v.volOmap == nil || v.volOmap.treeOID == 0 {
		return nil, fmt.Errorf("apfs: OMAP info: no volume omap")
	}
	raw, err := v.c.readBlock(v.volOmap.treeOID)
	if err != nil {
		return nil, err
	}
	return readRootBTreeInfo(raw)
}

// refreshOMAPLevel2RootCounts rewrites the level-2 root's btreeInfo
// trailer (totalKeys + nodeCount) after a deeper-level mutation that
// changed leaf entry counts but kept the root index entries
// unchanged (the common case: leaf rewrite or level-1 internal
// rewrite without splitting).
func (v *Volume) refreshOMAPLevel2RootCounts(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, rootInfo *btreeInfo) error {
	bs := v.physicalBlockSize()
	rootIdx, err := readOMAPInternalIndex(rootNode, rootInfo)
	if err != nil {
		return err
	}
	totalKeys, nodeCount, err := v.scanOMAPLevel2Counts(rootIdx)
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
		return fmt.Errorf("apfs: refresh OMAP L2 root counts: %w", err)
	}
	return nil
}

// refreshOMAPRootCounts walks every child leaf via the level-1 root's
// index entries, sums the per-leaf entry counts, and rewrites the
// root's btreeInfo trailer (bt_key_count + bt_node_count). The root's
// flags / table_space / TOC entries / keys / values are preserved
// byte-for-byte; only the trailer + obj_phys cksum change.
func (v *Volume) refreshOMAPRootCounts(rootPaddr uint64, rawRoot []byte, rootNode *btreeNode, rootInfo *btreeInfo) error {
	bs := v.physicalBlockSize()
	r, err := newNodeReader(rootNode, rootInfo)
	if err != nil {
		return err
	}
	totalKeys := uint64(0)
	for i := 0; i < r.EntryCount(); i++ {
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		childPaddr := binary.LittleEndian.Uint64(val[0:8])
		childRaw, err := v.c.readBlock(childPaddr)
		if err != nil {
			return err
		}
		childNode, err := readBTreeNode(childRaw)
		if err != nil {
			return err
		}
		totalKeys += uint64(childNode.nKeys)
	}
	nodeCount := uint64(r.EntryCount() + 1) // root + each child
	out := make([]byte, len(rawRoot))
	copy(out, rawRoot)
	bi := out[len(out)-btreeInfoSize:]
	binary.LittleEndian.PutUint64(bi[24:32], totalKeys)
	binary.LittleEndian.PutUint64(bi[32:40], nodeCount)
	sealBlock(out)
	if _, err := v.c.w.WriteAt(out, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: refresh OMAP root counts: %w", err)
	}
	return nil
}

// omapIndexEntry is one (key, child_paddr) pair in an internal OMAP
// node. The child is identified by paddr (PHYSICAL — OMAP nodes are
// stored at fixed paddrs, not OMAP-resolved).
type omapIndexEntry struct {
	oid, xid, childPaddr uint64
}

// emitOMAPNonRootLeaf writes a non-root OMAP leaf block (no btreeInfo
// trailer). Same kvoff fixed-shape layout as the regular OMAP leaf
// but without the trailer at the end.
func emitOMAPNonRootLeaf(ownPaddr, xid uint64, entries []omapEntry) []byte {
	const blockSize = 4096
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeOMAP), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagLeaf | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	const omapTOCLen uint16 = 448
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], omapTOCLen)
	keyLen := uint16(len(entries) * 16)
	valLen := uint16(len(entries) * 16)
	const headLen = 56
	freeLen := uint16(blockSize - headLen - int(omapTOCLen) - int(keyLen) - int(valLen))
	binary.LittleEndian.PutUint16(block[off+12:off+14], keyLen)
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(omapTOCLen)
	valBaseEnd := blockSize // non-root: no trailer, val_end = blockSize
	for i, e := range entries {
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], uint16(i*16))
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], uint16((i+1)*16))
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], e.xid)
		val := block[valBaseEnd-(i+1)*16 : valBaseEnd-i*16]
		binary.LittleEndian.PutUint32(val[0:4], 0)
		binary.LittleEndian.PutUint32(val[4:8], 4096)
		binary.LittleEndian.PutUint64(val[8:16], e.paddr)
	}
	sealBlock(block)
	return block
}

// emitOMAPInternalNonRoot writes a non-root OMAP internal node at the
// given level (≥1). Same kvoff layout as the level-1 root but without
// the btreeInfo trailer (non-root nodes share the tree-wide trailer
// from the root). Reserves the 576-byte table_space the kext uses for
// internal nodes (fsck rejects 448 at level≥1).
func emitOMAPInternalNonRoot(ownPaddr, xid uint64, entries []omapIndexEntry, level uint16) []byte {
	const blockSize = 4096
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTreeNode, uint32(objTypeOMAP), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], level)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	const omapInternalTOCLen uint16 = 576
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], omapInternalTOCLen)
	keyLen := uint16(len(entries) * 16)
	const internalValSize = 8
	valLen := uint16(len(entries) * internalValSize)
	const headLen = 56
	freeLen := uint16(blockSize - headLen - int(omapInternalTOCLen) - int(keyLen) - int(valLen))
	binary.LittleEndian.PutUint16(block[off+12:off+14], keyLen)
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(omapInternalTOCLen)
	valBaseEnd := blockSize // non-root: no trailer.
	for i, e := range entries {
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], uint16(i*16))
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], uint16((i+1)*internalValSize))
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], e.xid)
		val := block[valBaseEnd-(i+1)*internalValSize : valBaseEnd-i*internalValSize]
		binary.LittleEndian.PutUint64(val[0:8], e.childPaddr)
	}
	sealBlock(block)
	return block
}

// emitOMAPInternalRoot writes a level-1 OMAP root, byte-matching what
// Apple's apfs.kext produces for a multi-level volume OMAP. Verified
// via byte-diff against a kext-populated container
// (`TestProbe_AppleMultiLevelOMAP`):
//
//   - flags = ROOT | FIXED_KV_SIZE (0x05)
//   - table_space = (0, 576) — NOT the leaf's 448. fsck rejects 448
//     at level=1 with `invalid btn_table_space (0, 448), given
//     btn_flags (0x5)`.
//   - kvoff TOC: 4 bytes per entry (key.off uint16, val.off uint16).
//     key.off increments by 16 (bt_key_size); val.off increments by
//     8 (the internal-node value size — NOT the trailer's
//     bt_val_size of 16).
//   - Internal-node values: 8 bytes each, packed end-to-end backward
//     from val_end. NOT 16-byte slots with padding.
//   - Trailer: bt_key_size = bt_val_size = 16 (leaf-side; readers
//     override to 8 for non-leaf nodes via `r.node.IsLeaf()`).
func emitOMAPInternalRoot(ownPaddr, xid uint64, entries []omapIndexEntry, treeKeyCount, treeNodeCount uint64) []byte {
	return emitOMAPInternalRootAtLevel(ownPaddr, xid, entries, 1, treeKeyCount, treeNodeCount)
}

// emitOMAPInternalRootAtLevel writes an OMAP root internal node at the
// given level (1 for level-0-leaves-only, 2 when each child is itself
// a level-1 internal). table_space, kvoff layout, and trailer fields
// are identical to the level=1 case; only the level header field
// changes.
func emitOMAPInternalRootAtLevel(ownPaddr, xid uint64, entries []omapIndexEntry, level uint16, treeKeyCount, treeNodeCount uint64) []byte {
	const blockSize = 4096
	block := make([]byte, blockSize)
	encodeObjHeader(block, ownPaddr, xid, objTypeBTree, uint32(objTypeOMAP), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], level)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	// Apple's level=1 OMAP root reservation: 576 bytes (vs 448 for
	// leaves). Verified by byte-diff.
	const omapInternalTOCLen uint16 = 576
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], omapInternalTOCLen)
	keyLen := uint16(len(entries) * 16)
	const internalValSize = 8
	valLen := uint16(len(entries) * internalValSize)
	const headLen = 56
	freeLen := uint16(blockSize - headLen - int(omapInternalTOCLen) - int(keyLen) - int(valLen) - btreeInfoSize)
	binary.LittleEndian.PutUint16(block[off+12:off+14], keyLen)
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(omapInternalTOCLen)
	valBaseEnd := blockSize - btreeInfoSize
	for i, e := range entries {
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], uint16(i*16))
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], uint16((i+1)*internalValSize))
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], e.xid)
		val := block[valBaseEnd-(i+1)*internalValSize : valBaseEnd-i*internalValSize]
		binary.LittleEndian.PutUint64(val[0:8], e.childPaddr)
	}
	bi := block[blockSize-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical)
	binary.LittleEndian.PutUint32(bi[4:8], blockSize)
	binary.LittleEndian.PutUint32(bi[8:12], 16)
	binary.LittleEndian.PutUint32(bi[12:16], 16)
	binary.LittleEndian.PutUint32(bi[16:20], 16)
	binary.LittleEndian.PutUint32(bi[20:24], 16)
	binary.LittleEndian.PutUint64(bi[24:32], treeKeyCount)
	binary.LittleEndian.PutUint64(bi[32:40], treeNodeCount)
	sealBlock(block)
	return block
}

// emitFSTreeInternalExplicit writes an internal (non-leaf) FS-tree node.
// The "values" supplied are 8-byte child-OID payloads (the caller
// constructs them via encodeChildOIDValue). isRoot decides whether the
// btreeInfo trailer is appended (only root nodes carry it).
//
// treeLongestKey / treeLongestVal, when non-zero, override the locally-
// computed maxima. fsck's `bt_longest_key` cross-check considers the
// MAX across every key in the tree (including descendant leaves), not
// just this node — so callers that emit an internal root must pass in
// the tree-wide maxima from a leaf scan. Pass 0 to fall back to local.
//
// treeKeyCount / treeNodeCount, similarly, are tree-wide totals fsck
// validates against the trailer's `bt_key_count` / `bt_node_count`.
// Pass 0 to write 0 (the leaf path's "I am a single-node tree" form).
func emitFSTreeInternalExplicit(entries []fsLeafKV, blockSize int, oid, xid uint64, level uint16, isRoot bool, treeLongestKey, treeLongestVal uint32, treeKeyCount, treeNodeCount uint64) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, oid, xid, objTypeBTree, uint32(objTypeFSTree), objStorageVirtual)
	off := objPhysSize
	flags := uint16(0)
	if isRoot {
		flags |= btnFlagRoot
	}
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
	endOfData := blockSize
	if isRoot {
		endOfData -= btreeInfoSize
	}
	keyOff := 0
	valCur := 0
	for i, e := range entries {
		need := dataStart + tocLen + keyOff + len(e.key)
		if need > endOfData-valCur-len(e.val) {
			return nil, fmt.Errorf("apfs: emitFSTreeInternal: node overflow at entry %d", i)
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
	if isRoot {
		longestKey, longestVal := uint32(0), uint32(0)
		for _, e := range entries {
			if uint32(len(e.key)) > longestKey {
				longestKey = uint32(len(e.key))
			}
			if uint32(len(e.val)) > longestVal {
				longestVal = uint32(len(e.val))
			}
		}
		if treeLongestKey > longestKey {
			longestKey = treeLongestKey
		}
		if treeLongestVal > longestVal {
			longestVal = treeLongestVal
		}
		bi := block[blockSize-btreeInfoSize:]
		binary.LittleEndian.PutUint32(bi[0:4], btreeFlagKVNonAligned)
		binary.LittleEndian.PutUint32(bi[4:8], uint32(blockSize))
		binary.LittleEndian.PutUint32(bi[16:20], longestKey)
		binary.LittleEndian.PutUint32(bi[20:24], longestVal)
		binary.LittleEndian.PutUint64(bi[24:32], treeKeyCount)
		binary.LittleEndian.PutUint64(bi[32:40], treeNodeCount)
	}
	sealBlock(block)
	return block, nil
}

// encodeChildOIDValue returns the 8-byte value stored as an internal
// (non-leaf) FS-tree node's value: a bare uint64 child OID.
func encodeChildOIDValue(oid uint64) []byte {
	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, oid)
	return v
}

// emitFSTreeLeafNonRoot is emitFSTreeLeafExplicit but for non-root
// leaves (no btreeInfo trailer). Used when we split a single leaf into
// two siblings under a fresh internal root.
func emitFSTreeLeafNonRoot(entries []fsLeafKV, blockSize int, oid, xid uint64) ([]byte, error) {
	sortLeafEntries(entries)
	block := make([]byte, blockSize)
	encodeObjHeader(block, oid, xid, objTypeBTreeNode, uint32(objTypeFSTree), objStorageVirtual)
	off := objPhysSize
	flags := btnFlagLeaf
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
			return nil, fmt.Errorf("apfs: emitFSTreeLeafNonRoot: leaf overflow at entry %d", i)
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

// leafFitsCheck returns true iff the supplied entries can be encoded
// into a non-root FS-tree leaf of the given size. It mirrors the
// capacity arithmetic in emitFSTreeLeafNonRoot without producing the
// block.
func leafFitsCheck(entries []fsLeafKV, blockSize int, isRoot bool) bool {
	tocLen := len(entries) * 8
	if tocLen < 64 {
		tocLen = 64
	}
	headLen := objPhysSize + btreeNodeHeaderSize
	tail := 0
	if isRoot {
		tail = btreeInfoSize
	}
	used := 0
	for _, e := range entries {
		used += len(e.key) + len(e.val)
	}
	return headLen+tocLen+used+tail <= blockSize
}

// allocateNewTreeNode reserves a fresh paddr + oid pair for a new
// FS-tree node, marks the paddr allocated in the chunk bitmap, and
// returns them.
func (v *Volume) allocateNewTreeNode() (paddr, oid uint64, err error) {
	paddr, err = v.nextFreeBlock()
	if err != nil {
		return 0, 0, err
	}
	v.allocCursor = paddr + 1
	if err := v.c.markBlocksAllocated(paddr, 1); err != nil {
		return 0, 0, err
	}
	if err := v.bumpFSAllocCount(1); err != nil {
		return 0, 0, err
	}
	oid = v.c.allocVirtualOID()
	return paddr, oid, nil
}

// splitRootLeafAndWrite handles the "single leaf overflow" case during
// CreateFile. allEntries is the merged (existing + new) entry set;
// leafXID is the xid the new nodes should carry (matches the existing
// root's xid for in-place edit semantics).
func (v *Volume) splitRootLeafAndWrite(allEntries []fsLeafKV, rootPaddr, leafXID uint64) error {
	bs := v.physicalBlockSize()
	sortLeafEntries(allEntries)
	// Partition entries by cumulative byte size; aim for the midpoint.
	totalBytes := 0
	for _, e := range allEntries {
		totalBytes += 8 + len(e.key) + len(e.val)
	}
	splitBytes := totalBytes / 2
	cum := 0
	splitIdx := len(allEntries) / 2
	for i, e := range allEntries {
		cum += 8 + len(e.key) + len(e.val)
		if cum >= splitBytes {
			splitIdx = i + 1
			break
		}
	}
	if splitIdx == 0 {
		splitIdx = 1
	}
	if splitIdx >= len(allEntries) {
		splitIdx = len(allEntries) - 1
	}
	left := allEntries[:splitIdx]
	right := allEntries[splitIdx:]
	if !leafFitsCheck(left, int(bs), false) || !leafFitsCheck(right, int(bs), false) {
		return fmt.Errorf("apfs: splitRootLeaf: split halves still overflow (left=%d, right=%d, total=%d entries)",
			len(left), len(right), len(allEntries))
	}

	leftPaddr, leftOID, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: alloc left: %w", err)
	}
	rightPaddr, rightOID, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: alloc right: %w", err)
	}

	leftBlock, err := emitFSTreeLeafNonRoot(left, int(bs), leftOID, leafXID)
	if err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: emit left: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: write left at paddr %d: %w", leftPaddr, err)
	}
	rightBlock, err := emitFSTreeLeafNonRoot(right, int(bs), rightOID, leafXID)
	if err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: write right at paddr %d: %w", rightPaddr, err)
	}

	// Register both new leaves in the volume OMAP.
	if err := v.upsertVolumeOMAPEntry(leftOID, leafXID, leftPaddr); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: omap left: %w", err)
	}
	if err := v.upsertVolumeOMAPEntry(rightOID, leafXID, rightPaddr); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: omap right: %w", err)
	}

	// Build the new internal root: 2 entries pointing at the two leaves.
	// Index-node key for entry i = the smallest key of leaf i (Apple's
	// canonical convention; the descent uses "rightmost entry with key
	// ≤ target", which requires the index key to be the leaf's minimum).
	rootEntries := []fsLeafKV{
		{key: append([]byte(nil), left[0].key...), val: encodeChildOIDValue(leftOID)},
		{key: append([]byte(nil), right[0].key...), val: encodeChildOIDValue(rightOID)},
	}
	// Tree-wide longest key/val: max over allEntries (the union of both
	// new leaves) plus the root's own keys. Tree-wide key_count = sum
	// of leaf entries; node_count = root + 2 leaves = 3.
	longestKey, longestVal := uint32(0), uint32(0)
	for _, e := range allEntries {
		if uint32(len(e.key)) > longestKey {
			longestKey = uint32(len(e.key))
		}
		if uint32(len(e.val)) > longestVal {
			longestVal = uint32(len(e.val))
		}
	}
	rootBlock, err := emitFSTreeInternalExplicit(rootEntries, int(bs), v.apsb.rootTreeOID, leafXID, 1, true, longestKey, longestVal, uint64(len(allEntries)), 3)
	if err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: emit new root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: write new root at paddr %d: %w", rootPaddr, err)
	}
	if err := v.reloadRoot(rootPaddr); err != nil {
		return fmt.Errorf("apfs: splitRootLeaf: reload root: %w", err)
	}
	return nil
}

// computeTreeLongestKV scans every leaf entry in the FS-tree and
// returns the tree-wide maxima (longest key bytes, longest value bytes).
// Used to populate `bt_longest_key` / `bt_longest_val` on the root
// btreeInfo trailer; fsck cross-checks these against the actual tree
// content and rejects any value smaller than the true maximum.
//
// `extra` is a list of soon-to-be-inserted entries that the scan should
// also consider — useful when emitting a root before the matching leaf
// rewrite (or split) has gone to disk.
func (v *Volume) computeTreeLongestKV(extra []fsLeafKV) (uint32, uint32) {
	longestKey, longestVal := uint32(0), uint32(0)
	_ = v.traverseFSTree(func(k, val []byte) error {
		if uint32(len(k)) > longestKey {
			longestKey = uint32(len(k))
		}
		if uint32(len(val)) > longestVal {
			longestVal = uint32(len(val))
		}
		return nil
	})
	for _, e := range extra {
		if uint32(len(e.key)) > longestKey {
			longestKey = uint32(len(e.key))
		}
		if uint32(len(e.val)) > longestVal {
			longestVal = uint32(len(e.val))
		}
	}
	return longestKey, longestVal
}

// refreshRoot rebuilds the FS-tree root index node from the current
// state of its direct children. For a level-1 root the children are
// leaves and the index key is each leaf's first key. For a level-2+
// root the children are themselves internal nodes and the index key
// is each child internal node's leftmost subtree's first leaf key
// (i.e. the recursive descent of the leftmost path). When the root's
// would-be entries don't fit in a single 4 KiB block, this function
// PROMOTES the root one level via `promoteRoot` — splitting the
// children into two new internal nodes and emitting a new top-level
// root that points at them.
func (v *Volume) refreshRoot(rootPaddr uint64) error {
	if v.rootNode.IsLeaf() {
		return nil
	}
	bs := v.physicalBlockSize()
	// First sweep: prune any subtree whose every reachable leaf is
	// empty. Per-leaf deletes leave empty leaves in place (their
	// blocks aren't freed; the writer doesn't yet track FS-tree
	// frees), so without this pass `leftmostKeyInSubtree` would
	// stumble into one of them when rebuilding the root index. The
	// pruner rewrites internal nodes in place when their TOC changes,
	// so reload the in-memory root before reading it below.
	rootXIDForPrune := v.rootNode.hdr.xid
	if _, err := v.pruneEmptySubtreeChildren(rootPaddr, true, rootXIDForPrune); err != nil {
		return fmt.Errorf("apfs: refreshRoot: prune: %w", err)
	}
	if err := v.reloadRoot(rootPaddr); err != nil {
		return fmt.Errorf("apfs: refreshRoot: reload after prune: %w", err)
	}
	if v.rootNode.IsLeaf() {
		return nil
	}
	r, err := newNodeReader(v.rootNode, v.rootInfo)
	if err != nil {
		return err
	}
	rootEntries := make([]fsLeafKV, 0, r.EntryCount())
	for i := 0; i < r.EntryCount(); i++ {
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		childOID := binary.LittleEndian.Uint64(val[0:8])
		childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if err != nil {
			return fmt.Errorf("apfs: refreshRoot: resolve child %d: %w", childOID, err)
		}
		// A child subtree may be empty after a delete cascade — e.g.
		// `removeKeyFromLeaf` rewrites a leaf in place and the last
		// surviving entry was the one we just removed. The empty leaf
		// is still pointed at by the root index, but it carries no
		// keys, so `leftmostKeyInSubtree` would fail. Drop the empty
		// child from the rebuilt root index instead (the block is left
		// allocated for now; the writer does not yet track per-block
		// frees from the FS-tree itself).
		if isEmpty, ierr := v.isSubtreeEmpty(childPaddr); ierr != nil {
			return fmt.Errorf("apfs: refreshRoot: probe child %d: %w", childOID, ierr)
		} else if isEmpty {
			continue
		}
		// First key reachable through this child = leftmost key in its
		// subtree. For a leaf child it's just keyAt(0); for an internal
		// child we recurse via leftmostKeyInSubtree.
		firstKey, err := v.leftmostKeyInSubtree(childPaddr)
		if err != nil {
			return fmt.Errorf("apfs: refreshRoot: leftmost key for child %d: %w", childOID, err)
		}
		rootEntries = append(rootEntries, fsLeafKV{
			key: append([]byte(nil), firstKey...),
			val: encodeChildOIDValue(childOID),
		})
	}
	// Sort by key so the index stays in canonical FS-key order.
	sortLeafEntries(rootEntries)
	rootXID := v.rootNode.hdr.xid
	// All children turned out to be empty: collapse the root back to a
	// single empty leaf. This restores the invariant that the tree is
	// always traversable (the empty-leaf path through lookupFSTreeFirst
	// returns os.ErrNotExist) without leaving the root pointing at
	// stale, empty internal subtrees.
	if len(rootEntries) == 0 {
		emptyLeaf, err := emitFSTreeLeafExplicit(nil, int(bs), v.apsb.rootTreeOID, rootXID)
		if err != nil {
			return fmt.Errorf("apfs: refreshRoot: emit empty leaf: %w", err)
		}
		if _, werr := v.c.w.WriteAt(emptyLeaf, int64(rootPaddr*bs)); werr != nil {
			return fmt.Errorf("apfs: refreshRoot: write empty leaf: %w", werr)
		}
		return v.reloadRoot(rootPaddr)
	}
	longestKey, longestVal := v.computeTreeLongestKV(nil)
	keyCount, nodeCount, err := v.computeTreeCounts(rootEntries)
	if err != nil {
		return err
	}
	rootBlock, err := emitFSTreeInternalExplicit(rootEntries, int(bs), v.apsb.rootTreeOID, rootXID, v.rootNode.level, true, longestKey, longestVal, keyCount, nodeCount)
	if err == nil {
		if _, werr := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); werr != nil {
			return fmt.Errorf("apfs: refreshRoot: write: %w", werr)
		}
		return v.reloadRoot(rootPaddr)
	}
	// emitFSTreeInternalExplicit returns "node overflow" when the root
	// can't hold all child entries. Promote: split the entries into
	// two new internal nodes at level=current and emit a new root one
	// level higher pointing at them.
	if !isOverflowErr(err) {
		return fmt.Errorf("apfs: refreshRoot: emit: %w", err)
	}
	return v.promoteRoot(rootEntries, rootPaddr, rootXID, v.rootNode.level)
}

// pruneEmptySubtreeChildren rewrites the internal node at `paddr` so
// that its child-OID index no longer references any subtree whose
// every reachable leaf is empty. The traversal is post-order: each
// child is descended into first (so internal grandchildren are
// pruned before we judge whether their parent is "empty"), then the
// current node's TOC is rebuilt from the surviving children. Used by
// refreshRoot to clean up empty branches left behind by per-leaf
// deletes that exhaust an entire subtree.
//
// Returns true when, after pruning, the node itself has zero
// surviving entries (i.e. the entire subtree under `paddr` was
// empty). Callers that own this node should drop their reference to
// it in that case; the orphaned block is not reclaimed (the writer
// does not yet track per-block frees outside the spaceman).
func (v *Volume) pruneEmptySubtreeChildren(paddr uint64, isRoot bool, rootXID uint64) (allEmpty bool, err error) {
	bs := v.physicalBlockSize()
	raw, err := v.c.readBlock(paddr)
	if err != nil {
		return false, err
	}
	node, err := readBTreeNode(raw)
	if err != nil {
		return false, err
	}
	if node.IsLeaf() {
		return node.nKeys == 0, nil
	}
	var info *btreeInfo
	if isRoot {
		info, err = readRootBTreeInfo(raw)
		if err != nil {
			return false, err
		}
	}
	r, err := newNodeReader(node, info)
	if err != nil {
		return false, err
	}
	var survivors []fsLeafKV
	dirty := false
	for i := 0; i < r.EntryCount(); i++ {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return false, kerr
		}
		val, verr := r.valueAt(i)
		if verr != nil {
			return false, verr
		}
		childOID := binary.LittleEndian.Uint64(val[0:8])
		childPaddr, oerr := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if oerr != nil {
			return false, fmt.Errorf("apfs: prune: resolve child %d: %w", childOID, oerr)
		}
		// Recurse: prune the child's own empty subtrees first, then
		// decide whether to keep or drop the link from this node.
		childEmpty, perr := v.pruneEmptySubtreeChildren(childPaddr, false, rootXID)
		if perr != nil {
			return false, perr
		}
		if childEmpty {
			dirty = true
			continue
		}
		// Re-read the child's leftmost key — pruning grandchildren may
		// have shifted the minimum key on this child even though the
		// child itself isn't empty. Without this refresh the parent's
		// stored index key could be larger than the child's actual new
		// minimum, breaking binary-search descent.
		newLeftmost, lerr := v.leftmostKeyInSubtree(childPaddr)
		if lerr != nil {
			return false, fmt.Errorf("apfs: prune: leftmost in surviving child %d: %w", childOID, lerr)
		}
		if !bytesEqual(k, newLeftmost) {
			dirty = true
		}
		survivors = append(survivors, fsLeafKV{
			key: append([]byte(nil), newLeftmost...),
			val: append([]byte(nil), val[:8]...),
		})
	}
	if !dirty {
		return false, nil
	}
	if len(survivors) == 0 {
		// The non-root internal node lost every reference. Caller
		// will drop us from its TOC; we don't rewrite the block.
		if !isRoot {
			return true, nil
		}
		// Root case: collapse to an empty leaf so the tree remains
		// traversable. Caller (refreshRoot) handles the collapse, so
		// just return; the survivor list is already empty.
		return true, nil
	}
	sortLeafEntries(survivors)
	block, err := emitFSTreeInternalExplicit(survivors, int(bs), node.hdr.oid, rootXID, node.level, isRoot, 0, 0, 0, 0)
	if err != nil {
		return false, fmt.Errorf("apfs: prune: emit internal at level %d: %w", node.level, err)
	}
	if _, err := v.c.w.WriteAt(block, int64(paddr*bs)); err != nil {
		return false, fmt.Errorf("apfs: prune: write internal at level %d: %w", node.level, err)
	}
	return false, nil
}

// isSubtreeEmpty reports whether every leaf reachable from the
// subtree rooted at `paddr` carries zero keys. Used by refreshRoot to
// prune child entries whose payload has been entirely deleted, so the
// rebuilt root index doesn't reference an empty leaf or an internal
// node whose every descent ends at an empty leaf. Mirrors the
// leftmost-descent shape of `leftmostKeyInSubtree`; an internal node
// counts as empty only if EVERY child is empty (we recurse into all
// children at each level), which is the only configuration the writer
// can produce today.
func (v *Volume) isSubtreeEmpty(paddr uint64) (bool, error) {
	raw, err := v.c.readBlock(paddr)
	if err != nil {
		return false, err
	}
	node, err := readBTreeNode(raw)
	if err != nil {
		return false, err
	}
	if node.IsLeaf() {
		return node.nKeys == 0, nil
	}
	if node.nKeys == 0 {
		return true, nil
	}
	r, err := newNodeReader(node, nil)
	if err != nil {
		return false, err
	}
	for i := 0; i < r.EntryCount(); i++ {
		childOID, err := r.childOIDAt(i)
		if err != nil {
			return false, err
		}
		childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if err != nil {
			return false, err
		}
		empty, err := v.isSubtreeEmpty(childPaddr)
		if err != nil {
			return false, err
		}
		if !empty {
			return false, nil
		}
	}
	return true, nil
}

// leftmostKeyInSubtree returns the first key reachable through the
// subtree rooted at `paddr`. For a leaf paddr it's just the leaf's
// keyAt(0); for an internal node it's the leftmost child's leftmost
// key (recursive descent down the leftmost path).
func (v *Volume) leftmostKeyInSubtree(paddr uint64) ([]byte, error) {
	for {
		raw, err := v.c.readBlock(paddr)
		if err != nil {
			return nil, err
		}
		node, err := readBTreeNode(raw)
		if err != nil {
			return nil, err
		}
		if node.nKeys == 0 {
			return nil, fmt.Errorf("empty node at paddr %d", paddr)
		}
		r, err := newNodeReader(node, nil)
		if err != nil {
			return nil, err
		}
		if node.IsLeaf() {
			return r.keyAt(0)
		}
		// Internal node: descend via leftmost child.
		val, err := r.valueAt(0)
		if err != nil {
			return nil, err
		}
		childOID := binary.LittleEndian.Uint64(val[0:8])
		childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if err != nil {
			return nil, err
		}
		paddr = childPaddr
	}
}

// isOverflowErr reports whether err is an emitFSTreeInternal /
// emitFSTreeLeaf "node overflow" error. The emitter wraps these as
// `fmt.Errorf("...: node overflow at entry %d", ...)`; we string-match
// because the package doesn't export distinct error types yet.
func isOverflowErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for i := 0; i+len("node overflow") <= len(msg); i++ {
		if msg[i:i+len("node overflow")] == "node overflow" {
			return true
		}
	}
	for i := 0; i+len("leaf overflow") <= len(msg); i++ {
		if msg[i:i+len("leaf overflow")] == "leaf overflow" {
			return true
		}
	}
	return false
}

// promoteRoot handles the FS-tree root level promotion (level → level+1).
// Triggered by refreshRoot when the root's would-be entries don't fit
// in a single block. Distributes `entries` (the old root's children
// indices) between two NEW internal nodes at the same level the old
// root was at, then re-emits the root block at `rootPaddr` carrying
// just two index entries pointing at those new nodes (level + 1).
//
// Volume OMAP gets two new entries (one per new internal node);
// `nx_next_oid` is bumped. Old root paddr stays the same — only its
// content changes — so the volume OMAP entry for the FS-tree root oid
// doesn't move.
func (v *Volume) promoteRoot(entries []fsLeafKV, rootPaddr, leafXID uint64, oldLevel uint16) error {
	bs := v.physicalBlockSize()
	if len(entries) < 2 {
		return fmt.Errorf("apfs: promoteRoot: too few entries to split (%d)", len(entries))
	}
	// Callers from `modifyLeafAtPaddrAndInsert` build `entries` by
	// `readAllInternalEntries` + an in-place key update + an append, so
	// the slice is not guaranteed to be in canonical key order on entry.
	// `leftmostKeyInSubtree` below trusts that left[]/right[] are stored
	// in ascending key order on the new internal nodes, so the parent
	// index key we pick (the leftmost descendant) describes them
	// correctly. Sort once here so the index-midpoint split is
	// deterministic and the resulting subtrees are validly ordered.
	sortLeafEntries(entries)
	mid := len(entries) / 2
	left := entries[:mid]
	right := entries[mid:]

	leftPaddr, leftOID, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: alloc left: %w", err)
	}
	rightPaddr, rightOID, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: alloc right: %w", err)
	}

	leftBlock, err := emitFSTreeInternalExplicit(left, int(bs), leftOID, leafXID, oldLevel, false, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: emit left: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leftPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promoteRoot: write left: %w", err)
	}
	rightBlock, err := emitFSTreeInternalExplicit(right, int(bs), rightOID, leafXID, oldLevel, false, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promoteRoot: write right: %w", err)
	}
	if err := v.upsertVolumeOMAPEntry(leftOID, leafXID, leftPaddr); err != nil {
		return fmt.Errorf("apfs: promoteRoot: omap left: %w", err)
	}
	if err := v.upsertVolumeOMAPEntry(rightOID, leafXID, rightPaddr); err != nil {
		return fmt.Errorf("apfs: promoteRoot: omap right: %w", err)
	}

	// New root entries: each child's first index key (= the leftmost
	// reachable leaf key in that subtree).
	leftFirst, err := v.leftmostKeyInSubtree(leftPaddr)
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: leftmost in left: %w", err)
	}
	rightFirst, err := v.leftmostKeyInSubtree(rightPaddr)
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: leftmost in right: %w", err)
	}
	rootEntries := []fsLeafKV{
		{key: append([]byte(nil), leftFirst...), val: encodeChildOIDValue(leftOID)},
		{key: append([]byte(nil), rightFirst...), val: encodeChildOIDValue(rightOID)},
	}
	longestKey, longestVal := v.computeTreeLongestKV(nil)
	keyCount := uint64(0)
	_ = v.traverseFSTree(func(k, val []byte) error { keyCount++; return nil })
	// Node count: existing leaves + the 2 new internal nodes + new root
	// = walk each subtree to count nodes. For simplicity: estimate as
	// keyCount/14 leaves + 3 internal. fsck cross-checks via total node
	// count; a generous estimate avoids underflow.
	nodeCount := keyCount/14 + 3
	if nodeCount < 5 {
		nodeCount = 5
	}
	rootBlock, err := emitFSTreeInternalExplicit(rootEntries, int(bs), v.apsb.rootTreeOID, leafXID, oldLevel+1, true, longestKey, longestVal, keyCount, nodeCount)
	if err != nil {
		return fmt.Errorf("apfs: promoteRoot: emit new root: %w", err)
	}
	if _, err := v.c.w.WriteAt(rootBlock, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: promoteRoot: write new root: %w", err)
	}
	return v.reloadRoot(rootPaddr)
}

// computeTreeCounts walks every leaf in the FS-tree and returns
// (key_count, node_count) — the totals fsck stamps into the root's
// btreeInfo trailer. The caller passes the prospective new root index
// entries; node_count = 1 (root) + len(rootEntries) (one leaf per
// child pointer, since we don't yet support 3-level trees).
func (v *Volume) computeTreeCounts(rootEntries []fsLeafKV) (uint64, uint64, error) {
	keyCount := uint64(0)
	if err := v.traverseFSTree(func(k, val []byte) error {
		keyCount++
		return nil
	}); err != nil {
		return 0, 0, err
	}
	nodeCount := uint64(1) + uint64(len(rootEntries))
	return keyCount, nodeCount, nil
}

// childInfo records one (childKey, childOID, childPaddr) tuple decoded
// from an internal node — used by descendToLeafForKey when the caller
// needs to know which child a key descends into AND its physical paddr.
type childInfo struct {
	key   []byte
	oid   uint64
	paddr uint64
	idx   int // position in the parent's TOC
}

// internalNodeRef identifies one internal (non-leaf) node on the
// descent path from root to a leaf, plus the position within that
// node's TOC of the child we followed. Used by descent helpers that
// need to update the index keys all the way back up after a leaf
// split.
type internalNodeRef struct {
	paddr uint64 // physical address of the internal node
	oid   uint64 // virtual oid (volume-OMAP key)
	idx   int    // TOC index of the child we followed from this node
}

// descendToLeafPath returns the full chain of internal nodes traversed
// from the FS-tree root to the leaf that would hold `targetKey`. The
// path is returned root-first (path[0] = root, path[len-1] = the
// immediate parent of the leaf). The leaf itself is returned via
// `leafPaddr`/`leafOID`. Errors out when the tree is a single-leaf
// root (the caller should use the in-place / split-root path).
func (v *Volume) descendToLeafPath(targetKey []byte) (leafPaddr, leafOID uint64, path []internalNodeRef, err error) {
	if v.rootNode.IsLeaf() {
		return 0, 0, nil, fmt.Errorf("apfs: descend: tree is single-leaf")
	}
	// The root has no enclosing parent — we know its paddr from the
	// volume OMAP, but reuse the value that's already cached on the
	// container (apsb.rootTreeOID via omapLookup).
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("apfs: descend: resolve fs-tree root: %w", err)
	}
	curNode := v.rootNode
	curInfo := v.rootInfo
	curPaddr := rootPaddr
	curOID := v.apsb.rootTreeOID
	for !curNode.IsLeaf() {
		r, err := newNodeReader(curNode, curInfo)
		if err != nil {
			return 0, 0, nil, err
		}
		nKeys := r.EntryCount()
		if nKeys == 0 {
			return 0, 0, nil, fmt.Errorf("apfs: descend: empty index node at level %d", curNode.level)
		}
		idx := 0
		for i := 0; i < nKeys; i++ {
			k, kerr := r.keyAt(i)
			if kerr != nil {
				return 0, 0, nil, kerr
			}
			if compareFSKey(k, targetKey) <= 0 {
				idx = i
			} else {
				break
			}
		}
		childOID, err := r.childOIDAt(idx)
		if err != nil {
			return 0, 0, nil, err
		}
		childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("apfs: descend: resolve child oid %d: %w", childOID, err)
		}
		path = append(path, internalNodeRef{paddr: curPaddr, oid: curOID, idx: idx})
		childRaw, err := v.c.readBlock(childPaddr)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("apfs: descend: read child block at %d: %w", childPaddr, err)
		}
		nextNode, err := readBTreeNode(childRaw)
		if err != nil {
			return 0, 0, nil, err
		}
		curNode = nextNode
		curInfo = nil
		curPaddr = childPaddr
		curOID = childOID
	}
	return curPaddr, curOID, path, nil
}

// descendToLeafForKey walks the FS-tree from the root to the leaf that
// would hold targetKey, returning that leaf's paddr/oid + the parent
// internal nodes along the way (root last). For now only 2-level trees
// are supported (root → leaf); deeper trees error out so we don't
// silently produce a malformed index update.
func (v *Volume) descendToLeafForKey(targetKey []byte) (leafPaddr, leafOID uint64, parent childInfo, err error) {
	if v.rootNode.IsLeaf() {
		// Single-level: caller should use the in-place / split-root path.
		return 0, 0, childInfo{}, fmt.Errorf("apfs: descend: tree is single-leaf")
	}
	// Recursive descent through any number of internal levels. At each
	// step we pick the rightmost entry whose index key is ≤ targetKey
	// and follow that child's OID through the volume OMAP. The IMMEDIATE
	// parent of the leaf is the one we return as `parent` — that's the
	// node whose index entry would need updating after a leaf split.
	curNode := v.rootNode
	curInfo := v.rootInfo
	var parentInfo childInfo
	for !curNode.IsLeaf() {
		r, err := newNodeReader(curNode, curInfo)
		if err != nil {
			return 0, 0, childInfo{}, err
		}
		nKeys := r.EntryCount()
		if nKeys == 0 {
			return 0, 0, childInfo{}, fmt.Errorf("apfs: descend: empty index node at level %d", curNode.level)
		}
		idx := 0
		for i := 0; i < nKeys; i++ {
			k, kerr := r.keyAt(i)
			if kerr != nil {
				return 0, 0, childInfo{}, kerr
			}
			if compareFSKey(k, targetKey) <= 0 {
				idx = i
			} else {
				break
			}
		}
		childOID, err := r.childOIDAt(idx)
		if err != nil {
			return 0, 0, childInfo{}, err
		}
		childPaddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
		if err != nil {
			return 0, 0, childInfo{}, fmt.Errorf("apfs: descend: resolve child oid %d: %w", childOID, err)
		}
		idxKey, err := r.keyAt(idx)
		if err != nil {
			return 0, 0, childInfo{}, err
		}
		parentInfo = childInfo{
			key:   append([]byte(nil), idxKey...),
			oid:   childOID,
			paddr: childPaddr,
			idx:   idx,
		}
		// Follow the child.
		childRaw, err := v.c.readBlock(childPaddr)
		if err != nil {
			return 0, 0, childInfo{}, fmt.Errorf("apfs: descend: read child block at %d: %w", childPaddr, err)
		}
		nextNode, err := readBTreeNode(childRaw)
		if err != nil {
			return 0, 0, childInfo{}, err
		}
		curNode = nextNode
		curInfo = nil // child nodes don't carry btreeInfo trailer
	}
	return parentInfo.paddr, parentInfo.oid, parentInfo, nil
}

// readAllInternalEntries collects every (key, child-oid-bytes) pair
// from the FS-tree root (assumed to be an internal node).
func (v *Volume) readAllInternalEntries() ([]fsLeafKV, error) {
	if v.rootNode.IsLeaf() {
		return nil, fmt.Errorf("apfs: readAllInternal: root is a leaf")
	}
	r, err := newNodeReader(v.rootNode, v.rootInfo)
	if err != nil {
		return nil, err
	}
	out := make([]fsLeafKV, 0, r.EntryCount())
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return nil, err
		}
		v, err := r.valueAt(i)
		if err != nil {
			return nil, err
		}
		out = append(out, fsLeafKV{
			key: append([]byte(nil), k...),
			val: append([]byte(nil), v[:8]...),
		})
	}
	return out, nil
}

// modifyLeafAtPaddrAndInsert reads the FS-tree leaf at leafPaddr, adds
// newEntries, and rewrites the leaf in place if it still fits. If the
// leaf would overflow, it is split into two halves: the original paddr
// keeps the left half (oid unchanged), a fresh paddr+oid stores the
// right half, and the parent index node gets a new entry. Returns the
// rebuilt root (always the FS-tree's apsb.rootTreeOID block).
func (v *Volume) modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID uint64, newEntries []fsLeafKV, rootPaddr uint64) error {
	bs := v.physicalBlockSize()
	rawLeaf, err := v.c.readBlock(leafPaddr)
	if err != nil {
		return fmt.Errorf("apfs: read leaf at paddr %d: %w", leafPaddr, err)
	}
	leaf, err := readBTreeNode(rawLeaf)
	if err != nil {
		return fmt.Errorf("apfs: parse leaf: %w", err)
	}
	if !leaf.IsLeaf() {
		return fmt.Errorf("apfs: descended target is not a leaf (level=%d)", leaf.level)
	}
	r, err := newNodeReader(leaf, nil)
	if err != nil {
		return err
	}
	all := make([]fsLeafKV, 0, r.EntryCount()+len(newEntries))
	for i := 0; i < r.EntryCount(); i++ {
		k, err := r.keyAt(i)
		if err != nil {
			return err
		}
		val, err := r.valueAt(i)
		if err != nil {
			return err
		}
		all = append(all, fsLeafKV{
			key: append([]byte(nil), k...),
			val: append([]byte(nil), val...),
		})
	}
	// Merge with upsert semantics so a new entry with the same key
	// replaces the old one (e.g. refreshed root-dir inode val) instead
	// of duplicating it.
	for _, ne := range newEntries {
		all = upsertEntry(all, ne.key, ne.val)
	}
	sortLeafEntries(all)
	if leafFitsCheck(all, int(bs), false) {
		// In-place rewrite — preserves leafOID, paddr and xid.
		newLeaf, err := emitFSTreeLeafNonRoot(all, int(bs), leafOID, leafXID)
		if err != nil {
			return fmt.Errorf("apfs: emit leaf: %w", err)
		}
		if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: write leaf at paddr %d: %w", leafPaddr, err)
		}
		return nil
	}
	// Need to split this leaf. Split by byte midpoint.
	totalBytes := 0
	for _, e := range all {
		totalBytes += 8 + len(e.key) + len(e.val)
	}
	splitBytes := totalBytes / 2
	cum := 0
	splitIdx := len(all) / 2
	for i, e := range all {
		cum += 8 + len(e.key) + len(e.val)
		if cum >= splitBytes {
			splitIdx = i + 1
			break
		}
	}
	if splitIdx == 0 {
		splitIdx = 1
	}
	if splitIdx >= len(all) {
		splitIdx = len(all) - 1
	}
	left := all[:splitIdx]
	right := all[splitIdx:]
	if !leafFitsCheck(left, int(bs), false) || !leafFitsCheck(right, int(bs), false) {
		return fmt.Errorf("apfs: leaf split halves still overflow (left=%d, right=%d)", len(left), len(right))
	}
	rightPaddr, rightOID, err := v.allocateNewTreeNode()
	if err != nil {
		return fmt.Errorf("apfs: splitLeaf: alloc right: %w", err)
	}
	leftBlock, err := emitFSTreeLeafNonRoot(left, int(bs), leafOID, leafXID)
	if err != nil {
		return fmt.Errorf("apfs: splitLeaf: emit left: %w", err)
	}
	if _, err := v.c.w.WriteAt(leftBlock, int64(leafPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: splitLeaf: write left at paddr %d: %w", leafPaddr, err)
	}
	rightBlock, err := emitFSTreeLeafNonRoot(right, int(bs), rightOID, leafXID)
	if err != nil {
		return fmt.Errorf("apfs: splitLeaf: emit right: %w", err)
	}
	if _, err := v.c.w.WriteAt(rightBlock, int64(rightPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: splitLeaf: write right at paddr %d: %w", rightPaddr, err)
	}
	if err := v.upsertVolumeOMAPEntry(rightOID, leafXID, rightPaddr); err != nil {
		return fmt.Errorf("apfs: splitLeaf: omap right: %w", err)
	}

	// Add the new right leaf entry to the leaf's IMMEDIATE parent
	// internal node. In a 2-level tree the parent IS the root, but in
	// deeper trees the parent is at level 1 and the root sits above it
	// — putting the new leaf entry directly into the root would skip
	// the intermediate level and produce a structurally invalid tree
	// (root child OIDs would point to leaves in some entries and to
	// internal nodes in others). We re-descend with left[0].key so we
	// can locate the immediate parent for any tree level, then propagate
	// any cascade splits back up to the root.
	rootXID := v.rootNode.hdr.xid
	leafParentLeftKey := append([]byte(nil), left[0].key...)
	leafParentRightKey := append([]byte(nil), right[0].key...)
	return v.insertSiblingIntoParent(leafParentLeftKey, leafOID, leafParentRightKey, rightOID, rootXID, rootPaddr)
}

// insertSiblingIntoParent updates the immediate-parent internal node
// of a freshly-split leaf so that the parent's index has:
//
//   - the existing entry for `leftChildOID` rewritten to use
//     `leftFirstKey` as its index key (left[0] of the rewritten leaf),
//   - a new entry (rightFirstKey, rightChildOID) for the freshly
//     allocated right sibling.
//
// If the parent overflows after the insertion, the parent itself is
// split and the propagation continues one level up. When the cascade
// reaches the root and the root overflows, the root is promoted via
// `promoteRoot`. After every successful update the FS-tree root's
// metadata is refreshed so the in-memory cached root sees the new
// shape.
//
// The function tolerates any tree depth from level 1 (single root +
// leaves) to arbitrarily deep multi-level trees.
func (v *Volume) insertSiblingIntoParent(leftFirstKey []byte, leftChildOID uint64, rightFirstKey []byte, rightChildOID uint64, rootXID, rootPaddr uint64) error {
	bs := v.physicalBlockSize()
	// Use the right sibling's first key to locate the immediate parent
	// node — descent picks the rightmost entry whose index key ≤ target,
	// and right's first key currently still resolves into the leaf we
	// just split (since the parent index hasn't been updated yet).
	_, _, path, err := v.descendToLeafPath(rightFirstKey)
	if err != nil {
		return fmt.Errorf("apfs: splitLeaf: descend for parent: %w", err)
	}
	if len(path) == 0 {
		return fmt.Errorf("apfs: splitLeaf: empty internal path")
	}
	// Walk path from leaf-parent (last) up to root (first).
	curLeftKey := append([]byte(nil), leftFirstKey...)
	curLeftOID := leftChildOID
	curRightKey := append([]byte(nil), rightFirstKey...)
	curRightOID := rightChildOID
	for level := len(path) - 1; level >= 0; level-- {
		ref := path[level]
		isRoot := level == 0
		// Read the internal node's current entries.
		rawNode, err := v.c.readBlock(ref.paddr)
		if err != nil {
			return fmt.Errorf("apfs: splitLeaf: read internal at %d: %w", ref.paddr, err)
		}
		node, err := readBTreeNode(rawNode)
		if err != nil {
			return err
		}
		var info *btreeInfo
		if isRoot {
			info, err = readRootBTreeInfo(rawNode)
			if err != nil {
				return err
			}
		}
		r, err := newNodeReader(node, info)
		if err != nil {
			return err
		}
		entries := make([]fsLeafKV, 0, r.EntryCount()+1)
		for i := 0; i < r.EntryCount(); i++ {
			k, kerr := r.keyAt(i)
			if kerr != nil {
				return kerr
			}
			val, verr := r.valueAt(i)
			if verr != nil {
				return verr
			}
			entries = append(entries, fsLeafKV{
				key: append([]byte(nil), k...),
				val: append([]byte(nil), val[:8]...),
			})
		}
		// Update the existing entry pointing at curLeftOID, and add a
		// new entry for curRightOID.
		updated := false
		for i := range entries {
			oid := binary.LittleEndian.Uint64(entries[i].val[0:8])
			if oid == curLeftOID {
				entries[i].key = append([]byte(nil), curLeftKey...)
				updated = true
				break
			}
		}
		if !updated {
			return fmt.Errorf("apfs: splitLeaf: parent at level %d does not reference child oid %d", node.level, curLeftOID)
		}
		entries = append(entries, fsLeafKV{
			key: append([]byte(nil), curRightKey...),
			val: encodeChildOIDValue(curRightOID),
		})
		sortLeafEntries(entries)

		// In-place fit?
		if leafFitsCheck(entries, int(bs), isRoot) {
			var block []byte
			if isRoot {
				longestKey, longestVal := v.computeTreeLongestKV(nil)
				// Use placeholder counts for the first emit; refreshRoot
				// at the end recomputes accurate totals. We're already
				// touching the in-memory rootNode, so a single emit is
				// enough to make the tree traversable for the recount.
				block, err = emitFSTreeInternalExplicit(entries, int(bs), ref.oid, rootXID, node.level, true, longestKey, longestVal, 0, 0)
			} else {
				block, err = emitFSTreeInternalExplicit(entries, int(bs), ref.oid, rootXID, node.level, false, 0, 0, 0, 0)
			}
			if err != nil {
				return fmt.Errorf("apfs: splitLeaf: emit internal at level %d: %w", node.level, err)
			}
			if _, err := v.c.w.WriteAt(block, int64(ref.paddr*bs)); err != nil {
				return fmt.Errorf("apfs: splitLeaf: write internal at level %d: %w", node.level, err)
			}
			if isRoot {
				if err := v.reloadRoot(rootPaddr); err != nil {
					return fmt.Errorf("apfs: splitLeaf: reload root: %w", err)
				}
				// Final accurate refresh once the tree shape settles.
				return v.refreshRoot(rootPaddr)
			}
			// Non-root parent fit — propagation stops here, but the
			// root still needs its tree-wide counts/longest-keys updated
			// because we added a key. refreshRoot handles that by
			// walking every child's leftmost descendant.
			return v.refreshRoot(rootPaddr)
		}
		// Parent overflowed: split this internal node by index midpoint.
		// (entries are now sorted, so the index midpoint is the value
		// midpoint of the sort order.)
		if isRoot {
			return v.promoteRoot(entries, rootPaddr, rootXID, node.level)
		}
		mid := len(entries) / 2
		leftHalf := entries[:mid]
		rightHalf := entries[mid:]
		if !leafFitsCheck(leftHalf, int(bs), false) || !leafFitsCheck(rightHalf, int(bs), false) {
			return fmt.Errorf("apfs: splitLeaf: internal split halves overflow (left=%d, right=%d)", len(leftHalf), len(rightHalf))
		}
		// Rewrite this internal node's paddr with the LEFT half.
		leftBlock, err := emitFSTreeInternalExplicit(leftHalf, int(bs), ref.oid, rootXID, node.level, false, 0, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("apfs: splitLeaf: emit internal left at level %d: %w", node.level, err)
		}
		if _, err := v.c.w.WriteAt(leftBlock, int64(ref.paddr*bs)); err != nil {
			return fmt.Errorf("apfs: splitLeaf: write internal left at level %d: %w", node.level, err)
		}
		// Allocate a fresh oid+paddr for the RIGHT half.
		newRightPaddr, newRightOID, err := v.allocateNewTreeNode()
		if err != nil {
			return fmt.Errorf("apfs: splitLeaf: alloc internal right at level %d: %w", node.level, err)
		}
		rightBlock, err := emitFSTreeInternalExplicit(rightHalf, int(bs), newRightOID, rootXID, node.level, false, 0, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("apfs: splitLeaf: emit internal right at level %d: %w", node.level, err)
		}
		if _, err := v.c.w.WriteAt(rightBlock, int64(newRightPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: splitLeaf: write internal right at level %d: %w", node.level, err)
		}
		if err := v.upsertVolumeOMAPEntry(newRightOID, rootXID, newRightPaddr); err != nil {
			return fmt.Errorf("apfs: splitLeaf: omap internal right at level %d: %w", node.level, err)
		}
		// Propagate one level up: the level-up parent's existing index
		// entry for ref.oid keeps pointing at leftHalf (same paddr+oid,
		// but its leftmost key may have changed), and a new entry for
		// newRightOID is inserted carrying rightHalf[0].key.
		curLeftKey = append([]byte(nil), leftHalf[0].key...)
		curLeftOID = ref.oid
		curRightKey = append([]byte(nil), rightHalf[0].key...)
		curRightOID = newRightOID
	}
	// Shouldn't reach here: the root case `isRoot` always returns
	// above. Guard anyway so a logic regression surfaces loudly
	// rather than silently dropping the cascade.
	return fmt.Errorf("apfs: splitLeaf: cascade propagated past root without termination")
}
