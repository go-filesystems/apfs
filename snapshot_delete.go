package filesystem_apfs

// snapshot_delete.go — symmetric `Volume.DeleteSnapshot` for the
// `CreateSnapshot` API (snapshot_create.go).
//
// Removes the (J_SNAP_NAME, J_SNAP_META) record pair from the
// volume's snap-meta tree, frees the frozen-APSB paddr the snapshot
// owned, and decrements `apsb.apfs_num_snapshots`. When the deleted
// snapshot was the latest (highest xid), `om_most_recent_snap` is
// rolled back to the new largest surviving xid (or zero if none).
//
// Scope:
//   - PHYSICAL snap-meta trees only (matches CreateSnapshot's scope).
//   - Single-leaf AND 2-level multi-level snap-meta trees (the same
//     promotion shape `appendSnapMetaRecords` produces).
//   - Cloning chains and snapshot-of-snapshot are out of scope; we
//     don't share extents between snapshots so the frozen paddr can
//     be freed unconditionally.

import (
	"encoding/binary"
	"fmt"
	"os"
)

// DeleteSnapshot removes the snapshot named `name` from the volume.
// Returns os.ErrNotExist when no snapshot of that name exists.
//
// The snapshot's frozen APSB block is freed, the J_SNAP_NAME +
// J_SNAP_META records are dropped from the snap-meta tree, and
// `apsb.apfs_num_snapshots` is decremented. If `name` was the
// most-recent snapshot, the volume OMAP's `om_most_recent_snap` is
// rolled back to the new maximum xid (or 0 when no snapshots remain).
func (v *Volume) DeleteSnapshot(name string) error {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return fmt.Errorf("apfs: DeleteSnapshot on a snapshot view is not supported")
	}
	if name == "" {
		return fmt.Errorf("apfs: DeleteSnapshot: empty name")
	}
	if v.apsb == nil || v.apsb.snapMetaOID == 0 {
		return fmt.Errorf("apfs: DeleteSnapshot: no snap-meta tree")
	}
	if !v.apsb.snapMetaIsPhysical() {
		return fmt.Errorf("apfs: DeleteSnapshot: only PHYSICAL snap-meta trees are supported")
	}

	// 1. Resolve name → xid + frozen APSB paddr.
	snapXID, frozenPaddr, err := v.findSnapshotByName(name)
	if err != nil {
		return err
	}

	// 2. Build the two keys we need to drop.
	snapMetaKey := encodeSnapMetaKey(snapXID)
	snapNameKey := encodeSnapNameKey(name)

	// 3. Remove the records from the snap-meta tree.
	if err := v.removeSnapMetaRecords([][]byte{snapMetaKey, snapNameKey}); err != nil {
		return fmt.Errorf("apfs: DeleteSnapshot: remove records: %w", err)
	}

	// 4. Free the frozen APSB paddr (1 block).
	if frozenPaddr != 0 {
		if err := v.c.markBlocksFreed(frozenPaddr, 1); err != nil {
			return fmt.Errorf("apfs: DeleteSnapshot: free frozen APSB at %d: %w", frozenPaddr, err)
		}
		if err := v.bumpFSAllocCount(-1); err != nil {
			return fmt.Errorf("apfs: DeleteSnapshot: decrement alloc count: %w", err)
		}
	}

	// 5. Decrement apsb.apfs_num_snapshots.
	if err := v.bumpAPSBNumSnapshots(-1); err != nil {
		return fmt.Errorf("apfs: DeleteSnapshot: decrement num_snapshots: %w", err)
	}
	if v.apsb != nil && v.apsb.numSnapshots > 0 {
		v.apsb.numSnapshots--
	}

	// 6. If the deleted snapshot was the most-recent, recompute
	//    om_most_recent_snap from the surviving records.
	if v.volOmap != nil && v.volOmap.mostRecentXID == snapXID {
		newMax := v.findMaxRemainingSnapXID()
		if err := v.rewindVolumeOMAPMostRecentSnap(newMax); err != nil {
			return fmt.Errorf("apfs: DeleteSnapshot: rewind om_most_recent_snap: %w", err)
		}
	}
	return nil
}

// findSnapshotByName walks the snap-meta tree and returns the
// (xid, frozenAPSBPaddr) of the snapshot named `name`. Returns
// os.ErrNotExist when no match.
func (v *Volume) findSnapshotByName(name string) (uint64, uint64, error) {
	root, info, err := v.openSnapMetaTree()
	if err != nil {
		return 0, 0, err
	}
	if root == nil {
		return 0, 0, os.ErrNotExist
	}
	var xid, paddr uint64
	hit := false
	walkErr := v.traverseBTreeWithOmap(root, info, func(k, val []byte) error {
		_, typ, herr := jKeyHeader(k)
		if herr != nil || typ != jTypeSnapMeta {
			return nil
		}
		snap, ok := decodeSnapMeta(k, val)
		if !ok || snap.Name != name {
			return nil
		}
		xid = snap.XID
		paddr = snap.APSBOID
		hit = true
		return nil
	})
	if walkErr != nil {
		return 0, 0, walkErr
	}
	if !hit {
		return 0, 0, os.ErrNotExist
	}
	return xid, paddr, nil
}

// findMaxRemainingSnapXID returns the largest J_SNAP_META xid still
// in the snap-meta tree, or 0 when none remain. Called after a
// DeleteSnapshot that may have removed the most-recent snapshot.
func (v *Volume) findMaxRemainingSnapXID() uint64 {
	root, info, err := v.openSnapMetaTree()
	if err != nil || root == nil {
		return 0
	}
	var max uint64
	_ = v.traverseBTreeWithOmap(root, info, func(k, val []byte) error {
		_, typ, herr := jKeyHeader(k)
		if herr != nil || typ != jTypeSnapMeta {
			return nil
		}
		xid, _, _ := jKeyHeader(k)
		if xid > max {
			max = xid
		}
		return nil
	})
	return max
}

// removeSnapMetaRecords drops the given keys from the snap-meta
// tree, handling both single-leaf and 2-level shapes.
func (v *Volume) removeSnapMetaRecords(keys [][]byte) error {
	bs := v.physicalBlockSize()
	rootPaddr := v.apsb.snapMetaOID
	rawRoot, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta remove: read root: %w", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return err
	}
	if !rootNode.IsLeaf() {
		// Multi-level: descend per key, rewrite each affected leaf.
		for _, k := range keys {
			if err := v.snapMetaRemoveOneRecordMultiLevel(rawRoot, rootNode, k); err != nil {
				return err
			}
			// Re-read root in case a leaf split affected the index.
			rawRoot, err = v.c.readBlock(rootPaddr)
			if err != nil {
				return err
			}
			rootNode, err = readBTreeNode(rawRoot)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// Single-leaf: rebuild the leaf without the keys.
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return err
	}
	existing, err := readAllLeafEntries(rootNode, rootInfo)
	if err != nil {
		return err
	}
	out := make([]fsLeafKV, 0, len(existing))
	for _, kv := range existing {
		drop := false
		for _, target := range keys {
			if bytesEqual(kv.key, target) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	leafXID := rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitPhysicalBTreeLeafExplicit(out, int(bs), rootPaddr, leafXID, objTypeSnapMetaTree)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta remove: emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta remove: write leaf: %w", err)
	}
	return nil
}

// snapMetaRemoveOneRecordMultiLevel descends the 2-level snap-meta
// tree, finds the leaf containing `key`, and rewrites it without
// that key.
func (v *Volume) snapMetaRemoveOneRecordMultiLevel(rootBytes []byte, rootNode *btreeNode, key []byte) error {
	bs := int(v.physicalBlockSize())
	leafPaddr, _, _, err := v.snapMetaDescendToLeaf(rootBytes, rootNode, key)
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
	out := make([]fsLeafKV, 0, len(existing))
	for _, kv := range existing {
		if bytesEqual(kv.key, key) {
			continue
		}
		out = append(out, kv)
	}
	leafXID := leafNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}
	newLeaf, err := emitSnapMetaLeafNonRoot(leafPaddr, leafXID, out, bs)
	if err != nil {
		return fmt.Errorf("apfs: snap-meta remove (ml): emit leaf: %w", err)
	}
	if _, err := v.c.w.WriteAt(newLeaf, int64(leafPaddr)*int64(bs)); err != nil {
		return fmt.Errorf("apfs: snap-meta remove (ml): write leaf: %w", err)
	}
	return nil
}

// rewindVolumeOMAPMostRecentSnap rewrites om_most_recent_snap to
// `newMax` (0 when no snapshots remain). Also decrements
// om_snap_count by 1. Called after DeleteSnapshot when the deleted
// snapshot was the previous most-recent.
func (v *Volume) rewindVolumeOMAPMostRecentSnap(newMax uint64) error {
	if v.volOmap == nil || v.volOmap.treeOID == 0 {
		return nil
	}
	rootPaddr := v.volOmap.treeOID
	bs := v.physicalBlockSize()
	raw, err := v.c.readBlock(rootPaddr)
	if err != nil {
		return err
	}
	// om_most_recent_snap is at offset 0x40 in apfs_omap_phys.
	// om_snap_count is at offset 0x38 (uint32).
	if len(raw) < 0x50 {
		return fmt.Errorf("apfs: rewind snap state: OMAP block too short")
	}
	curCount := binary.LittleEndian.Uint32(raw[0x38:0x3C])
	if curCount > 0 {
		binary.LittleEndian.PutUint32(raw[0x38:0x3C], curCount-1)
	}
	binary.LittleEndian.PutUint64(raw[0x40:0x48], newMax)
	sealBlock(raw)
	if _, err := v.c.w.WriteAt(raw, int64(rootPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: rewind snap state: write OMAP: %w", err)
	}
	v.volOmap.mostRecentXID = newMax
	if v.volOmap.snapCnt > 0 {
		v.volOmap.snapCnt--
	}
	return nil
}
