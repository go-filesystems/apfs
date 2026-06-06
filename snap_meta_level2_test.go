package filesystem_apfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapMeta_PromotesToLevel2 forces the snap-meta tree past its
// level-1 root cap. Production uses the natural ~120-child per-block
// limit (≈13 000 snapshots); the test lowers it via
// snapMetaInternalCapEntries so the level-2 promotion path runs
// without writing thousands of snapshots. Records are injected via
// appendSnapMetaRecords (bypassing CreateSnapshot, which shares one
// xid until Commit) so every record has a distinct key.
//
// After promotion the snap-meta root must be level=2 and every
// inserted J_SNAP_META record must still be reachable via the
// reader's traversal.
func TestSnapMeta_PromotesToLevel2(t *testing.T) {
	prev := snapMetaInternalCapEntries
	snapMetaInternalCapEntries = 4 // 5 child internals → triggers L2 promotion.
	defer func() { snapMetaInternalCapEntries = prev }()

	dir := t.TempDir()
	path := filepath.Join(dir, "sm_l2.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "SMETAL2"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	// 800 J_SNAP_META records: enough to fill ~7 leaves × ~110 each,
	// which with cap=4 forces level-2 promotion (after 5+ leaves) and
	// then exercises additional inserts via the level-2 path.
	const N = 800
	entries := make([]fsLeafKV, 0, N)
	for i := 1; i <= N; i++ {
		key := encodeSnapMetaKey(uint64(i))
		val := make([]byte, 50)
		binary.LittleEndian.PutUint64(val[0:8], uint64(i))
		entries = append(entries, fsLeafKV{key: key, val: val})
	}
	for i := 0; i < N; i += 5 {
		end := i + 5
		if end > N {
			end = N
		}
		if err := v.appendSnapMetaRecords(entries[i:end]); err != nil {
			c.Close()
			t.Fatalf("appendSnapMetaRecords chunk %d-%d: %v", i, end, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume reopen: %v", err)
	}
	rawRoot, err := c2.readBlock(v2.apsb.snapMetaOID)
	if err != nil {
		t.Fatalf("read snap-meta root: %v", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		t.Fatalf("parse snap-meta root: %v", err)
	}
	t.Logf("after %d records: snap-meta root level=%d, nKeys=%d",
		N, rootNode.level, rootNode.nKeys)
	if rootNode.level < 2 {
		t.Fatalf("snap-meta root level: got %d, want ≥ 2 (level-2 promotion didn't fire)", rootNode.level)
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		t.Fatalf("readRootBTreeInfo: %v", err)
	}
	count := 0
	if err := v2.traverseBTreeWithOmap(rootNode, rootInfo, func(k, val []byte) error {
		_, typ, _ := jKeyHeader(k)
		if typ == jTypeSnapMeta {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("traverse: %v", err)
	}
	if count != N {
		t.Errorf("J_SNAP_META count after re-open: got %d, want %d", count, N)
	}
}
