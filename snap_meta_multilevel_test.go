package filesystem_apfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapMetaMultiLevel_PromotesAtThreshold injects synthetic
// J_SNAP_META records directly through `appendSnapMetaRecords` (the
// writer-side helper that CreateSnapshot also uses). 200 distinct
// xids are enough to overflow a single 4 KiB leaf (~112 entries cap)
// and push the snap-meta tree to level=1 with two non-root leaves.
//
// We bypass CreateSnapshot here because each invocation uses the
// container's current xid as the snapshot xid, and the xid only
// advances on Commit — and the checkpoint descriptor area has
// capacity 8 (ring-buffer wrap is iteration D-8). Driving the
// underlying tree mutation directly verifies the multi-level
// promotion in isolation.
func TestSnapMetaMultiLevel_PromotesAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "SnapPromote"); err != nil {
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
	const N = 200
	// Build 200 J_SNAP_META records with distinct xids (and trivial
	// 50-byte values to mimic Apple's apfs_snap_meta_val layout).
	entries := make([]fsLeafKV, 0, N)
	for i := 1; i <= N; i++ {
		key := encodeSnapMetaKey(uint64(i))
		val := make([]byte, 50)
		binary.LittleEndian.PutUint64(val[0:8], uint64(i)) // any extentRefOID-ish field
		entries = append(entries, fsLeafKV{key: key, val: val})
	}
	// Insert in chunks of 5 to exercise the multi-level append loop
	// (CreateSnapshot would call appendSnapMetaRecords with 1-2
	// records at a time).
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
	rawRoot, err := v2.c.readBlock(v2.apsb.snapMetaOID)
	if err != nil {
		t.Fatalf("read snap-meta root: %v", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		t.Fatalf("parse snap-meta root: %v", err)
	}
	t.Logf("after %d records: snap-meta root level = %d, nKeys=%d",
		N, rootNode.level, rootNode.nKeys)
	if rootNode.IsLeaf() {
		t.Fatalf("snap-meta tree did not promote: root still a leaf with %d entries",
			rootNode.nKeys)
	}
	if rootNode.level != 1 {
		t.Errorf("root level: got %d, want 1", rootNode.level)
	}

	// Walk the tree and count J_SNAP_META records — should be exactly N.
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		t.Fatalf("readRootBTreeInfo: %v", err)
	}
	count := 0
	walkErr := v2.traverseBTreeWithOmap(rootNode, rootInfo, func(k, val []byte) error {
		_, typ, _ := jKeyHeader(k)
		if typ == jTypeSnapMeta {
			count++
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("traverse: %v", walkErr)
	}
	if count != N {
		t.Errorf("J_SNAP_META count after re-open: got %d, want %d", count, N)
	}
}
