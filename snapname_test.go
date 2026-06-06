package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// snapNameKey is the test-side counterpart of buildSnapNameKey: same
// layout (oid=0, type=jTypeSnapName, uint16 name_len, NUL-terminated
// name).
func snapNameKey(name string) []byte {
	return buildSnapNameKey(name)
}

// snapNameValue serialises the 8-byte xid that lives in the value of a
// J_SNAP_NAME record.
func snapNameValue(xid uint64) []byte {
	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, xid)
	return v
}

// TestLookupSnapshotByName_FastPath exercises the J_SNAP_NAME
// binary-search code path. The synthetic snap meta tree carries both
// J_SNAP_META records (keyed by xid) and J_SNAP_NAME records (keyed by
// (oid=0, type=jTypeSnapName, name)). LookupSnapshotByName must:
//   - Find each snapshot by its name without scanning the entire tree.
//   - Return os.ErrNotExist for an unknown name, taking the fast-path
//     fast-fail (no fallback hit either).
//   - Be unaffected by snapshots written in any order — sorting inside
//     writeFSTreeLeafCustom puts the records in canonical APFS order.
func TestLookupSnapshotByName_FastPath(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSBWithSnapMeta(img.blocks[3], 100, 4, 200, 300, "FastSnap")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6}, // FS-tree
		{oid: 300, paddr: 7}, // snap meta tree
	})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
	})

	// Snap meta tree carries J_SNAP_META records for 3 snapshots PLUS
	// matching J_SNAP_NAME records. They are intentionally provided in
	// non-sorted order; writeFSTreeLeafCustom sorts them by compareFSKey
	// before writing.
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: snapMetaKey(7100), val: snapMetaValue(0, 5678, 0xD1, 0xD2, 9, 0, "lunch")},
		{key: snapNameKey("lunch"), val: snapNameValue(7100)},
		{key: snapMetaKey(7000), val: snapMetaValue(0, 1234, 0xC1, 0xC2, 5, 0, "morning")},
		{key: snapNameKey("morning"), val: snapNameValue(7000)},
		{key: snapMetaKey(7200), val: snapMetaValue(0, 9012, 0xE1, 0xE2, 3, 0, "evening")},
		{key: snapNameKey("evening"), val: snapNameValue(7200)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}

	cases := []struct {
		name     string
		wantXID  uint64
		wantOID  uint64
		wantInum uint64
	}{
		{"morning", 7000, 1234, 5},
		{"lunch", 7100, 5678, 9},
		{"evening", 7200, 9012, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.LookupSnapshotByName(tc.name)
			if err != nil {
				t.Fatalf("LookupSnapshotByName(%q): %v", tc.name, err)
			}
			if got.XID != tc.wantXID || got.APSBOID != tc.wantOID || got.Inum != tc.wantInum {
				t.Fatalf("snapshot mismatch: got %+v", got)
			}
			if got.Name != tc.name {
				t.Fatalf("Name=%q want %q", got.Name, tc.name)
			}
		})
	}

	// Unknown name: fast path returns no match; fallback scan also returns
	// nothing; final result must be os.ErrNotExist.
	t.Run("unknown_name", func(t *testing.T) {
		_, err := v.LookupSnapshotByName("midnight")
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})
}

// TestLookupSnapshotByName_Fallback verifies that an image
// containing only J_SNAP_META records (no J_SNAP_NAME, the way our
// earlier synthetic images were built) still resolves names — the fast
// path returns "no match", the linear ListSnapshots fallback succeeds.
func TestLookupSnapshotByName_Fallback(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSBWithSnapMeta(img.blocks[3], 100, 4, 200, 300, "Fallback")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
		{oid: 300, paddr: 7},
	})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		// Only J_SNAP_META — no J_SNAP_NAME — so the fast path can't hit.
		{key: snapMetaKey(8000), val: snapMetaValue(0, 4242, 0, 0, 1, 0, "weekly")},
	})
	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	got, err := v.LookupSnapshotByName("weekly")
	if err != nil {
		t.Fatalf("LookupSnapshotByName: %v", err)
	}
	if got.XID != 8000 || got.APSBOID != 4242 {
		t.Fatalf("fallback mismatch: %+v", got)
	}
}
