package filesystem_apfs

import (
	"crypto/sha256"
	"testing"
)

// buildSealedFSTreeImage assembles a synthetic image whose FS-tree internal
// root carries hashed btn_index_node_val entries (8-byte child OID +
// 32-byte SHA-256 of the child block). The two child leaves each hold a
// single inode (101 in leaf 1, 102 in leaf 2). Returns the assembled
// bytes; the caller may flip a byte before re-running the test to exercise
// the corruption path.
func buildSealedFSTreeImage(t *testing.T) []byte {
	t.Helper()
	img := &containerImage{blocks: make([][]byte, 9)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Sealed")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6}, // FS-tree root
		{oid: 201, paddr: 7}, // leaf 1
		{oid: 202, paddr: 8}, // leaf 2
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 11, 0o100644)},
	})
	writeFSTreeLeafCustom(img.blocks[8], []fsLeafEntry{
		{key: jKey(102, jTypeInode), val: buildInodeValue(1, 22, 0o100644)},
	})
	// Compute the SHA-256 of each child leaf AFTER it has been written —
	// this is the value the parent's hashed entries must carry.
	hash1 := sha256.Sum256(img.blocks[7])
	hash2 := sha256.Sum256(img.blocks[8])
	writeFSTreeInternalHashed(img.blocks[6], []fsHashedEntry{
		{key: jKey(101, jTypeInode), childOID: 201, hash: hash1[:]},
		{key: jKey(102, jTypeInode), childOID: 202, hash: hash2[:]},
	})
	return img.bytes()
}

// TestHashVerify_HappyPath confirms a sealed (hashed) FS-tree image
// with correct hashes is readable both with and without verification.
func TestHashVerify_HappyPath(t *testing.T) {
	buf := buildSealedFSTreeImage(t)

	for _, tc := range []struct {
		name   string
		verify bool
	}{
		{"verify_off", false},
		{"verify_on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &memReadAt{buf: append([]byte(nil), buf...)}
			c, err := OpenContainerFromBackend(r)
			if err != nil {
				t.Fatalf("OpenContainerFromBackend: %v", err)
			}
			defer c.Close()
			c.SetVerifyHashes(tc.verify)
			v, err := c.OpenVolume(0)
			if err != nil {
				t.Fatalf("OpenVolume: %v", err)
			}
			ino, err := v.LookupInodeRecord(101)
			if err != nil {
				t.Fatalf("LookupInodeRecord(101): %v", err)
			}
			if ino.Size != 11 {
				t.Fatalf("size=%d want 11", ino.Size)
			}
			if _, err := v.LookupInodeRecord(102); err != nil {
				t.Fatalf("LookupInodeRecord(102): %v", err)
			}
		})
	}
}

// TestHashVerify_DetectsCorruption flips one byte of a child leaf
// and confirms that:
//   - With verification enabled, the descent that touches the corrupted
//     leaf fails with a hash-mismatch error.
//   - With verification disabled, the descent silently returns the
//     corrupted data (this is the documented trade-off — verification is
//     opt-in for performance reasons).
func TestHashVerify_DetectsCorruption(t *testing.T) {
	buf := buildSealedFSTreeImage(t)
	// Corrupt leaf #2 (block index 8) — a single byte flip is enough to
	// break the SHA-256 over the whole 4 KiB block.
	corrupt := append([]byte(nil), buf...)
	corrupt[8*4096+200] ^= 0xFF

	t.Run("verify_off_silently_succeeds", func(t *testing.T) {
		r := &memReadAt{buf: append([]byte(nil), corrupt...)}
		c, err := OpenContainerFromBackend(r)
		if err != nil {
			t.Fatalf("OpenContainerFromBackend: %v", err)
		}
		defer c.Close()
		v, err := c.OpenVolume(0)
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		// Inode 102 lives in the corrupted leaf; size field is at a
		// different offset so the read may still complete with a wrong
		// payload — the point is that no error is raised.
		if _, err := v.LookupInodeRecord(102); err != nil {
			t.Fatalf("expected silent success without verification, got %v", err)
		}
	})

	t.Run("verify_on_rejects", func(t *testing.T) {
		r := &memReadAt{buf: append([]byte(nil), corrupt...)}
		c, err := OpenContainerFromBackend(r)
		if err != nil {
			t.Fatalf("OpenContainerFromBackend: %v", err)
		}
		defer c.Close()
		c.SetVerifyHashes(true)
		v, err := c.OpenVolume(0)
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		_, err = v.LookupInodeRecord(102)
		if err == nil {
			t.Fatal("expected hash-mismatch error, got none")
		}
		// The error chain should mention "hash mismatch".
		if !contains(err.Error(), "hash mismatch") {
			t.Fatalf("error %q does not mention 'hash mismatch'", err)
		}
	})

	t.Run("verify_on_unrelated_leaf_unaffected", func(t *testing.T) {
		// Corruption is in leaf 2; descents into leaf 1 should still be
		// fine even with verification on.
		r := &memReadAt{buf: append([]byte(nil), corrupt...)}
		c, err := OpenContainerFromBackend(r)
		if err != nil {
			t.Fatalf("OpenContainerFromBackend: %v", err)
		}
		defer c.Close()
		c.SetVerifyHashes(true)
		v, err := c.OpenVolume(0)
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		if _, err := v.LookupInodeRecord(101); err != nil {
			t.Fatalf("LookupInodeRecord(101) on uncorrupted leaf failed: %v", err)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
