package filesystem_apfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestFormatContainer_RoundTrip is the primary acceptance test for
// iteration D of the read/write roadmap: an empty container produced by
// FormatContainer must be openable by OpenContainer and report a coherent,
// inhabitable empty volume — empty inode list, no snapshots, the
// volume label round-trips, and explicit lookups for non-existent
// inodes / snapshots fail with os.ErrNotExist.
func TestFormatContainer_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.apfs")
	const sizeBytes = int64(1 << 20) // 1 MiB
	const label = "FreshlyFormatted"

	// File must exist before FormatContainer writes into it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, sizeBytes, label); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer on freshly-formatted container: %v", err)
	}
	defer c.Close()

	vols := c.Volumes()
	if len(vols) != 1 || vols[0].OID != defaultAPSBOID {
		t.Fatalf("Volumes()=%+v, want one volume oid=%d", vols, defaultAPSBOID)
	}

	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if v.Name() != label {
		t.Fatalf("Name=%q want %q", v.Name(), label)
	}

	// FormatContainer pre-populates the FS-tree with the two synthetic
	// special directories Apple's `newfs_apfs` writes via `make_cat_root`:
	// root (oid=2) and private-dir (oid=3), along with their parent
	// dentries under APFS_ROOT_DIR_PARENT (oid=1). Without these the
	// kext refuses to mount our containers (mount_apfs returns EINVAL).
	inodes, err := v.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	if len(inodes) != 2 {
		t.Fatalf("expected 2 special-dir inodes (root + private-dir), got %d: %+v", len(inodes), inodes)
	}
	gotByID := map[uint64]Inode{}
	for _, ino := range inodes {
		gotByID[ino.ID] = ino
	}
	if root, ok := gotByID[2]; !ok || root.Name != "root" || !root.IsDir {
		t.Fatalf("expected root inode (oid=2, name='root', IsDir=true); got %+v", gotByID[2])
	}
	if priv, ok := gotByID[3]; !ok || priv.Name != "private-dir" || !priv.IsDir {
		t.Fatalf("expected private-dir inode (oid=3, name='private-dir', IsDir=true); got %+v", gotByID[3])
	}

	if _, err := v.LookupInodeRecord(42); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LookupInodeRecord(unknown oid): got %v, want os.ErrNotExist", err)
	}

	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Fatalf("expected no snapshots, got %d", len(snaps))
	}

	if _, err := v.LookupSnapshotByName("any"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LookupSnapshotByName: got %v, want os.ErrNotExist", err)
	}
}

// TestFormatContainer_RejectsTooSmall verifies that FormatContainer
// refuses to write a container smaller than the metadata footprint
// instead of producing an unreadable image.
func TestFormatContainer_RejectsTooSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	err := FormatContainer(path, 4096*4, "tiny") // 4 blocks, less than formatMetadataBlocks=8
	if err == nil {
		t.Fatal("expected rejection for size below metadata footprint")
	}
}

// TestFormatContainer_HashVerifyOnEmptyVolume confirms that an empty
// freshly-formatted volume does not break when SetVerifyHashes(true) is
// enabled. The container we emit is not hashed, so verification is a
// no-op for every descent.
func TestFormatContainer_HashVerifyOnEmptyVolume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Verify"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	c.SetVerifyHashes(true)
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := v.ListInodes(); err != nil {
		t.Fatalf("ListInodes with VerifyHashes=true: %v", err)
	}
}
