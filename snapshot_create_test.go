package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateSnapshot_RoundTrip creates a file, takes a snapshot, then
// re-opens and verifies ListSnapshots reports the snapshot, the
// J_SNAP_NAME lookup resolves it by name, and apfs_num_snapshots is 1.
func TestCreateSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "SnapTest"); err != nil {
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
	if _, err := v.CreateFile(2, "before-snap.txt", []byte("baseline content\n")); err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	const snapName = "test-snap-1"
	snapXID, err := v.CreateSnapshot(snapName)
	if err != nil {
		c.Close()
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if snapXID == 0 {
		c.Close()
		t.Fatalf("CreateSnapshot returned xid=0")
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer (re-open): %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	snaps, err := v2.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("ListSnapshots: got %d, want 1: %+v", len(snaps), snaps)
	}
	got := snaps[0]
	if got.Name != snapName {
		t.Errorf("snap name: got %q, want %q", got.Name, snapName)
	}
	if got.XID != snapXID {
		t.Errorf("snap xid: got %d, want %d", got.XID, snapXID)
	}
	if got.APSBOID == 0 {
		t.Errorf("snap APSBOID is zero")
	}
	if got.CreateTime == 0 {
		t.Errorf("snap CreateTime is zero (should be set to time.Now())")
	}
	// J_SNAP_NAME-based lookup must also find the snapshot by name.
	bn, err := v2.LookupSnapshotByName(snapName)
	if err != nil {
		t.Fatalf("LookupSnapshotByName(%q): %v", snapName, err)
	}
	if bn.XID != snapXID {
		t.Errorf("LookupSnapshotByName xid: got %d, want %d", bn.XID, snapXID)
	}
}
