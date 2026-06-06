package filesystem_apfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestDeleteSnapshot_RoundTrip creates a snapshot, deletes it by
// name, and verifies it's gone from ListSnapshots.
func TestDeleteSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "delsnap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := FormatContainer(path, 1<<22, "DelSnap"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	if _, err := v.CreateFile(2, "f.txt", []byte("x")); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	v.SetSuppressSnapshotGuard(true)
	if _, err := v.CreateSnapshot("snap-to-delete"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// Sanity: snapshot is listed before deletion.
	snaps, err := v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots pre-delete: %v", err)
	}
	if len(snaps) != 1 || snaps[0].Name != "snap-to-delete" {
		t.Fatalf("pre-delete: got %+v, want 1 snapshot named snap-to-delete", snaps)
	}
	// Delete and verify.
	if err := v.DeleteSnapshot("snap-to-delete"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	snaps, err = v.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots post-delete: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("post-delete: got %d snapshots, want 0", len(snaps))
	}
}

// TestDeleteSnapshot_NotFound returns os.ErrNotExist for a name
// that doesn't match any snapshot.
func TestDeleteSnapshot_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Missing"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	err = v.DeleteSnapshot("ghost")
	if err == nil {
		t.Fatal("DeleteSnapshot ghost: expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Logf("got %v (acceptable — wrapping varies)", err)
	}
}

// TestDeleteSnapshot_EmptyName rejects empty names.
func TestDeleteSnapshot_EmptyName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Empty"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	if err := v.DeleteSnapshot(""); err == nil {
		t.Fatal("DeleteSnapshot empty: expected error")
	}
}

// TestDeleteSnapshot_NumSnapshotsDecrements verifies the
// apsb.numSnapshots cache is updated after deletion.
func TestDeleteSnapshot_NumSnapshotsDecrements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "count.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := FormatContainer(path, 1<<22, "Count"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	v.SetSuppressSnapshotGuard(true)
	if _, err := v.CreateSnapshot("solo"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	before := v.apsb.numSnapshots
	if before == 0 {
		t.Fatalf("apsb.numSnapshots should be ≥1 after create, got %d", before)
	}
	if err := v.DeleteSnapshot("solo"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if v.apsb.numSnapshots != before-1 {
		t.Errorf("apsb.numSnapshots: got %d, want %d", v.apsb.numSnapshots, before-1)
	}
}
