package filesystem_apfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapshotGuard_RefusesPostSnapshotWrites confirms that writes
// against a volume with snapshots return `ErrHasSnapshot` until either
// the snapshots are removed OR the guard is explicitly suppressed.
// Protects the snapshot's frozen view from in-place mutations.
func TestSnapshotGuard_RefusesPostSnapshotWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "Guard"); err != nil {
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
	if _, err := v.CreateFile(2, "before-snap.txt", []byte("baseline")); err != nil {
		c.Close()
		t.Fatalf("CreateFile pre-snapshot: %v", err)
	}
	if _, err := v.CreateSnapshot("guard-snap"); err != nil {
		c.Close()
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// Post-snapshot write must be refused.
	_, err = v.CreateFile(2, "after-snap.txt", []byte("forbidden"))
	if err == nil {
		c.Close()
		t.Fatal("CreateFile after snapshot succeeded; expected ErrHasSnapshot")
	}
	if !errors.Is(err, ErrHasSnapshot) {
		c.Close()
		t.Fatalf("CreateFile after snapshot: got %v, want errors.Is(ErrHasSnapshot)", err)
	}
	// Suppression escape hatch lets the write through (used by tests
	// that intentionally invalidate snapshots for byte-diff diagnostics).
	v.SetSuppressSnapshotGuard(true)
	if _, err := v.CreateFile(2, "after-snap.txt", []byte("with suppression")); err != nil {
		c.Close()
		t.Fatalf("CreateFile after snapshot with suppression: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
