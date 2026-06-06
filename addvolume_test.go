package filesystem_apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAddVolume_RoundTrip formats a single-volume container, adds a
// second volume via AddVolume, then re-opens and verifies (a) the
// container reports two volumes via Volumes(), (b) each volume's name
// matches what we set, (c) writing into volume 1 + reading back works.
func TestAddVolume_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "VolA"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	idx, err := c.AddVolume("VolB")
	if err != nil {
		c.Close()
		t.Fatalf("AddVolume: %v", err)
	}
	if idx != 1 {
		t.Errorf("AddVolume returned index %d, want 1", idx)
	}
	// Drop a file into the new volume to exercise its full structure.
	v1, err := c.OpenVolume(1)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume(1): %v", err)
	}
	body := []byte("written into volume B\n")
	fileOID, err := v1.CreateFile(2, "in_B.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile in volume 1: %v", err)
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
	vols := c2.Volumes()
	if len(vols) != 2 {
		t.Fatalf("Volumes(): got %d, want 2: %+v", len(vols), vols)
	}
	v0, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume(0): %v", err)
	}
	if v0.Name() != "VolA" {
		t.Errorf("volume 0 name: got %q, want %q", v0.Name(), "VolA")
	}
	v1r, err := c2.OpenVolume(1)
	if err != nil {
		t.Fatalf("OpenVolume(1): %v", err)
	}
	if v1r.Name() != "VolB" {
		t.Errorf("volume 1 name: got %q, want %q", v1r.Name(), "VolB")
	}
	ino, err := v1r.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode in volume 1: %v", err)
	}
	got, err := v1r.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("file content: got %q, want %q", got, body)
	}
}
