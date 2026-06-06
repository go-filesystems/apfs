package filesystem_apfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeleteDirectory_RoundTrip creates a subdirectory, deletes it
// while empty, then verifies the directory is gone after re-open.
func TestDeleteDirectory_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rmdir.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RmDirTest"); err != nil {
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
	subOID, err := v.CreateDirectory(2, "doomed", 0o755)
	if err != nil {
		c.Close()
		t.Fatalf("CreateDirectory: %v", err)
	}
	if err := v.DeleteDirectory(2, "doomed"); err != nil {
		c.Close()
		t.Fatalf("DeleteDirectory: %v", err)
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
	if _, err := v2.FindInode(subOID); err == nil {
		t.Errorf("FindInode(%d) succeeded after DeleteDirectory; expected error", subOID)
	}
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	for _, ino := range inodes {
		if ino.Name == "doomed" {
			t.Errorf("doomed/ still listed after DeleteDirectory")
		}
	}
}

// TestDeleteDirectory_NonEmptyRefused verifies the POSIX-style refusal
// to remove a non-empty directory.
func TestDeleteDirectory_NonEmptyRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rmdir.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RmDirNE"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	subOID, err := v.CreateDirectory(2, "haskid", 0o755)
	if err != nil {
		t.Fatalf("CreateDirectory: %v", err)
	}
	if _, err := v.CreateFile(subOID, "child.txt", []byte("kid")); err != nil {
		t.Fatalf("CreateFile under subdir: %v", err)
	}
	err = v.DeleteDirectory(2, "haskid")
	if err == nil {
		t.Fatal("DeleteDirectory: expected error on non-empty dir")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("expected 'not empty' in error, got: %v", err)
	}
}

// TestDeleteDirectory_RefusesRoot confirms we never remove the
// canonical synthetic top-level directories.
func TestDeleteDirectory_RefusesRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rmdir.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RmDirRoot"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	// The root dir's drec lives at (parent=1, name="root"); attempting
	// to delete it should be refused (oid 2 is the root).
	if err := v.DeleteDirectory(1, "root"); err == nil {
		t.Error("DeleteDirectory(/root): expected refusal, got success")
	}
	if err := v.DeleteDirectory(1, "private-dir"); err == nil {
		t.Error("DeleteDirectory(/private-dir): expected refusal, got success")
	}
}
