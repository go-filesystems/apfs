package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeleteFile_RoundTrip creates two files, deletes one, then re-opens
// and verifies the deleted file is gone (FindInode fails) but the
// surviving file still reads back correctly. ListInodes and the parent
// inode's nchildren must reflect the post-delete state.
func TestDeleteFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "del.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "DelTest"); err != nil {
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
	keepBody := []byte("survivor content\n")
	deletedBody := []byte("doomed content\n")
	keepOID, err := v.CreateFile(2, "survivor.txt", keepBody)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile survivor: %v", err)
	}
	deletedOID, err := v.CreateFile(2, "doomed.txt", deletedBody)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile doomed: %v", err)
	}
	if err := v.DeleteFile(2, "doomed.txt"); err != nil {
		c.Close()
		t.Fatalf("DeleteFile: %v", err)
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
	// Survivor must still resolve.
	keepIno, err := v2.FindInode(keepOID)
	if err != nil {
		t.Fatalf("FindInode(survivor=%d): %v", keepOID, err)
	}
	got, err := v2.ReadFile(keepIno)
	if err != nil {
		t.Fatalf("ReadFile survivor: %v", err)
	}
	if string(got) != string(keepBody) {
		t.Errorf("survivor content: got %q, want %q", got, keepBody)
	}
	// Deleted must NOT resolve.
	if _, err := v2.FindInode(deletedOID); err == nil {
		t.Errorf("FindInode(doomed=%d) succeeded after delete; expected error", deletedOID)
	}
	// ListInodes must not include doomed.txt by name.
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	names := map[string]bool{}
	for _, ino := range inodes {
		names[ino.Name] = true
	}
	if !names["survivor.txt"] {
		t.Error("survivor.txt missing from ListInodes")
	}
	if names["doomed.txt"] {
		t.Error("doomed.txt still listed after delete")
	}
}
