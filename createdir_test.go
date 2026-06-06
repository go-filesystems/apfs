package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateDirectory_RoundTrip creates a directory at the volume root,
// puts a file inside it, commits, then re-opens and verifies the
// hierarchy is intact. Exercises:
//   - CreateDirectory under root (rebindToRoot path)
//   - CreateFile under a non-root parent (refreshNonRootParentNchildren
//     for the user-created dir)
//   - Per-record-type counts after re-open.
func TestCreateDirectory_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "TreeTest"); err != nil {
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
	subOID, err := v.CreateDirectory(2, "subdir", 0o755)
	if err != nil {
		c.Close()
		t.Fatalf("CreateDirectory: %v", err)
	}
	if subOID == 0 || subOID == 2 {
		c.Close()
		t.Fatalf("unexpected subdir oid: %d", subOID)
	}
	want := []byte("nested file body\n")
	fileOID, err := v.CreateFile(subOID, "nested.txt", want)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile under subdir: %v", err)
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
		t.Fatalf("OpenContainer (post-write): %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	byID := map[uint64]Inode{}
	byName := map[string]Inode{}
	for _, ino := range inodes {
		byID[ino.ID] = ino
		byName[ino.Name] = ino
	}
	subdir, ok := byID[subOID]
	if !ok {
		t.Fatalf("subdir oid %d not found in inodes", subOID)
	}
	if !subdir.IsDir {
		t.Errorf("subdir is not a directory (mode=0o%o)", subdir.Mode)
	}
	if subdir.Name != "subdir" {
		t.Errorf("subdir name: got %q, want %q", subdir.Name, "subdir")
	}
	if subdir.ParentID != 2 {
		t.Errorf("subdir parent: got %d, want 2", subdir.ParentID)
	}
	nested, ok := byID[fileOID]
	if !ok {
		t.Fatalf("nested file oid %d not found", fileOID)
	}
	if nested.Name != "nested.txt" {
		t.Errorf("nested name: got %q, want %q", nested.Name, "nested.txt")
	}
	if nested.ParentID != subOID {
		t.Errorf("nested parent: got %d, want %d (subdir)", nested.ParentID, subOID)
	}
	full, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode(%d): %v", fileOID, err)
	}
	got, err := v2.ReadFile(full)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ReadFile content mismatch:\n got:  %q\n want: %q", got, want)
	}
}
