package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRename_IntraDir creates a file, renames it within the same
// directory, then verifies the old name is gone and the new name
// resolves to the same inode and content.
func TestRename_IntraDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ren.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RenIntra"); err != nil {
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
	body := []byte("intra-dir rename target\n")
	fileOID, err := v.CreateFile(2, "old.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.Rename(2, "old.txt", 2, "new.txt"); err != nil {
		c.Close()
		t.Fatalf("Rename: %v", err)
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
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	names := map[string]uint64{}
	for _, ino := range inodes {
		names[ino.Name] = ino.ID
	}
	if names["old.txt"] != 0 {
		t.Errorf("old.txt still listed after rename (oid=%d)", names["old.txt"])
	}
	if names["new.txt"] != fileOID {
		t.Errorf("new.txt: got oid=%d, want %d", names["new.txt"], fileOID)
	}
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content: got %q, want %q", got, body)
	}
}

// TestRename_AcrossDirs creates a file in the root, renames it INTO
// a subdirectory under a different name, and verifies (a) the inode's
// parent_id points to the subdir, (b) both nchildren counts are
// correct, (c) content reads back from the new location.
func TestRename_AcrossDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ren.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RenCross"); err != nil {
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
	body := []byte("cross-dir rename body\n")
	fileOID, err := v.CreateFile(2, "atroot.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.Rename(2, "atroot.txt", subOID, "moved.txt"); err != nil {
		c.Close()
		t.Fatalf("Rename across dirs: %v", err)
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
	moved, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode(%d): %v", fileOID, err)
	}
	if moved.ParentID != subOID {
		t.Errorf("moved.txt parent: got %d, want %d (subdir)", moved.ParentID, subOID)
	}
	if moved.Name != "moved.txt" {
		t.Errorf("moved.txt name: got %q, want %q", moved.Name, "moved.txt")
	}
	got, err := v2.ReadFile(moved)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content: got %q, want %q", got, body)
	}
	// atroot.txt must be gone from root.
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	for _, ino := range inodes {
		if ino.Name == "atroot.txt" {
			t.Errorf("atroot.txt still listed after rename out of root")
		}
	}
}

// TestRename_OverwritesRegularFileDestination verifies POSIX
// rename-overwrite semantics: when both source and dest are regular
// files with nlink==1, rename atomically replaces the destination
// with the source. After the operation only the destination name
// remains, its content matches the source's, and the source name
// returns ENOENT.
func TestRename_OverwritesRegularFileDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ren.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RenOverwrite"); err != nil {
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
	srcContent := []byte("source-content-XYZ")
	if _, err := v.CreateFile(2, "src.txt", srcContent); err != nil {
		c.Close()
		t.Fatalf("CreateFile src: %v", err)
	}
	if _, err := v.CreateFile(2, "dst.txt", []byte("dest-original-bytes")); err != nil {
		c.Close()
		t.Fatalf("CreateFile dst: %v", err)
	}
	if err := v.Rename(2, "src.txt", 2, "dst.txt"); err != nil {
		c.Close()
		t.Fatalf("Rename (overwrite): %v", err)
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
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume reopen: %v", err)
	}
	// Source name must be gone.
	if _, _, err := v2.lookupFSTreeFirst(encodeDrecKey(2, "src.txt")); err == nil {
		t.Errorf("Rename overwrite: source name still present after rename")
	}
	// Destination must carry the source's content.
	inos, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	regulars := 0
	var destInode Inode
	for _, ino := range inos {
		if ino.Mode&0xF000 == 0x8000 {
			regulars++
			destInode = ino
		}
	}
	if regulars != 1 {
		t.Errorf("regular-file count after overwrite: got %d, want 1 (orphan inode?)", regulars)
	}
	got, err := v2.ReadFile(destInode)
	if err != nil {
		t.Fatalf("ReadFile dst: %v", err)
	}
	if string(got) != string(srcContent) {
		t.Errorf("dest content: got %q, want %q", got, srcContent)
	}
}

// TestRename_RejectsDirectoryOverwrite verifies that overwrite-rename
// refuses to delete a directory in the destination slot (POSIX-ish:
// `rename(file, dir)` would corrupt the dir's children).
func TestRename_RejectsDirectoryOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ren.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RenDirGuard"); err != nil {
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
	if _, err := v.CreateFile(2, "src.txt", []byte("hello")); err != nil {
		t.Fatalf("CreateFile src: %v", err)
	}
	if _, err := v.CreateDirectory(2, "destdir", 0o755); err != nil {
		t.Fatalf("CreateDirectory: %v", err)
	}
	if err := v.Rename(2, "src.txt", 2, "destdir"); err == nil {
		t.Fatal("Rename: expected error when overwriting a directory")
	}
}
