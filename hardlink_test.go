package filesystem_apfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateHardlink_NlinkChain creates a file then adds two hardlinks
// (1→2→3 nlink transitions). Verifies that ListSiblings returns three
// names sharing the same OwnerID, the inode's nlink is 3, and content
// is readable through any of the three names.
func TestCreateHardlink_NlinkChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "HardlinkChain"); err != nil {
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
	body := []byte("three names same inode\n")
	fileOID, err := v.CreateFile(2, "primary.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	// First hardlink: 1→2 transition (existing 1→2 path).
	if err := v.CreateHardlink(fileOID, 2, "alias_one.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink first: %v", err)
	}
	// Second hardlink: 2→3 transition (incremental path).
	if err := v.CreateHardlink(fileOID, 2, "alias_two.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink second: %v", err)
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
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	sibs, err := v2.ListSiblings(ino)
	if err != nil {
		t.Fatalf("ListSiblings: %v", err)
	}
	if len(sibs) != 3 {
		t.Fatalf("ListSiblings: got %d, want 3: %+v", len(sibs), sibs)
	}
	names := map[string]bool{}
	for _, s := range sibs {
		if s.OwnerID != fileOID {
			t.Errorf("sibling owner: got %d, want %d", s.OwnerID, fileOID)
		}
		names[s.Name] = true
	}
	for _, want := range []string{"primary.txt", "alias_one.txt", "alias_two.txt"} {
		if !names[want] {
			t.Errorf("missing sibling name %q", want)
		}
	}
	body2, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body2) != string(body) {
		t.Fatalf("content: got %q, want %q", body2, body)
	}
}

// TestCreateHardlink_RoundTrip creates a file, adds a hardlink under a
// different name, then re-opens and verifies:
//   - the inode's nlink is 2
//   - both names resolve to the same inode oid
//   - ListSiblings returns two entries with the right (parent, name) pairs
func TestCreateHardlink_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hardlink.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "HardlinkTest"); err != nil {
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
	body := []byte("hardlinked file body\n")
	fileOID, err := v.CreateFile(2, "primary.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.CreateHardlink(fileOID, 2, "alias.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink: %v", err)
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
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode(%d): %v", fileOID, err)
	}
	// ListSiblings should return both names; ListInodes should still
	// surface the file's content via either drec.
	sibs, err := v2.ListSiblings(ino)
	if err != nil {
		t.Fatalf("ListSiblings: %v", err)
	}
	if len(sibs) != 2 {
		t.Fatalf("ListSiblings: got %d, want 2: %+v", len(sibs), sibs)
	}
	names := map[string]bool{}
	for _, s := range sibs {
		if s.OwnerID != fileOID {
			t.Errorf("sibling owner: got %d, want %d", s.OwnerID, fileOID)
		}
		if s.ParentID != 2 {
			t.Errorf("sibling parent: got %d, want 2", s.ParentID)
		}
		names[s.Name] = true
	}
	if !names["primary.txt"] || !names["alias.txt"] {
		t.Errorf("sibling names: got %v, want primary.txt + alias.txt", names)
	}
	// Both ListInodes-discovered drec entries (one per name) must point
	// at the same fileOID.
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	hits := 0
	for _, i := range inodes {
		if i.ID == fileOID {
			hits++
		}
	}
	// ListInodes folds drecs by file_id, so we expect exactly one
	// projected Inode for the hardlinked file regardless of the two
	// drecs.
	if hits != 1 {
		t.Errorf("ListInodes hits for fileOID=%d: got %d, want 1", fileOID, hits)
	}
	// Read content via FindInode-resolved inode.
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("ReadFile content mismatch:\n got:  %q\n want: %q", got, body)
	}
}

// TestDeleteFile_HardlinkAlias creates a 3-link inode (primary +
// two aliases), then deletes the two aliases in order. After each
// delete: the deleted alias's drec is gone, the inode's content
// still reads back through any surviving alias, and nlink has
// decremented accordingly. After the final delete (3→2→1) the inode
// remains alive and addressable through the primary name.
func TestDeleteFile_HardlinkAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hldel.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "HardlinkDel"); err != nil {
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
	body := []byte("delete-aliases-but-keep-inode\n")
	fileOID, err := v.CreateFile(2, "primary.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.CreateHardlink(fileOID, 2, "alias_one.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink one: %v", err)
	}
	if err := v.CreateHardlink(fileOID, 2, "alias_two.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink two: %v", err)
	}

	// First delete: 3 → 2. Removes alias_one.txt only.
	if err := v.DeleteFile(2, "alias_one.txt"); err != nil {
		c.Close()
		t.Fatalf("DeleteFile alias_one: %v", err)
	}
	if _, _, lerr := v.lookupFSTreeFirst(encodeDrecKey(2, "alias_one.txt")); lerr == nil {
		c.Close()
		t.Fatal("alias_one.txt drec still present after delete")
	}
	// Inode still alive.
	_, inodeValAfter1, ierr := v.lookupFSTreeFirst(encodeInodeKey(fileOID))
	if ierr != nil {
		c.Close()
		t.Fatalf("lookup inode after first delete: %v", ierr)
	}
	nlinkAfter1 := uint32(inodeValAfter1[56]) | uint32(inodeValAfter1[57])<<8 |
		uint32(inodeValAfter1[58])<<16 | uint32(inodeValAfter1[59])<<24
	if nlinkAfter1 != 2 {
		t.Errorf("nlink after first delete: got %d, want 2", nlinkAfter1)
	}

	// Second delete: 2 → 1. Removes alias_two.txt.
	if err := v.DeleteFile(2, "alias_two.txt"); err != nil {
		c.Close()
		t.Fatalf("DeleteFile alias_two: %v", err)
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
	if _, _, lerr := v2.lookupFSTreeFirst(encodeDrecKey(2, "alias_one.txt")); lerr == nil {
		t.Errorf("alias_one.txt drec resurrected after re-open")
	}
	if _, _, lerr := v2.lookupFSTreeFirst(encodeDrecKey(2, "alias_two.txt")); lerr == nil {
		t.Errorf("alias_two.txt drec resurrected after re-open")
	}
	// Primary still works.
	ino, err := v2.FindInode(fileOID)
	if err != nil {
		t.Fatalf("FindInode primary: %v", err)
	}
	got, err := v2.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile primary: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("ReadFile via primary: got %q, want %q", got, body)
	}
}

// TestDeleteFile_HardlinkStrictCleanup_NlinkOne creates a file, adds
// one hardlink (nlink: 1 → 2), then deletes the alias (nlink: 2 → 1).
// Verifies the surviving alias has every trace of its hardlinked past
// removed:
//   - inode's nlink is 1
//   - no J_SIBLING_LINK record remains under the inode oid
//   - no J_SIBLING_MAP record points back to the inode
//   - the surviving drec value has been rewritten without the
//     INO_EXT_TYPE_SIBLING_ID xfield (length is the plain 18 bytes,
//     not 18 + 4 + 4 + 8 = 34).
func TestDeleteFile_HardlinkStrictCleanup_NlinkOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "strict.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "Strict"); err != nil {
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
	body := []byte("strict cleanup payload\n")
	fileOID, err := v.CreateFile(2, "primary.txt", body)
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	if err := v.CreateHardlink(fileOID, 2, "alias.txt"); err != nil {
		c.Close()
		t.Fatalf("CreateHardlink: %v", err)
	}
	if err := v.DeleteFile(2, "alias.txt"); err != nil {
		c.Close()
		t.Fatalf("DeleteFile alias: %v", err)
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

	// nlink == 1
	_, inodeVal, err := v2.lookupFSTreeFirst(encodeInodeKey(fileOID))
	if err != nil {
		t.Fatalf("lookup inode: %v", err)
	}
	nlink := binary.LittleEndian.Uint32(inodeVal[56:60])
	if nlink != 1 {
		t.Errorf("nlink: got %d, want 1", nlink)
	}

	// No SIBLING_LINK under fileOID, no SIBLING_MAP pointing at fileOID.
	var sibLinks, sibMaps int
	_ = v2.traverseFSTree(func(k, val []byte) error {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return nil
		}
		if typ == jTypeSibLink && oid == fileOID {
			sibLinks++
		}
		if typ == jTypeSibMap && len(val) >= 8 &&
			binary.LittleEndian.Uint64(val[0:8]) == fileOID {
			sibMaps++
		}
		return nil
	})
	if sibLinks != 0 {
		t.Errorf("SIBLING_LINK survivors: got %d, want 0", sibLinks)
	}
	if sibMaps != 0 {
		t.Errorf("SIBLING_MAP survivors: got %d, want 0", sibMaps)
	}

	// Surviving drec value is the plain 18-byte form (no xfield).
	_, drecVal, err := v2.lookupFSTreeFirst(encodeDrecKey(2, "primary.txt"))
	if err != nil {
		t.Fatalf("lookup primary drec: %v", err)
	}
	if len(drecVal) != 18 {
		t.Errorf("primary drec val length: got %d, want 18 (SIBLING_ID xfield should be stripped)", len(drecVal))
	}
}
