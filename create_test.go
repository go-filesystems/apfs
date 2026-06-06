package filesystem_apfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateFile_AfterFormat is the headline iteration C-2 test:
// FormatContainer + OpenContainerRW + CreateFile + ReadFile round-trip.
// Every byte of state in the volume — extent payload, J_INODE_VAL,
// J_DIR_REC, J_FILE_EXTENT — has to come from the encoders introduced
// in this iteration; the read parser then has to recognise the whole
// graph and return the file's name + content.
func TestCreateFile_AfterFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Pilot"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	const fileName = "hello.txt"
	payload := []byte("first file written through the native APFS pilot")
	newOID, err := v.CreateFile(1, fileName, payload)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if newOID < 1000 {
		t.Fatalf("expected newOID ≥ 1000, got %d", newOID)
	}
	c.Close()

	// Re-open read-only and verify the file is fully resolvable.
	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("re-OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("re-OpenVolume: %v", err)
	}

	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	var found *Inode
	for i := range inodes {
		if inodes[i].ID == newOID {
			found = &inodes[i]
		}
	}
	if found == nil {
		t.Fatalf("inode %d not found in ListInodes (got %+v)", newOID, inodes)
	}
	if found.Name != fileName {
		t.Fatalf("Name=%q want %q", found.Name, fileName)
	}
	if found.Size != uint64(len(payload)) {
		t.Fatalf("Size=%d want %d", found.Size, len(payload))
	}
	// CreateFile rewrites parentOID == APFS_ROOT_DIR_PARENT (1) to
	// APFS_ROOT_DIR_INO_NUM (2) and bootstraps the canonical root
	// directory so Apple's fsck_apfs accepts the resulting tree.
	if found.ParentID != 2 {
		t.Fatalf("ParentID=%d want 2 (root dir)", found.ParentID)
	}
	got, err := v2.ReadFile(*found)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadFile content mismatch:\n got=%q\nwant=%q", got, payload)
	}
}

// TestCreateFile_MultipleFiles confirms that CreateFile correctly
// allocates fresh oids and disjoint extents across consecutive calls.
func TestCreateFile_MultipleFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Multi"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, _ := c.OpenVolume(0)

	files := []struct {
		name string
		data []byte
	}{
		{"alpha", []byte("payload of alpha")},
		{"beta", []byte("the beta file is a bit longer than alpha")},
		{"gamma", bytes.Repeat([]byte{0x42}, 200)},
	}
	oids := make([]uint64, len(files))
	for i, f := range files {
		oid, err := v.CreateFile(1, f.name, f.data)
		if err != nil {
			t.Fatalf("CreateFile(%q): %v", f.name, err)
		}
		oids[i] = oid
	}
	// All oids must be distinct.
	for i := 0; i < len(oids); i++ {
		for j := i + 1; j < len(oids); j++ {
			if oids[i] == oids[j] {
				t.Fatalf("duplicate oids: %v", oids)
			}
		}
	}
	c.Close()

	// Re-open and confirm all files are present with correct content.
	c2, _ := OpenContainer(path)
	defer c2.Close()
	v2, _ := c2.OpenVolume(0)
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	got := map[string][]byte{}
	for i := range inodes {
		ino := inodes[i]
		if ino.Name == "" || ino.IsDir {
			// Skip directories (e.g. the synthetic root dir bootstrapped
			// by CreateFile so apfs.kext's mount path can locate it).
			continue
		}
		data, err := v2.ReadFile(ino)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", ino.Name, err)
		}
		got[ino.Name] = data
	}
	for _, f := range files {
		if !bytes.Equal(got[f.name], f.data) {
			t.Fatalf("file %q: got %q want %q", f.name, got[f.name], f.data)
		}
	}
}

// TestCreateFile_ThenWriteFile chains iteration B and C:
// CreateFile lays down an inode + first extent; WriteFile then patches
// the size + content on a subsequent OpenContainerRW session.
func TestCreateFile_ThenWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Chain"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, _ := c.OpenVolume(0)
	original := []byte("original content")
	oid, err := v.CreateFile(1, "doc.txt", original)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	c.Close()

	c2, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("re-OpenContainerRW: %v", err)
	}
	v2, _ := c2.OpenVolume(0)
	ino, err := v2.FindInode(oid)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	updated := []byte("rewritten")
	if err := v2.WriteFile(ino, updated); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	c2.Close()

	c3, _ := OpenContainer(path)
	defer c3.Close()
	v3, _ := c3.OpenVolume(0)
	ino3, err := v3.FindInode(oid)
	if err != nil {
		t.Fatalf("re-FindInode: %v", err)
	}
	if ino3.Size != uint64(len(updated)) {
		t.Fatalf("after WriteFile: size=%d want %d", ino3.Size, len(updated))
	}
	got, _ := v3.ReadFile(ino3)
	if !bytes.Equal(got, updated) {
		t.Fatalf("after WriteFile: got %q want %q", got, updated)
	}
}

// TestCreateFile_RejectsReadOnly verifies the read-only guard.
func TestCreateFile_RejectsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "RO"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	if _, err := v.CreateFile(1, "x", []byte("y")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("got %v, want ErrReadOnly", err)
	}
}

// TestCreateFile_RejectsEmptyName verifies the basic input
// validation.
func TestCreateFile_RejectsEmptyName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noname.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "NoName"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	if _, err := v.CreateFile(1, "", []byte("x")); err == nil {
		t.Fatal("expected error for empty name")
	}
}
