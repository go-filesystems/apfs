package filesystem_apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateSymlink_RoundTrip creates a symlink under the volume root,
// commits, and re-opens to verify the inode mode says S_IFLNK and the
// `com.apple.fs.symlink` xattr carries the target string.
func TestCreateSymlink_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sym.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "SymTest"); err != nil {
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
	const target = "/etc/hosts"
	linkOID, err := v.CreateSymlink(2, "myhosts", target)
	if err != nil {
		c.Close()
		t.Fatalf("CreateSymlink: %v", err)
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
	ino, err := v2.FindInode(linkOID)
	if err != nil {
		t.Fatalf("FindInode(%d): %v", linkOID, err)
	}
	// S_IFLNK = 0o120000 — high 4 bits of mode = 0xA.
	if (ino.Mode & 0xF000) != 0xA000 {
		t.Errorf("symlink mode: got 0o%o, want S_IFLNK in high bits", ino.Mode)
	}
	xs, err := v2.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	var found bool
	for _, x := range xs {
		if x.Name == symlinkXAttrName {
			found = true
			if x.Flags&xattrFlagDataEmbedded == 0 {
				t.Errorf("symlink xattr is not embedded (flags=0x%x)", x.Flags)
			}
			// Strip trailing NUL.
			got := x.EmbeddedValue
			if len(got) > 0 && got[len(got)-1] == 0 {
				got = got[:len(got)-1]
			}
			if !bytes.Equal(got, []byte(target)) {
				t.Errorf("symlink target: got %q, want %q", got, target)
			}
		}
	}
	if !found {
		t.Errorf("symlink xattr %q not found in ListXAttrs (got %d xattrs)", symlinkXAttrName, len(xs))
	}
}
