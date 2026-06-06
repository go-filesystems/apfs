package filesystem_apfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTimestamps_OverwriteUpdatesMtime verifies that OverwriteFile
// advances the inode's mod_time + change_time. Reads the inode val
// directly via lookupFSTreeFirst (the higher-level Inode struct
// doesn't surface the timestamps).
func TestTimestamps_OverwriteUpdatesMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ts.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "TSTest"); err != nil {
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
	fileOID, err := v.CreateFile(2, "x.txt", []byte("a"))
	if err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	createMtime := readInodeMtime(t, v, fileOID)
	// Sleep enough for time.Now() to advance by ≥ 1 nanosecond resolution
	// across all platforms. 5ms is generous and reliable.
	time.Sleep(5 * time.Millisecond)
	if err := v.OverwriteFile(fileOID, []byte("ab")); err != nil {
		c.Close()
		t.Fatalf("OverwriteFile: %v", err)
	}
	overwriteMtime := readInodeMtime(t, v, fileOID)
	if overwriteMtime <= createMtime {
		t.Errorf("OverwriteFile did not advance mtime: create=%d overwrite=%d",
			createMtime, overwriteMtime)
	}
	c.Close()
}

// readInodeMtime reads the J_DSTREAM-bearing inode at oid and returns
// its mod_time field (apfs_inode_val +24).
func readInodeMtime(t *testing.T, v *Volume, oid uint64) uint64 {
	t.Helper()
	_, val, err := v.lookupFSTreeFirst(encodeInodeKey(oid))
	if err != nil {
		t.Fatalf("lookupFSTreeFirst: %v", err)
	}
	if len(val) < 32 {
		t.Fatalf("inode val too short: %d", len(val))
	}
	return binary.LittleEndian.Uint64(val[24:32])
}
