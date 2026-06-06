package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCommit_RingBufferWrap commits 20+ times in a row, exceeding the
// 8-slot descriptor area FormatContainer reserves. Without
// ring-buffer wrap each commit consumes 2 desc slots and ~4 data
// slots, so the suite would fail at the 3rd or 4th commit with
// "descriptor area exhausted". With wrap, the ring keeps recycling
// the oldest checkpoint's slots and the volume stays mountable
// through arbitrarily many commits.
//
// Verifies after re-open that:
//   - The latest file written is readable.
//   - The volume's xid has advanced past the original 2.
//   - `xp_desc_index` (the on-disk pointer to the latest checkpoint)
//     references a slot < `xp_desc_blocks` (i.e. wrap actually
//     produced a slot in [0, capacity)).
func TestCommit_RingBufferWrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "WrapTest"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	const N = 20
	var lastFileOID uint64
	var lastBody []byte
	for i := 0; i < N; i++ {
		c, err := OpenContainerRW(path)
		if err != nil {
			t.Fatalf("OpenContainerRW iter %d: %v", i, err)
		}
		v, err := c.OpenVolume(0)
		if err != nil {
			c.Close()
			t.Fatalf("OpenVolume iter %d: %v", i, err)
		}
		body := []byte(fmt.Sprintf("iter-%d-payload", i))
		oid, err := v.CreateFile(2, fmt.Sprintf("f_%02d.txt", i), body)
		if err != nil {
			c.Close()
			t.Fatalf("CreateFile iter %d: %v", i, err)
		}
		if err := c.Commit(); err != nil {
			c.Close()
			t.Fatalf("Commit iter %d: %v", i, err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("Close iter %d: %v", i, err)
		}
		lastFileOID = oid
		lastBody = body
	}

	// Re-open one last time and verify the latest file made it through.
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer after %d commits: %v", N, err)
	}
	defer c.Close()
	if c.sb.xid <= 2 {
		t.Errorf("xid did not advance: %d (want > 2 after %d commits)", c.sb.xid, N)
	}
	if c.sb.xpDescIndex >= c.sb.xpDescBlocks {
		t.Errorf("xpDescIndex out of range: %d ≥ capacity %d", c.sb.xpDescIndex, c.sb.xpDescBlocks)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume after wrap: %v", err)
	}
	ino, err := v.FindInode(lastFileOID)
	if err != nil {
		t.Fatalf("FindInode last file: %v", err)
	}
	got, err := v.ReadFile(ino)
	if err != nil {
		t.Fatalf("ReadFile last file: %v", err)
	}
	if string(got) != string(lastBody) {
		t.Errorf("last file content: got %q, want %q", got, lastBody)
	}
}
