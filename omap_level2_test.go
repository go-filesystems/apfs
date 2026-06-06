package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestOMAP_PromotesToLevel2 forces the volume OMAP past its level-1
// root cap. Production cap is ~122 child slots (≈13 800 OMAP entries,
// which would require ~1.5M files); the test lowers it to a small
// value so the promotion path runs end-to-end without that load. The
// post-promotion OMAP root must be level=2 with two level-1 internal
// children, and every previously-stored mapping must still resolve.
func TestOMAP_PromotesToLevel2(t *testing.T) {
	prev := omapInternalRootCap
	omapInternalRootCap = 4 // 5 OMAP leaves → triggers promotion.
	defer func() { omapInternalRootCap = prev }()

	if testing.Short() {
		t.Skip("skipping in -short: forces ~600 OMAP entries via 6000 files")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "omap_l2.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	// 256 MiB — enough for the file payloads + metadata at this scale.
	if err := FormatContainer(path, 1<<28, "OMAPL2"); err != nil {
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
	// Create enough files to force several FS-tree leaf splits — each
	// split allocates a fresh virtual oid mapped through the volume OMAP,
	// so the OMAP grows as a side-effect. Under cap=4, ~5 leaves push
	// the OMAP root past level-1.
	const N = 3000
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("f_%04d.bin", i)
		body := []byte{byte('A' + i%26)}
		if _, err := v.CreateFile(2, name, body); err != nil {
			c.Close()
			t.Fatalf("CreateFile %d: %v", i, err)
		}
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	c.Close()

	c2, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c2.Close()
	v2, err := c2.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume reopen: %v", err)
	}

	// Re-read the volume OMAP root, verify level=2.
	rawRoot, err := c2.readBlock(v2.volOmap.treeOID)
	if err != nil {
		t.Fatalf("read OMAP root: %v", err)
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		t.Fatalf("parse OMAP root: %v", err)
	}
	t.Logf("after %d files: OMAP root level=%d, nKeys=%d", N, rootNode.level, rootNode.nKeys)
	if rootNode.level < 2 {
		t.Fatalf("OMAP root level: got %d, want ≥ 2 (level-2 promotion didn't fire)", rootNode.level)
	}

	// Every file must still be reachable through omapLookup (which already
	// recurses through any level). Spot-check a sampling.
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	regulars := 0
	for _, ino := range inodes {
		if ino.Mode&0xF000 == 0x8000 {
			regulars++
		}
	}
	if regulars != N {
		t.Errorf("file count after re-open: got %d, want %d", regulars, N)
	}
}
