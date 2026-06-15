package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRootPromotion_LiftsCap creates dirs up to where two stacked
// caps almost meet:
//   - The level-1 FS-tree root index can hold ~120 child pointers
//     (each ~30 bytes for dir-keys with hashed names) before
//     overflowing — this is what `promoteRoot` would handle.
//   - The volume OMAP itself is still a single-leaf B-tree, capped
//     at ~110 entries (one per FS-tree leaf, since each split
//     allocates a new oid → new OMAP entry).
//
// In practice the volume OMAP cap is reached FIRST (around 1500 dirs
// = 110 leaves = 110 OMAP entries). The promotion code path is in
// place but isn't exercised in this test until the volume OMAP also
// supports multi-level. We test up to 1000 dirs (well past the prior
// 50-files unit test) and verify the FS-tree handles the size.
func TestRootPromotion_LiftsCap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: creates 2000 dirs to drive multi-level FS-tree + volume-OMAP promotion")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "promote.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "Promote"); err != nil { // 32 MiB
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	// 2000 dirs: now past the volume OMAP single-leaf cap (~110
	// entries), exercises BOTH the multi-level FS-tree write +
	// `refreshRoot` pipeline AND the volume OMAP single-leaf →
	// 2-level promotion path (`promoteVolumeOMAPToTwoLevel`).
	const N = 2000
	createdOIDs := make(map[string]uint64, N)
	for i := 0; i < N; i++ {
		v, err := c.OpenVolume(0)
		if err != nil {
			c.Close()
			t.Fatalf("OpenVolume @ %d: %v", i, err)
		}
		name := fmt.Sprintf("p_%04d", i)
		oid, err := v.CreateDirectory(2, name, 0o755)
		if err != nil {
			c.Close()
			t.Fatalf("CreateDirectory %d (%q): %v", i, name, err)
		}
		createdOIDs[name] = oid
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
		t.Fatalf("OpenVolume re-open: %v", err)
	}
	t.Logf("after %d dirs: FS-tree root level = %d", N, v2.rootNode.level)
	if v2.rootNode.level < 1 {
		t.Errorf("root level: got %d, want ≥ 1 (no leaf splits happened)", v2.rootNode.level)
	}
	// Verify the volume OMAP also got promoted past the single-leaf
	// cap. Read its tree root and check its level — should be 1
	// (level-1 root + level-0 leaves) once we exceed ~110 entries.
	omapRootRaw, _ := c2.readBlock(v2.volOmap.treeOID)
	omapRootNode, _ := readBTreeNode(omapRootRaw)
	t.Logf("after %d dirs: volume OMAP root level = %d", N, omapRootNode.level)
	if omapRootNode.level < 1 {
		t.Errorf("volume OMAP root level: got %d, want ≥ 1 (OMAP didn't split)", omapRootNode.level)
	}
	// Spot-check that every directory is reachable after promotion.
	missing := 0
	inodes, err := v2.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	byName := map[string]Inode{}
	for _, ino := range inodes {
		byName[ino.Name] = ino
	}
	for name, wantOID := range createdOIDs {
		ino, ok := byName[name]
		if !ok {
			missing++
			t.Errorf("dir %q missing after promotion (have %d inodes)", name, len(inodes))
			continue
		}
		if ino.ID != wantOID {
			t.Errorf("dir %q oid: got %d, want %d", name, ino.ID, wantOID)
		}
	}
	if missing == 0 {
		t.Logf("root promotion OK: %d dirs reachable through level=%d FS-tree.", N, v2.rootNode.level)
	}
}
