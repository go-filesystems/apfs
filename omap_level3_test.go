package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestOMAP_PromotesToLevel3 forces the volume OMAP past the level-2
// root cap so the cascade in upsertVolumeOMAPLevel2 triggers
// promoteOMAPRootToLevel3.
//
// Strategy: lower omapInternalRootCap to 2 (so the cap-vs-natural
// growth window is tight), insert files in batches, and check the
// OMAP root level after each commit. We stop as soon as we reach
// level 3 — overshooting would trigger the (still-unimplemented)
// level-4 promotion, which is correctly rejected by our code but
// not what this test is asserting.
//
// At production cap (~122) the same cascade only fires near ~1.8M
// OMAP entries.
func TestOMAP_PromotesToLevel3(t *testing.T) {
	prev := omapInternalRootCap
	omapInternalRootCap = 2
	defer func() { omapInternalRootCap = prev }()

	if testing.Short() {
		t.Skip("skipping in -short: forces level-3 promotion via thousands of small inserts")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "omap_l3.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<28, "OMAPL3"); err != nil {
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

	// Insert in batches of 100; after each batch, re-read the
	// OMAP root and check its level. Stop as soon as we reach
	// level 3 (the goal) or N exceeds the safety cap.
	const batch = 100
	const maxBatches = 30 // 3000 total — overshoots heavily at cap=2 but we'll bail out early
	reachedLevel3 := false
	totalInserted := 0
	for b := 0; b < maxBatches; b++ {
		for i := 0; i < batch; i++ {
			n := b*batch + i
			name := fmt.Sprintf("f_%05d.bin", n)
			body := []byte{byte('A' + n%26)}
			if _, err := v.CreateFile(2, name, body); err != nil {
				// Hitting the level-4 "not supported" wall means the
				// cascade went one further than this test asserts —
				// we expected to stop at level 3 before that.
				t.Logf("CreateFile %d failed after %d total inserts: %v",
					n, totalInserted, err)
				if reachedLevel3 {
					return // we already reached the goal; subsequent overflow is fine
				}
				t.Fatalf("hit overflow before reaching level 3")
			}
			totalInserted++
		}
		if err := c.Commit(); err != nil {
			t.Fatalf("Commit batch %d: %v", b, err)
		}
		rawRoot, err := c.readBlock(v.volOmap.treeOID)
		if err != nil {
			t.Fatalf("read OMAP root after batch %d: %v", b, err)
		}
		rootNode, err := readBTreeNode(rawRoot)
		if err != nil {
			t.Fatalf("parse OMAP root: %v", err)
		}
		t.Logf("after batch %d (%d files): OMAP root level=%d, nKeys=%d",
			b, totalInserted, rootNode.level, rootNode.nKeys)
		if rootNode.level >= 3 {
			reachedLevel3 = true
			break
		}
	}
	if !reachedLevel3 {
		t.Fatalf("OMAP never reached level 3 in %d files at cap=2", totalInserted)
	}
}
