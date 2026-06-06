package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestExtentRef_PromotesToLevel3 forces the extent-ref tree past its
// level-2 root cap so the cascade in extentRefAppendLevel2 triggers
// promoteExtentRefToLevel3. Mirrors TestExtentRef_PromotesToLevel2
// with both the root AND the non-root internal cap pinned low —
// otherwise the per-block byte limit (~122 children/internal at
// production cluster size) kicks in long before we generate enough
// extents to overflow level 2.
//
// Strategy: insert files in batches and check the root level after
// each commit, stopping as soon as we reach level 3. At production
// caps the same code only fires near ~1.8M extents.
func TestExtentRef_PromotesToLevel3(t *testing.T) {
	prevRoot := extentRefInternalCapEntries
	prevNonRoot := extentRefInternalNonRootCapEntries
	extentRefInternalCapEntries = 2
	extentRefInternalNonRootCapEntries = 2
	defer func() {
		extentRefInternalCapEntries = prevRoot
		extentRefInternalNonRootCapEntries = prevNonRoot
	}()

	if testing.Short() {
		t.Skip("skipping in -short: forces level-3 extent-ref promotion via thousands of inserts")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ext_l3.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<28, "EXTL3"); err != nil {
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

	const batch = 10
	const maxBatches = 100
	reachedLevel3 := false
	totalInserted := 0
	for b := 0; b < maxBatches; b++ {
		for i := 0; i < batch; i++ {
			n := b*batch + i
			name := fmt.Sprintf("e_%05d.bin", n)
			body := []byte{byte('A' + n%26)}
			if _, err := v.CreateFile(2, name, body); err != nil {
				t.Logf("CreateFile %d failed after %d total inserts: %v",
					n, totalInserted, err)
				if reachedLevel3 {
					return
				}
				t.Fatalf("hit overflow before reaching level 3")
			}
			totalInserted++
		}
		if err := c.Commit(); err != nil {
			t.Fatalf("Commit batch %d: %v", b, err)
		}
		rawRoot, err := c.readBlock(v.apsb.extentRefOID)
		if err != nil {
			t.Fatalf("read extent-ref root after batch %d: %v", b, err)
		}
		rootNode, err := readBTreeNode(rawRoot)
		if err != nil {
			t.Fatalf("parse extent-ref root: %v", err)
		}
		t.Logf("after batch %d (%d files): extent-ref root level=%d, nKeys=%d",
			b, totalInserted, rootNode.level, rootNode.nKeys)
		if rootNode.level >= 3 {
			reachedLevel3 = true
			break
		}
	}
	if !reachedLevel3 {
		t.Fatalf("extent-ref never reached level 3 in %d files at cap=2", totalInserted)
	}
}
