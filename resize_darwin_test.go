//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGrowShrinkThenFsckApfs is the Darwin compatibility gate: format
// a small container, write a couple of files, Grow, then Shrink back,
// and submit the result to `fsck_apfs -n`. Anything fsck rejects
// indicates a bookkeeping inconsistency between the NX SB, the
// spaceman, the CIB, and the bitmap.
//
// hdiutil attach is needed to get a /dev path fsck_apfs can read; the
// test detaches in t.Cleanup regardless of outcome.
func TestGrowShrinkThenFsckApfs(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "fsck_apfs")

	dir := t.TempDir()
	path := filepath.Join(dir, "resize-fsck.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	const startSize = int64(1 << 22) // 4 MiB
	const grownSize = int64(1 << 23) // 8 MiB
	if err := FormatContainer(path, startSize, "ResizeFsck"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	// Write two files BEFORE the resize so fsck has something to
	// cross-check (FS-tree extents must point at blocks the bitmap
	// marks as allocated).
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	for i := 0; i < 2; i++ {
		name := strings.Repeat("a", i+1) + "_resize.bin"
		if _, err := v.CreateFile(2, name, []byte("payload-"+name)); err != nil {
			c.Close()
			t.Fatalf("CreateFile %s: %v", name, err)
		}
	}
	if err := c.Grow(grownSize); err != nil {
		c.Close()
		t.Fatalf("Grow: %v", err)
	}
	if err := c.Shrink(startSize); err != nil {
		c.Close()
		t.Fatalf("Shrink: %v", err)
	}
	if err := c.Commit(); err != nil {
		c.Close()
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		path,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := strings.Fields(strings.TrimSpace(string(out)))[0]
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", dev).Run() })

	fsckOut, fsckErr := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	if fsckErr != nil {
		t.Fatalf("fsck_apfs after Grow+Shrink failed: %v\n%s", fsckErr, fsckOut)
	}
	t.Logf("fsck_apfs after Grow+Shrink clean:\n%s", fsckOut)
}
