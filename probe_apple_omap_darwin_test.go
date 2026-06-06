//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestProbe_AppleMultiLevelOMAP creates a fresh APFS container, mounts
// it via the macOS kext, populates it with thousands of small files
// (forcing the volume OMAP past its single-leaf cap), unmounts, then
// dumps the raw bytes of the volume OMAP root + a sample child leaf.
// Used to byte-diff Apple's exact layout against our writer's, so we
// can fix `emitOMAPInternalRoot` / `emitOMAPNonRootLeaf` to match
// what fsck accepts.
//
// Prints the dumps via t.Logf — run with `-v` and inspect the output.
func TestProbe_AppleMultiLevelOMAP(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "mount_apfs")
	requireTool(t, "diskutil")

	path := filepath.Join(t.TempDir(), "probe.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "Probe"); err != nil { // 16 MiB
		t.Fatalf("FormatContainer: %v", err)
	}

	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		path,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	containerDev := parseHdiutilAttachContainer(t, out)
	t.Logf("hdiutil attach output:\n%s", out)
	t.Logf("parsed containerDev = %q", containerDev)
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", containerDev).Run() })

	volDev := containerDev + "s1"
	t.Logf("trying mount_apfs %q", volDev)
	mnt := t.TempDir()
	if mountOut, err := exec.Command("mount_apfs", volDev, mnt).CombinedOutput(); err != nil {
		t.Fatalf("mount_apfs: %v\n%s", err, mountOut)
	}

	// Create 2500 small files — many enough to force the volume OMAP
	// to multi-level.
	for i := 0; i < 2500; i++ {
		name := filepath.Join(mnt, fmt.Sprintf("f_%05d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			exec.Command("diskutil", "unmount", mnt).Run()
			t.Fatalf("WriteFile %d: %v", i, err)
		}
	}

	if err := exec.Command("diskutil", "unmount", mnt).Run(); err != nil {
		t.Fatalf("diskutil unmount: %v", err)
	}
	if err := exec.Command("hdiutil", "detach", "-force", containerDev).Run(); err != nil {
		t.Fatalf("hdiutil detach: %v", err)
	}

	// Now read the bytes through our parser to find the volume OMAP
	// root paddr.
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	omapRootPaddr := v.volOmap.treeOID
	rootRaw, err := c.readBlock(omapRootPaddr)
	if err != nil {
		t.Fatalf("read OMAP root: %v", err)
	}
	rootNode, err := readBTreeNode(rootRaw)
	if err != nil {
		t.Fatalf("parse OMAP root: %v", err)
	}
	t.Logf("=== Apple-authored volume OMAP root @ paddr %d ===", omapRootPaddr)
	t.Logf("level=%d, nKeys=%d", rootNode.level, rootNode.nKeys)
	if rootNode.level < 1 {
		t.Fatalf("Apple's OMAP didn't promote — only %d entries fit a single leaf", rootNode.nKeys)
	}
	// Dump the relevant header + trailer bytes.
	const blockSize = 4096
	t.Logf("obj_phys[0:32]: %x", rootRaw[:32])
	t.Logf("btn header[32:56]: flags=%04x level=%04x nkeys=%08x table_space=%04x:%04x free_space=%04x:%04x key_free=%04x:%04x val_free=%04x:%04x",
		binary.LittleEndian.Uint16(rootRaw[32:34]),
		binary.LittleEndian.Uint16(rootRaw[34:36]),
		binary.LittleEndian.Uint32(rootRaw[36:40]),
		binary.LittleEndian.Uint16(rootRaw[40:42]),
		binary.LittleEndian.Uint16(rootRaw[42:44]),
		binary.LittleEndian.Uint16(rootRaw[44:46]),
		binary.LittleEndian.Uint16(rootRaw[46:48]),
		binary.LittleEndian.Uint16(rootRaw[48:50]),
		binary.LittleEndian.Uint16(rootRaw[50:52]),
		binary.LittleEndian.Uint16(rootRaw[52:54]),
		binary.LittleEndian.Uint16(rootRaw[54:56]))
	t.Logf("btreeInfo trailer[blockSize-40:blockSize]:")
	for i := 0; i < 40; i += 4 {
		off := blockSize - 40 + i
		t.Logf("  +%2d: %08x", i, binary.LittleEndian.Uint32(rootRaw[off:off+4]))
	}
	// Dump the first 3 TOC entries (4 bytes each if FIXED, 8 bytes
	// each if variable). Show as hex so we can decode either way.
	t.Logf("first 32 bytes of TOC (data area starts at byte 56):")
	for i := 0; i < 32; i += 8 {
		t.Logf("  +%2d: %x", 56+i, rootRaw[56+i:56+i+8])
	}
	// Dump the first 3 keys (16 bytes each, located after the TOC).
	tableSpaceLen := binary.LittleEndian.Uint16(rootRaw[42:44])
	keyAreaStart := 56 + int(tableSpaceLen)
	t.Logf("first 3 keys at +%d (16-byte oid+xid pairs):", keyAreaStart)
	for i := 0; i < 3 && keyAreaStart+i*16+16 <= blockSize; i++ {
		k := rootRaw[keyAreaStart+i*16 : keyAreaStart+i*16+16]
		oid := binary.LittleEndian.Uint64(k[0:8])
		xid := binary.LittleEndian.Uint64(k[8:16])
		t.Logf("  key[%d]: oid=%d xid=%d (%x)", i, oid, xid, k)
	}
	// Dump the first 3 values (each is some N bytes from the val_end
	// backward; for FIXED OMAP root, val_end = blockSize - 40).
	valEnd := blockSize - 40
	t.Logf("first 3 values from val_end=%d backward (16 bytes each, treating as 16-byte slots):", valEnd)
	for i := 0; i < 3; i++ {
		off := valEnd - (i+1)*16
		if off < 0 {
			break
		}
		v := rootRaw[off : off+16]
		t.Logf("  val[%d] @ +%d: %x  (first 8 as paddr=%d)", i, off, v, binary.LittleEndian.Uint64(v[0:8]))
	}
	// Also try interpreting as 8-byte values (in case Apple uses that).
	t.Logf("first 3 values from val_end=%d backward (8 bytes each):", valEnd)
	for i := 0; i < 3; i++ {
		off := valEnd - (i+1)*8
		if off < 0 {
			break
		}
		v := rootRaw[off : off+8]
		t.Logf("  val[%d] @ +%d: %x  (paddr=%d)", i, off, v, binary.LittleEndian.Uint64(v[0:8]))
	}
}
