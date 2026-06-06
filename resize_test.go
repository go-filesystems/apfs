package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formatForResize is the shared test setup: format a fresh container,
// optionally bake a few small files into it, and return its on-disk
// path. The default size is comfortably inside chunk 0 (≤ 128 MiB)
// so it exercises the single-chunk regime resize.go currently
// supports.
func formatForResize(t *testing.T, sizeBytes int64, withFiles int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "resize.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, sizeBytes, "ResizeTest"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	if withFiles == 0 {
		return path
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
	for i := 0; i < withFiles; i++ {
		name := fmt.Sprintf("pre-resize-%03d.bin", i)
		payload := []byte(strings.Repeat("x", 256))
		if _, err := v.CreateFile(2 /* root */, name, payload); err != nil {
			c.Close()
			t.Fatalf("CreateFile %s: %v", name, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// readNXBlockCount reads nx_block_count from block 0 without going
// through the high-level container parser. It lets tests verify that
// the on-disk superblock truly carries the post-resize geometry,
// independent of any in-memory state Container holds.
func readNXBlockCount(t *testing.T, path string) uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, 4096)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("read block 0: %v", err)
	}
	return binary.LittleEndian.Uint64(buf[40:48])
}

// TestResize_GrowShrinkRoundTrip exercises the happy path on every
// platform: format → grow → confirm new size + persistence → shrink
// back → confirm size again. After each step we re-open the
// container to make sure the on-disk metadata reflects the change
// (not just the cached in-memory superblock).
func TestResize_GrowShrinkRoundTrip(t *testing.T) {
	const startSize = int64(1 << 22) // 4 MiB
	const grownSize = int64(1 << 23) // 8 MiB
	path := formatForResize(t, startSize, 4)

	// Verify baseline.
	if got := readNXBlockCount(t, path); got != uint64(startSize/4096) {
		t.Fatalf("baseline blockCount=%d want %d", got, startSize/4096)
	}

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	if err := c.Grow(grownSize); err != nil {
		c.Close()
		t.Fatalf("Grow: %v", err)
	}
	if c.sb.blockCount != uint64(grownSize/4096) {
		t.Errorf("post-Grow in-memory blockCount=%d want %d",
			c.sb.blockCount, grownSize/4096)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close after Grow: %v", err)
	}

	if got := readNXBlockCount(t, path); got != uint64(grownSize/4096) {
		t.Errorf("on-disk blockCount after Grow=%d want %d", got, grownSize/4096)
	}
	if st, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	} else if st.Size() != grownSize {
		t.Errorf("file size after Grow=%d want %d", st.Size(), grownSize)
	}

	// Re-open + confirm the file content survives.
	c2, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW after Grow: %v", err)
	}
	v, err := c2.OpenVolume(0)
	if err != nil {
		c2.Close()
		t.Fatalf("OpenVolume after Grow: %v", err)
	}
	inodes, err := v.ListInodes()
	if err != nil {
		c2.Close()
		t.Fatalf("ListInodes after Grow: %v", err)
	}
	preResize := 0
	for _, ino := range inodes {
		if strings.HasPrefix(ino.Name, "pre-resize-") {
			preResize++
		}
	}
	if preResize != 4 {
		t.Errorf("pre-resize files after Grow=%d want 4", preResize)
	}

	// Shrink back to the original size. With only metadata + 4 small
	// files allocated, the bitmap should be clear above the boundary,
	// so the operation should succeed.
	if err := c2.Shrink(startSize); err != nil {
		c2.Close()
		t.Fatalf("Shrink: %v", err)
	}
	if c2.sb.blockCount != uint64(startSize/4096) {
		t.Errorf("post-Shrink in-memory blockCount=%d want %d",
			c2.sb.blockCount, startSize/4096)
	}
	if err := c2.Close(); err != nil {
		t.Fatalf("Close after Shrink: %v", err)
	}
	if got := readNXBlockCount(t, path); got != uint64(startSize/4096) {
		t.Errorf("on-disk blockCount after Shrink=%d want %d", got, startSize/4096)
	}
}

// TestResize_ErrShrinkUnsupported verifies the sentinel surfaces when
// any block ≥ newBlocks is still marked allocated. We engineer the
// failure by setting newBlocks below the format-time metadata
// footprint (blocks 0..formatMetadataBlocks-1 are unconditionally
// marked allocated by the format-time bitmap). The path-of-least-
// resistance is to request a size at the lower bound + epsilon and
// verify the sentinel propagates through errors.Is.
func TestResize_ErrShrinkUnsupported(t *testing.T) {
	const startSize = int64(1 << 22) // 4 MiB = 1024 blocks
	path := formatForResize(t, startSize, 0)

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()

	// formatMetadataBlocks (91 at the time of writing) is the highest
	// block the format-time bitmap marks as allocated. Targeting a
	// boundary BELOW that high-water mark guarantees the chunk-bitmap
	// guard fires.
	belowMeta := int64(formatMetadataBlocks-1) * 4096
	// Container.resizeLocked normally rejects "below metadata" with a
	// different error (formatMetadataBlocks floor). We want the
	// SHRINK-UNSUPPORTED sentinel, so we have to provoke it where
	// newBlocks ≥ formatMetadataBlocks but a higher block is still
	// allocated. CreateFile a single small file: its data block
	// allocates somewhere in chunk 0 above the metadata floor, and
	// shrinking to JUST that boundary trips the guard.
	if belowMeta <= 0 {
		t.Skip("formatMetadataBlocks layout makes this test ill-defined")
	}

	// Path 1: confirm the floor-error path is distinguishable from
	// ErrShrinkUnsupported. (The error returned for "below the
	// metadata floor" is intentionally NOT the sentinel — it's a
	// formatted error message — so errors.Is returns false there.)
	err = c.Shrink(int64(formatMetadataBlocks/2) * 4096)
	if err == nil {
		t.Fatal("Shrink to below metadata floor: want error, got nil")
	}
	if errors.Is(err, ErrShrinkUnsupported) {
		t.Errorf("below-floor error must NOT wrap ErrShrinkUnsupported (got %v)", err)
	}

	// Path 2: allocate a file via CreateFile so its extent lives
	// somewhere above formatMetadataBlocks, then Shrink to a size
	// that drops below that extent — the sentinel must fire.
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	payload := []byte(strings.Repeat("y", 4096))
	if _, err := v.CreateFile(2 /* root */, "doomed.bin", payload); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	// The freshly-allocated extent sits at some block N ≥
	// formatMetadataBlocks. Computing N exactly would require walking
	// the FS-tree; the simpler path is to ask for the smallest legal
	// shrink (newBlocks == formatMetadataBlocks). If there's any
	// allocation above that boundary — which there now is — the
	// sentinel fires.
	tinyBytes := int64(formatMetadataBlocks) * 4096
	err = c.Shrink(tinyBytes)
	if err == nil {
		t.Fatalf("Shrink to %d: want ErrShrinkUnsupported, got nil", tinyBytes)
	}
	if !errors.Is(err, ErrShrinkUnsupported) {
		t.Fatalf("Shrink: want errors.Is(err, ErrShrinkUnsupported), got %v", err)
	}
}

// TestResize_Dispatch exercises the Resize convenience entry point in
// every direction: no-op, grow, shrink. It also confirms that the
// pre-condition errors (non-blocksize multiple, zero/negative) are
// reported as plain errors rather than the sentinel.
func TestResize_Dispatch(t *testing.T) {
	const startSize = int64(1 << 22) // 4 MiB
	path := formatForResize(t, startSize, 0)

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()

	// No-op: same size.
	if err := c.Resize(startSize); err != nil {
		t.Fatalf("Resize no-op: %v", err)
	}
	if c.sb.blockCount != uint64(startSize/4096) {
		t.Errorf("no-op changed blockCount: got %d", c.sb.blockCount)
	}

	// Grow path.
	if err := c.Resize(startSize * 2); err != nil {
		t.Fatalf("Resize grow: %v", err)
	}
	if c.sb.blockCount != uint64(startSize*2/4096) {
		t.Errorf("Resize grow blockCount=%d want %d", c.sb.blockCount, startSize*2/4096)
	}

	// Shrink path.
	if err := c.Resize(startSize); err != nil {
		t.Fatalf("Resize shrink: %v", err)
	}
	if c.sb.blockCount != uint64(startSize/4096) {
		t.Errorf("Resize shrink blockCount=%d want %d", c.sb.blockCount, startSize/4096)
	}

	// Invalid: not a block-size multiple.
	if err := c.Resize(startSize + 100); err == nil {
		t.Fatal("Resize with non-block-aligned size: want error")
	}
	// Invalid: zero/negative.
	if err := c.Resize(0); err == nil {
		t.Fatal("Resize(0): want error")
	}
	if err := c.Resize(-1); err == nil {
		t.Fatal("Resize(-1): want error")
	}
}

// TestResize_RejectsCrossChunk confirms the multi-chunk gate fires.
// blocksPerChunkConst = 32768 = 128 MiB; growing past that requires a
// fresh chunk_info_block which the current implementation does not
// synthesise.
func TestResize_RejectsCrossChunk(t *testing.T) {
	const startSize = int64(1 << 23) // 8 MiB
	path := formatForResize(t, startSize, 0)
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	// blocksPerChunkConst * 4096 = 128 MiB. Adding one block crosses it.
	newSize := int64(blocksPerChunkConst+1) * 4096
	err = c.Grow(newSize)
	if err == nil {
		t.Fatal("Grow past chunk boundary: want error, got nil")
	}
	if !errors.Is(err, ErrResizeUnsupported) {
		t.Fatalf("cross-chunk Grow: want errors.Is ErrResizeUnsupported, got %v", err)
	}
}

// TestResize_ReadOnlyRejection confirms that resize APIs respect the
// container's read-only state.
func TestResize_ReadOnlyRejection(t *testing.T) {
	const startSize = int64(1 << 22)
	path := formatForResize(t, startSize, 0)
	c, err := OpenContainer(path) // read-only
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	if err := c.Grow(startSize * 2); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Grow on RO: want ErrReadOnly, got %v", err)
	}
	if err := c.Shrink(startSize / 2); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Shrink on RO: want ErrReadOnly, got %v", err)
	}
	if err := c.Resize(startSize * 2); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Resize on RO: want ErrReadOnly, got %v", err)
	}
}

// TestResize_HighestAllocatedBlock unit-tests the bitmap-walking
// helper without going through the full resize cascade. It uses
// hand-crafted bitmaps so the table is dense and the boundaries
// exact.
func TestResize_HighestAllocatedBlock(t *testing.T) {
	cases := []struct {
		name        string
		bitmap      []byte
		chunkBlocks uint64
		wantBlock   uint64
		wantOK      bool
	}{
		{"empty", []byte{0x00, 0x00}, 16, 0, false},
		{"bit0", []byte{0x01}, 8, 0, true},
		{"bit7", []byte{0x80}, 8, 7, true},
		{"bit7-plus-bit3", []byte{0x88}, 8, 7, true},
		{"second-byte-bit2", []byte{0x00, 0x04}, 16, 10, true},
		{"chunkBlocks-clips", []byte{0xFF}, 4, 3, true}, // bits 4..7 ignored
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotBlock, gotOK := highestAllocatedBlock(tc.bitmap, tc.chunkBlocks)
			if gotBlock != tc.wantBlock || gotOK != tc.wantOK {
				t.Errorf("highestAllocatedBlock(%x, %d) = (%d, %v), want (%d, %v)",
					tc.bitmap, tc.chunkBlocks, gotBlock, gotOK, tc.wantBlock, tc.wantOK)
			}
		})
	}
}

// TestResize_TruncateBackend_NonTruncator ensures the helper is a
// no-op for backends that do not implement truncator. This protects
// against a future regression where someone adds a panic / error on
// the unsupported branch.
func TestResize_TruncateBackend_NonTruncator(t *testing.T) {
	// Tiny fake that satisfies containerWriter but not truncator.
	fake := &writerNoTruncate{}
	if err := truncateBackend(fake, 1<<20); err != nil {
		t.Fatalf("truncateBackend on non-truncator: want nil, got %v", err)
	}
}

// writerNoTruncate implements containerWriter (WriteAt) without
// truncator. Used to exercise the no-op branch of truncateBackend.
type writerNoTruncate struct{}

func (w *writerNoTruncate) WriteAt(p []byte, off int64) (int, error) { return len(p), nil }
