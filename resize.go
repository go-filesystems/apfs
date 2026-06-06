// resize.go — container Grow / Shrink / Resize.
//
// Apple's `diskutil apfs resizeContainer` reshapes a live APFS container
// in two regimes:
//
//   - Grow:   extend nx_block_count, extend the spaceman's chunk-info
//             range, extend the chunk allocation bitmap, expand the
//             backing storage.
//   - Shrink: refuse if anything is still allocated above newSize;
//             otherwise relocate / drop trailing data, reduce the
//             spaceman bookkeeping, and trim the backing storage.
//
// The implementation here covers the single-chunk regime that all of
// this package's test sizes (≤ 128 MiB = blocksPerChunk * 4 KiB) fall
// into. Growth that crosses a chunk boundary requires allocating a
// fresh chunk_info_block / allocation bitmap; that is intentionally
// out of scope for this iteration (returns ErrResizeUnsupported with
// a precise message). Shrink relocation of extents above the new
// boundary is similarly out of scope: when any block ≥ newBlocks is
// marked allocated in the chunk bitmap, Shrink returns
// ErrShrinkUnsupported so callers can fall back to defragmentation
// or refuse the operation cleanly.
//
// All write paths re-Fletcher-seal mutated blocks and update both the
// live NX SB at block 0 AND the current desc-area copy that fsck_apfs
// cross-checks. The order is consistent with Commit's crash-safe
// cascade (desc copy first, then block 0).

package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// ErrResizeUnsupported is returned when a Grow/Shrink would require
// allocating a fresh chunk_info_block (i.e. cross a 128 MiB chunk
// boundary). The single-chunk regime covers every test container in
// this package; a future iteration will lift the restriction.
var ErrResizeUnsupported = errors.New("apfs: resize crosses chunk boundary (not implemented)")

// ErrShrinkUnsupported is returned by Shrink when at least one block
// at or above the requested new boundary is still marked allocated in
// the spaceman bitmap. Relocating those extents downward would
// require a pure-Go defragmenter, which is out of scope here.
var ErrShrinkUnsupported = errors.New("apfs: shrink would lose allocated extents (relocation not implemented)")

// truncator is the optional capability a backend exposes when its
// physical extent can be trimmed / extended via Truncate. *os.File
// satisfies it; in-memory backends (bytes.Buffer-style) typically do
// not, in which case Grow/Shrink falls back to a "no truncate" path
// — extending zero-fill is handled by the OS for a Truncate-capable
// backend, and for non-truncate backends the caller is expected to
// have sized the backing storage appropriately upfront.
type truncator interface {
	Truncate(size int64) error
}

// blocksPerChunkConst is the spaceman's blocks-per-chunk constant
// (Apple's APFS uses 32768 = 128 MiB at 4 KiB blocks). It is the
// inflection point between single-chunk and multi-chunk regimes;
// resize within a single chunk only touches CIB[0] and bitmap[0].
const blocksPerChunkConst uint64 = 32768

// Grow extends the container to at least newSizeBytes. The growth is
// rejected when newSizeBytes is not strictly larger than the current
// container, when it would require a new spaceman chunk, or when the
// container is read-only. On success the NX superblock, spaceman, and
// chunk_info_block are all updated and the backing storage is
// extended where the backend supports Truncate.
func (c *Container) Grow(newSizeBytes int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resizeLocked(newSizeBytes, growDirection)
}

// Shrink reduces the container to exactly newSizeBytes. The operation
// is rejected when newSizeBytes is not strictly smaller than the
// current container, when any block ≥ newBlocks is allocated, when
// it would require a new spaceman chunk (i.e. shrink to less than
// formatMetadataBlocks * blockSize), or when the container is
// read-only. On success the spaceman, chunk_info_block, and NX
// superblock all advertise the smaller geometry and (for a
// Truncate-capable backend) the underlying file is trimmed.
func (c *Container) Shrink(newSizeBytes int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resizeLocked(newSizeBytes, shrinkDirection)
}

// Resize is a convenience dispatcher: it computes the direction from
// the current container size and forwards to Grow or Shrink. A
// no-op (newSizeBytes equal to the current size) returns nil.
func (c *Container) Resize(newSizeBytes int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sb == nil {
		return fmt.Errorf("apfs: Resize: container superblock not loaded")
	}
	curBytes := int64(c.sb.blockCount) * int64(c.sb.blockSize)
	switch {
	case newSizeBytes == curBytes:
		return nil
	case newSizeBytes > curBytes:
		return c.resizeLocked(newSizeBytes, growDirection)
	default:
		return c.resizeLocked(newSizeBytes, shrinkDirection)
	}
}

// resizeDirection enumerates the two resize regimes. Internal helper
// shared between Grow / Shrink / Resize so the validation cascade and
// the on-disk update sequence stay in lock-step.
type resizeDirection int

const (
	growDirection resizeDirection = iota
	shrinkDirection
)

// resizeLocked implements Grow / Shrink under the container lock.
// Validates the request, resolves the spaceman / CIB / bitmap chain,
// performs the direction-specific update, and persists the new
// blockCount in the NX superblock at block 0 + the desc-area copy.
func (c *Container) resizeLocked(newSizeBytes int64, dir resizeDirection) error {
	if c.w == nil {
		return ErrReadOnly
	}
	if c.sb == nil {
		return fmt.Errorf("apfs: resize: container superblock not loaded")
	}
	bs := uint64(c.sb.blockSize)
	if bs == 0 {
		return fmt.Errorf("apfs: resize: zero block size")
	}
	if newSizeBytes <= 0 {
		return fmt.Errorf("apfs: resize: invalid new size %d", newSizeBytes)
	}
	if uint64(newSizeBytes)%bs != 0 {
		return fmt.Errorf("apfs: resize: new size %d is not a multiple of block size %d",
			newSizeBytes, bs)
	}
	newBlocks := uint64(newSizeBytes) / bs
	cur := c.sb.blockCount
	switch dir {
	case growDirection:
		if newBlocks <= cur {
			return fmt.Errorf("apfs: Grow: new block count %d not greater than current %d",
				newBlocks, cur)
		}
	case shrinkDirection:
		if newBlocks >= cur {
			return fmt.Errorf("apfs: Shrink: new block count %d not less than current %d",
				newBlocks, cur)
		}
		if newBlocks < uint64(formatMetadataBlocks) {
			return fmt.Errorf("apfs: Shrink: new block count %d below minimum %d",
				newBlocks, formatMetadataBlocks)
		}
	}

	// Single-chunk gate: both old AND new block counts must fit in
	// chunk 0. Crossing the chunk boundary needs new CIB / bitmap
	// allocations which this iteration does not synthesise.
	if cur > blocksPerChunkConst || newBlocks > blocksPerChunkConst {
		return fmt.Errorf("%w (cur=%d, new=%d, blocksPerChunk=%d)",
			ErrResizeUnsupported, cur, newBlocks, blocksPerChunkConst)
	}

	loc, err := c.locateChunkZero()
	if err != nil {
		return fmt.Errorf("apfs: resize: locate chunk 0: %w", err)
	}
	if loc == nil {
		return fmt.Errorf("apfs: resize: no spaceman / CIB / bitmap chain (cannot resize)")
	}

	// Shrink guard: no allocated block may sit at or above newBlocks.
	// The chunk bitmap is the authoritative ledger — walking it
	// catches both file extents and metadata that bypass FS-tree
	// iteration.
	if dir == shrinkDirection {
		if used, ok := highestAllocatedBlock(loc.bitmap, loc.chunkBlocks); ok && used >= newBlocks {
			return fmt.Errorf("%w: highest used block %d ≥ new boundary %d",
				ErrShrinkUnsupported, used, newBlocks)
		}
	}

	// 1) Update the chunk_info_block: ci_block_count and ci_free_count
	//    move together. On grow the delta is added to ci_free_count
	//    (the new tail blocks start free); on shrink the delta is
	//    subtracted from ci_free_count (the new tail blocks were
	//    already free per the guard above).
	const ciBlockCountOff = 40 + 16 // +0x38: ci_block_count (uint32)
	const ciFreeCountOff = 40 + 20  // +0x3C: ci_free_count (uint32)
	oldChunkBlocks := uint32(loc.chunkBlocks)
	newChunkBlocks := uint32(newBlocks)
	oldFreeCount := binary.LittleEndian.Uint32(loc.cibBlock[ciFreeCountOff : ciFreeCountOff+4])
	var newFreeCount uint32
	switch dir {
	case growDirection:
		delta := newChunkBlocks - oldChunkBlocks
		newFreeCount = oldFreeCount + delta
	case shrinkDirection:
		delta := oldChunkBlocks - newChunkBlocks
		if oldFreeCount < delta {
			// The bitmap guard above already rejected over-allocated
			// shrinks, so this is a defensive check (covers a stale
			// ci_free_count) rather than a user-visible path.
			return fmt.Errorf("apfs: Shrink: ci_free_count %d < shrink delta %d",
				oldFreeCount, delta)
		}
		newFreeCount = oldFreeCount - delta
	}
	binary.LittleEndian.PutUint32(loc.cibBlock[ciBlockCountOff:ciBlockCountOff+4], newChunkBlocks)
	binary.LittleEndian.PutUint32(loc.cibBlock[ciFreeCountOff:ciFreeCountOff+4], newFreeCount)
	sealBlock(loc.cibBlock)
	if _, err := c.w.WriteAt(loc.cibBlock, int64(loc.cibPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: resize: write CIB: %w", err)
	}

	// 2) Update the spaceman: sm_dev[0].sm_block_count (offset 0x30)
	//    and sm_dev[0].sm_free_count (offset 0x48). Both are uint64.
	//    sm_dev[0].sm_chunk_count stays at 1 (single-chunk regime) so
	//    long as newBlocks ≤ blocksPerChunk — enforced by the gate
	//    above.
	//
	// Field layout (spaceman_device_t, starts at objPhysSize+16 = 48):
	//   +0x00  sm_block_count   uint64  ← we touch this
	//   +0x08  sm_chunk_count   uint64  (stays 1)
	//   +0x10  sm_cib_count     uint32  (stays 1)
	//   +0x14  sm_cab_count     uint32  (stays 0)
	//   +0x18  sm_free_count    uint64  ← we touch this  (offset 0x48)
	//   +0x20  sm_addr_offset   uint32
	const smDev0BlockCountOff = 0x30
	const smDev0FreeCountOff = 0x48
	binary.LittleEndian.PutUint64(loc.smBlock[smDev0BlockCountOff:smDev0BlockCountOff+8], newBlocks)
	oldSMFree := binary.LittleEndian.Uint64(loc.smBlock[smDev0FreeCountOff : smDev0FreeCountOff+8])
	var newSMFree uint64
	switch dir {
	case growDirection:
		newSMFree = oldSMFree + (newBlocks - cur)
	case shrinkDirection:
		delta := cur - newBlocks
		if oldSMFree < delta {
			return fmt.Errorf("apfs: Shrink: sm_dev[0].sm_free_count %d < shrink delta %d",
				oldSMFree, delta)
		}
		newSMFree = oldSMFree - delta
	}
	binary.LittleEndian.PutUint64(loc.smBlock[smDev0FreeCountOff:smDev0FreeCountOff+8], newSMFree)
	sealBlock(loc.smBlock)
	if _, err := c.w.WriteAt(loc.smBlock, int64(loc.smPaddr*bs)); err != nil {
		return fmt.Errorf("apfs: resize: write spaceman: %w", err)
	}

	// 3) Update the NX superblock at block 0 + the current desc-area
	//    NX SB copy. fsck_apfs cross-checks the UUID between the two
	//    copies and rejects any divergence in the rest of the field
	//    layout for the current checkpoint, so both must mirror the
	//    new nx_block_count.
	sb0, err := c.readBlock(0)
	if err != nil {
		return fmt.Errorf("apfs: resize: read NX SB: %w", err)
	}
	binary.LittleEndian.PutUint64(sb0[40:48], newBlocks)
	sealBlock(sb0)
	// Current desc-area NX SB copy lives at xpDescBase + xpDescIndex + 1
	// (the slot immediately after the current CheckpointMap).
	descNXSBCopy := c.sb.xpDescBase + uint64(c.sb.xpDescIndex) + 1
	if _, err := c.w.WriteAt(sb0, int64(descNXSBCopy*bs)); err != nil {
		return fmt.Errorf("apfs: resize: write NX SB copy: %w", err)
	}
	if _, err := c.w.WriteAt(sb0, 0); err != nil {
		return fmt.Errorf("apfs: resize: write NX SB: %w", err)
	}

	// 4) Reshape backing storage. For *os.File this is a Truncate
	//    call; for backends that don't expose Truncate we accept the
	//    in-band metadata change and leave physical sizing to the
	//    caller (typical for Container constructed from a fixed
	//    buffer).
	if err := truncateBackend(c.w, newSizeBytes); err != nil {
		return fmt.Errorf("apfs: resize: truncate backend: %w", err)
	}

	// 5) Refresh the in-memory NX SB so subsequent operations see the
	//    new geometry without a re-open.
	c.sb.blockCount = newBlocks
	return nil
}

// truncateBackend resizes the underlying backend storage when it
// implements truncator (*os.File and a few test backends do).
// Non-truncating backends silently succeed: the on-disk metadata
// already reflects the new size, and the caller is presumed to have
// pre-sized the buffer.
func truncateBackend(w containerWriter, newSizeBytes int64) error {
	if t, ok := w.(truncator); ok {
		return t.Truncate(newSizeBytes)
	}
	// Common shape for test backends: a *os.File wrapped in something
	// that satisfies WriteAt but not directly truncator. Fall through
	// — callers that pre-size their buffers don't need this branch,
	// and ones that do will satisfy truncator directly.
	if f, ok := w.(*os.File); ok {
		return f.Truncate(newSizeBytes)
	}
	return nil
}

// highestAllocatedBlock returns the highest block index within the
// chunk's bitmap whose allocation bit is set, or (0, false) when the
// bitmap is entirely clear. APFS convention is BIT SET = block
// allocated, so the scan is a backwards walk from the high end.
//
// chunkBlocks bounds the scan to the meaningful prefix of the bitmap
// (the bitmap is always a 4 KiB block but only the first chunkBlocks
// bits are populated).
func highestAllocatedBlock(bitmap []byte, chunkBlocks uint64) (uint64, bool) {
	if chunkBlocks == 0 {
		return 0, false
	}
	maxBit := chunkBlocks - 1
	for i := int64(maxBit); i >= 0; i-- {
		byteIdx := uint64(i) / 8
		if byteIdx >= uint64(len(bitmap)) {
			continue
		}
		bit := uint8(1) << (uint64(i) % 8)
		if bitmap[byteIdx]&bit != 0 {
			return uint64(i), true
		}
	}
	return 0, false
}

