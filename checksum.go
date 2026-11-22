package filesystem_apfs

// checksum.go enforces the Fletcher-64 object checksum (obj_phys_t.o_cksum)
// on every object read, and implements the checkpoint fall-back used when the
// container superblock fails it.
//
// Reference: "Apple File System Reference" (Apple Inc., 2020-06-22 and later
// revisions):
//   - "Objects" / obj_phys_t: o_cksum is "the Fletcher 64 checksum of the
//     object", computed over the object EXCLUDING the first 8 bytes (the
//     checksum field itself); "Fletcher 64 Checksum Algorithm" gives the
//     two-sum algorithm modulo 2^32-1 and the check-value construction.
//   - "Mounting an Apple File System Partition": the mount procedure reads
//     block zero, then locates the checkpoint descriptor area and "Find the
//     most recent valid checkpoint superblock" -- a superblock "is valid" only
//     if its checksum verifies. When the block-zero copy is not valid, the
//     descriptor area still holds the previous checkpoints, so the reader falls
//     back to the newest one that is.
//   - "Checkpoints" / nx_superblock_t: nx_xp_desc_blocks / nx_xp_desc_base
//     locate the checkpoint descriptor area (contiguous when the top bit of
//     nx_xp_desc_blocks is clear).
//
// Not objects, hence never checksummed: file data blocks, and the space
// manager's chunk bitmaps (raw bitmaps, see readBlockRaw users).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
)

// ErrChecksum is the sentinel every checksum failure matches with errors.Is.
var ErrChecksum = errors.New("apfs: object checksum mismatch")

// ChecksumError reports an object whose stored o_cksum does not equal the
// Fletcher-64 of its contents. Extract it with errors.As.
type ChecksumError struct {
	Block    uint64 // container block number the object was read from
	Stored   uint64 // o_cksum found on disk
	Computed uint64 // Fletcher-64 of block[8:]
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("apfs: object at block %d: o_cksum %#016x, computed %#016x (corrupt or tampered)", e.Block, e.Stored, e.Computed)
}

// Is makes errors.Is(err, ErrChecksum) true for every *ChecksumError.
func (e *ChecksumError) Is(target error) bool { return target == ErrChecksum }

// Options tunes how a container is opened.
type Options struct {
	// IgnoreChecksums disables o_cksum verification (a forensic opt-out for
	// damaged images). Off by default: with it on, a tampered image is served
	// as if it were genuine, and a later write seals checksums over whatever
	// it read.
	IgnoreChecksums bool
}

// verifyObjectBlock returns a *ChecksumError unless the Fletcher-64 of
// block[8:] equals the o_cksum in block[0:8].
func verifyObjectBlock(bn uint64, block []byte) error {
	if len(block) < objPhysSize {
		return fmt.Errorf("apfs: object at block %d: short block (%d bytes)", bn, len(block))
	}
	stored := binary.LittleEndian.Uint64(block[0:8])
	if got := fletcher64(block[8:]); got != stored {
		return &ChecksumError{Block: bn, Stored: stored, Computed: got}
	}
	return nil
}

// SetIgnoreChecksums toggles o_cksum verification on an open container.
func (c *Container) SetIgnoreChecksums(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ignoreChecksums = on
}

// maxDescScan bounds how many checkpoint-descriptor blocks the fall-back reads.
const maxDescScan = 4096

// openContainerFromOpts opens the container on r. Block zero must verify; if
// it (or the container object map) fails its checksum, older checkpoints in the
// descriptor area are tried, newest first.
func openContainerFromOpts(r containerReader, closer func() error, opts Options) (*Container, error) {
	const block0Size = 4096
	block := make([]byte, block0Size)
	if _, err := r.ReadAt(block, 0); err != nil {
		return nil, fmt.Errorf("apfs: read block 0: %w", err)
	}
	sb, err := readNXSuperblock(block)
	if err != nil {
		return nil, err
	}
	c := &Container{r: r, closer: closer, sb: sb, ignoreChecksums: opts.IgnoreChecksums}
	firstErr := c.loadCheckpoint(0)
	if firstErr == nil {
		return c, nil
	}
	var ce *ChecksumError
	if !errors.As(firstErr, &ce) {
		return nil, firstErr
	}
	for _, cand := range c.olderCheckpoints(sb) {
		c2 := &Container{r: r, closer: closer, sb: cand.sb, ignoreChecksums: opts.IgnoreChecksums}
		if c2.loadCheckpoint(cand.bn) == nil {
			return c2, nil
		}
	}
	return nil, firstErr
}

// loadCheckpoint verifies the superblock stored at block bn (0 for the
// block-zero copy) and resolves the container object map it names.
func (c *Container) loadCheckpoint(bn uint64) error {
	if !c.ignoreChecksums {
		raw, err := c.readBlockRaw(bn)
		if err != nil {
			return fmt.Errorf("apfs: read superblock block %d: %w", bn, err)
		}
		if err := verifyObjectBlock(bn, raw); err != nil {
			return err
		}
	}
	if c.sb.omapOID != 0 {
		omapBlock, err := c.readBlock(c.sb.omapOID)
		if err != nil {
			return fmt.Errorf("apfs: read container omap: %w", err)
		}
		om, err := readOmapPhys(omapBlock)
		if err != nil {
			return err
		}
		c.containerOmap = om
	}
	return nil
}

// checkpointCand is a checkpoint superblock found in the descriptor area.
type checkpointCand struct {
	sb *nxSuperblockNative
	bn uint64
}

// olderCheckpoints scans the checkpoint descriptor area for superblocks whose
// own checksum verifies, newest xid first. Non-contiguous descriptor areas and
// implausible sizes yield none.
func (c *Container) olderCheckpoints(bad *nxSuperblockNative) []checkpointCand {
	n := bad.xpDescBlocks
	if n == 0 || n&0x80000000 != 0 {
		return nil
	}
	if n > maxDescScan {
		n = maxDescScan
	}
	var out []checkpointCand
	for i := uint32(0); i < n; i++ {
		bn := bad.xpDescBase + uint64(i)
		raw, err := c.readBlockRaw(bn)
		if err != nil {
			continue
		}
		hdr, err := readObjPhys(raw[:objPhysSize])
		if err != nil || hdr.typ&0x00FF != objTypeNXSuperblock {
			continue
		}
		if verifyObjectBlock(bn, raw) != nil {
			continue
		}
		cand, err := readNXSuperblock(raw)
		if err != nil || cand.blockSize != bad.blockSize || cand.uuid != bad.uuid {
			continue
		}
		out = append(out, checkpointCand{sb: cand, bn: bn})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].sb.xid > out[j].sb.xid })
	return out
}

// OpenContainerOptions is OpenContainerAuto with Options.
func OpenContainerOptions(path string, opts Options) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("apfs: open %s: %w", path, err)
	}
	return openAutoFrom(f, f, nil, opts)
}

// OpenContainerRWOptions is OpenContainerRWAuto with Options.
func OpenContainerRWOptions(path string, opts Options) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apfs: rw open %s: %w", path, err)
	}
	return openAutoFrom(f, f, f, opts)
}

func openAutoFrom(f *os.File, rd containerReader, wr containerWriter, opts Options) (*Container, error) {
	off, err := findAPFSPartitionOffset(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	r, w := rd, wr
	if off != 0 {
		or := &offsetReader{inner: f, offset: off}
		r = or
		if wr != nil {
			w = &offsetWriter{offsetReader: or, innerW: f}
		}
	}
	c, err := openContainerFromOpts(r, f.Close, opts)
	if err != nil {
		f.Close()
		return nil, err
	}
	c.w = w
	return c, nil
}
