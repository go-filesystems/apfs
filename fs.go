package filesystem_apfs

// fs.go ties the lower-level decoders together and exposes the
// read-only entry points for APFS containers.
//
// Public API:
//
//   - OpenContainer(path)               → *Container
//   - OpenContainerFromBackend(b)       → *Container
//   - (c *Container).Volumes() → []VolumeInfo
//   - (c *Container).OpenVolume(idx) → *Volume
//   - (v *Volume).ListInodes() → []Inode
//   - (v *Volume).ReadFile(inodeID) → []byte
//
// What works:
//   - OMAP virtual→physical translation for the volume superblock and the
//     fs-tree root, with descent into matching internal-node children.
//   - Full FS-tree traversal: every leaf is visited regardless of B-tree
//     height, with internal-node child OIDs resolved through the volume
//     object map.
//   - FS-tree leaf decoding for record types: inode, drec (directory entry),
//     file extent, xattr, sibling link.
//   - File reading across multiple contiguous extents (extents sorted by
//     logical offset, sparse holes zero-filled, trailing zeros honoured).
//   - Per-inode listing of extended attributes (embedded payloads decoded;
//     stream xattrs surfaced with their stream id).
//   - Per-inode listing of sibling links (hard-link alternate paths).
//
// Known limits (intentional, to be lifted in subsequent iterations):
//   - Stream xattr payload reading (J_XATTR_DSTREAM follow).
//   - Snapshot trees, sealing, hashed FS-tree.
//   - Compressed file extents (apfs_compress_t / dataless extents).

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"

	"github.com/go-volumes/safeio"
)

// maxBTreeDepth bounds B-tree descent so a corrupt image whose internal
// nodes form an unbounded (or cyclic) chain cannot drive infinite recursion
// into a stack overflow. Real APFS trees are at most a handful of levels
// deep; 64 is comfortably above any legitimate height while still small
// enough to terminate quickly. (Finding H1.)
const maxBTreeDepth = 64

// btreeGuard bounds a single B-tree descent: it caps recursion depth and
// records every visited child node (by physical block address) so a
// self-referential or cyclic image terminates with an error instead of
// recursing forever. One guard is created per top-level traversal. (H1.)
type btreeGuard struct {
	depth   int
	visited *safeio.VisitSet // shared across the whole descent (pointer, not copied)
}

// newBTreeGuard starts a fresh descent at depth 0 with an empty visited set.
func newBTreeGuard() *btreeGuard {
	return &btreeGuard{visited: &safeio.VisitSet{}}
}

// descend validates a step from parent into a child node located at physical
// block paddr, then returns a guard for the next level. It enforces three
// invariants: (1) the depth budget is not exhausted; (2) paddr has not been
// seen before in this traversal (cycle detection, shared set so cycles across
// sibling subtrees are caught too); (3) the child sits strictly below the
// parent in level (a corrupt image that points a node at itself, or at a
// same/higher level, is rejected).
func (g *btreeGuard) descend(parent, child *btreeNode, paddr uint64) (*btreeGuard, error) {
	if g.depth >= maxBTreeDepth {
		return nil, fmt.Errorf("apfs: btree descent exceeded max depth %d", maxBTreeDepth)
	}
	if err := g.visited.Check(paddr); err != nil {
		return nil, fmt.Errorf("apfs: btree descent: %w", err)
	}
	if child.level >= parent.level {
		return nil, fmt.Errorf("apfs: btree descent: child level %d not below parent level %d", child.level, parent.level)
	}
	return &btreeGuard{depth: g.depth + 1, visited: g.visited}, nil
}

// ErrUnsupported is returned for code paths the parser knows exist on
// disk but does not yet implement (compressed extents, hashed
// FS-tree, etc.).
var ErrUnsupported = errors.New("apfs: feature not implemented in this iteration")

// containerReader is the io interface the parser needs. It mirrors
// apfsBackend without the Stat/WriteAt/Close obligations so the parser can
// also be driven from a *bytes.Reader-style backing.
type containerReader interface {
	ReadAt(p []byte, off int64) (int, error)
}

// containerWriter is the optional write capability. Reader-only backends
// (e.g. *bytes.Reader, ReadOnly *os.File) do not satisfy it; full *os.File
// opened with O_RDWR or any *bytes.Buffer-style RW does. Container
// stores a non-nil writer when the backend supports it, and write APIs
// (WriteFileInPlace, FormatContainer on an existing container, ...) refuse
// to operate when it is nil.
type containerWriter interface {
	WriteAt(p []byte, off int64) (int, error)
}

// ErrReadOnly is returned by write paths when the container was opened
// without write capability (e.g. via OpenContainer which opens the file
// O_RDONLY, or via OpenContainerFromBackend with a read-only backend).
var ErrReadOnly = errors.New("apfs: container is read-only")

// Container is an opened APFS container. It does not hold any keys —
// callers must unlock the underlying device with go-fde/apfs (or supply a
// non-encrypted reader) before passing it here.
type Container struct {
	// mu serialises all access to the container's mutable on-disk
	// state AND its volume views. The lock is held for the duration
	// of any public Container or Volume method.
	//
	// Rules to avoid deadlocks (Go's RWMutex is non-reentrant):
	//   - Public methods acquire the lock at entry; internal helpers
	//     (lowercase identifiers, including the `*Internal` /
	//     `*Locked` variants used by cross-method calls like
	//     `Rename → DeleteFile`) DO NOT acquire it.
	//   - The streaming readers (`FileReaderAt`, `XAttrStreamReaderAt`)
	//     are *snapshots* taken under the lock at construction time;
	//     their subsequent `ReadAt` calls do NOT re-lock. Concurrent
	//     mutation after construction may make the reader serve
	//     stale (but still valid) bytes — this is the documented
	//     contract.
	mu            sync.RWMutex
	r             containerReader
	w             containerWriter // non-nil when the backend supports writes
	closer        func() error
	sb            *nxSuperblockNative
	containerOmap *omapPhys // resolved container object map
	// allocOIDCursor is a fresh-virtual-oid allocator (seeded lazily from
	// nx_next_oid; used by leaf-split paths when allocating new FS-tree
	// nodes). Commit writes the latest value back into block 0.
	allocOIDCursor uint64
	// verifyHashes, when true, makes every B-tree descent through a hashed
	// internal node validate the child block's SHA-256 against the hash
	// stored alongside the child OID in the parent. Disabled by default;
	// flip with SetVerifyHashes.
	verifyHashes bool
}

// readFSChildBlock resolves a virtual child OID stored in entry idx of
// parentReader through the volume OMAP, reads the resulting physical
// block, and (when c.verifyHashes is enabled and the parent carries a
// trailing 32-byte hash) validates the block's SHA-256 against the hash.
//
// All FS-style descent paths (FS-tree, snapshot meta tree, anything that
// resolves children through the volume omap) funnel through this helper
// so hash verification is applied uniformly without per-site copy-paste.
func (v *Volume) readFSChildBlock(parentReader *nodeReader, idx int) ([]byte, uint64, error) {
	childOID, err := parentReader.childOIDAt(idx)
	if err != nil {
		return nil, 0, err
	}
	paddr, err := v.c.omapLookup(v.volOmap, childOID, v.xidLimit)
	if err != nil {
		return nil, 0, fmt.Errorf("apfs: resolve child %d: %w", childOID, err)
	}
	block, err := v.c.readBlock(paddr)
	if err != nil {
		return nil, 0, err
	}
	if v.c.verifyHashes {
		if hash, ok := parentReader.childHashAt(idx); ok {
			if err := verifyBlockHash(block, hash); err != nil {
				return nil, 0, fmt.Errorf("apfs: child oid %d: %w", childOID, err)
			}
		}
	}
	return block, paddr, nil
}

// SetVerifyHashes toggles SHA-256 verification of hashed B-tree children.
// When enabled, every traversal that descends a hashed internal node
// validates the child block's hash against the 32-byte digest stored after
// the child OID in the parent's value. Mismatches surface as errors from
// FindInode, LookupInodeRecord, ListInodes, ListSnapshots, etc.
//
// Apple uses hashed B-trees for sealed (signed) volumes such as the macOS
// system volume; non-hashed trees are silently exempt.
func (c *Container) SetVerifyHashes(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifyHashes = on
}

// verifyBlockHash returns nil iff sha256(block) equals expected. Used by
// the hashed-tree descent path when c.verifyHashes is true.
func verifyBlockHash(block, expected []byte) error {
	if len(expected) != sha256.Size {
		return fmt.Errorf("apfs: hash length %d (want %d)", len(expected), sha256.Size)
	}
	got := sha256.Sum256(block)
	if !bytes.Equal(got[:], expected) {
		return fmt.Errorf("apfs: hash mismatch (got %x… want %x…)", got[:8], expected[:8])
	}
	return nil
}

// VolumeInfo describes a volume found inside a container.
type VolumeInfo struct {
	Index uint32
	OID   uint64 // virtual oid of the APSB
	Name  string // populated lazily by OpenVolume
}

// Volume is an opened volume inside a container.
type Volume struct {
	c        *Container
	apsbOID  uint64 // virtual oid of the APSB (so writers can re-resolve the paddr)
	apsb     *apsbSuperblock
	volOmap  *omapPhys
	rootNode *btreeNode // FS-tree root, already resolved through the volume omap
	rootInfo *btreeInfo
	// suppressSnapshotGuard, when true, lets writers proceed even if
	// the volume has snapshots. Default false — writers return
	// ErrHasSnapshot to avoid corrupting the snapshot's frozen view.
	suppressSnapshotGuard bool
	// xidLimit is the upper bound (inclusive) used when resolving virtual
	// oids through the volume's object map. Live volumes use ^uint64(0)
	// (latest); snapshot views use the snapshot's frozen XID so reads see
	// the volume as it was at that point in time.
	xidLimit uint64
	// Bump-allocator state for iteration C of the read/write roadmap.
	// allocCursor is the next physical block address to hand out;
	// allocOIDCursor is the next inode object id. Both are populated
	// lazily by nextFreeBlock / nextInodeOID via a one-time scan of the
	// FS-tree, then incremented on each allocation. The boolean guards
	// avoid rescanning on subsequent allocations within the same session.
	allocCursor      uint64
	allocOIDCursor   uint64
	scannedHighWater bool
	scannedNextOID   bool
}

// Inode is the minimal projection of a J_INODE_VAL record exposed by
// this iteration of the parser.
type Inode struct {
	ID          uint64 // file system object identifier
	ParentID    uint64
	Name        string // populated when discovered through a parent's directory record
	Mode        uint16 // file mode (POSIX bits)
	Size        uint64 // logical file size (J_DSTREAM.size)
	IsDir       bool
	dataExtents []containerExtent // populated for non-empty regular files
}

// containerExtent is one J_FILE_EXTENT record: a contiguous run of physical
// blocks mapped to a logical offset of the file.
type containerExtent struct {
	logicalOffset uint64
	length        uint64
	physBlock     uint64
}

// OpenContainer opens a real APFS container at path read-only.
func OpenContainer(path string) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("apfs: open %s: %w", path, err)
	}
	c, err := openContainerFrom(f, f.Close)
	if err != nil {
		f.Close()
		return nil, err
	}
	// O_RDONLY means writes will fail; do not advertise write capability.
	c.w = nil
	return c, nil
}

// OpenContainerRW opens an APFS container at path read-write so callers can
// invoke the mutating APIs (WriteFileInPlace, ...). Read paths behave
// identically to OpenContainer.
func OpenContainerRW(path string) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apfs: rw open %s: %w", path, err)
	}
	c, err := openContainerFrom(f, f.Close)
	if err != nil {
		f.Close()
		return nil, err
	}
	c.w = f
	return c, nil
}

// OpenContainerFromBackend opens an APFS container from any ReadAt-capable
// backend. If the backend additionally satisfies containerWriter (WriteAt),
// write APIs are enabled. The caller retains ownership of the backend
// (Close on the returned container will not close it).
func OpenContainerFromBackend(r containerReader) (*Container, error) {
	c, err := openContainerFrom(r, func() error { return nil })
	if err != nil {
		return nil, err
	}
	if w, ok := r.(containerWriter); ok {
		c.w = w
	}
	return c, nil
}

func openContainerFrom(r containerReader, closer func() error) (*Container, error) {
	const block0Size = 4096
	block := make([]byte, block0Size)
	if _, err := r.ReadAt(block, 0); err != nil {
		return nil, fmt.Errorf("apfs: read block 0: %w", err)
	}
	sb, err := readNXSuperblock(block)
	if err != nil {
		return nil, err
	}
	c := &Container{r: r, closer: closer, sb: sb}
	// Resolve the container object map. The omap_oid in the NX superblock
	// is a "physical oid" by Apple's typing rules: it IS the block address.
	if sb.omapOID != 0 {
		omapBlock, err := c.readBlock(sb.omapOID)
		if err != nil {
			return nil, fmt.Errorf("apfs: read container omap: %w", err)
		}
		om, err := readOmapPhys(omapBlock)
		if err != nil {
			return nil, err
		}
		c.containerOmap = om
	}
	return c, nil
}

// Close releases the underlying file descriptor when one was opened by
// OpenContainer; OpenContainerFromBackend is a no-op.
func (c *Container) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

// Volumes lists the volumes declared in the NX superblock fs_oid array.
// Names are NOT decoded here (that requires opening the volume).
func (c *Container) Volumes() []VolumeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]VolumeInfo, 0, len(c.sb.fsOIDs))
	for i, oid := range c.sb.fsOIDs {
		out = append(out, VolumeInfo{Index: uint32(i), OID: oid})
	}
	return out
}

// readBlock reads exactly one container block at logical (physical) block
// number bn.
func (c *Container) readBlock(bn uint64) ([]byte, error) {
	bs := int(c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	buf := make([]byte, bs)
	if _, err := c.r.ReadAt(buf, int64(bn)*int64(bs)); err != nil {
		return nil, err
	}
	return buf, nil
}

// containerByteSize returns blockCount*blockSize as an int64 ceiling used to
// cap untrusted allocations (file sizes, extent lengths, sparse-hole gaps).
// It saturates to math.MaxInt64 on overflow so it stays a safe upper bound
// rather than wrapping to a small number. A zero/garbage blockCount yields a
// small positive ceiling (one block) so callers still get a usable bound.
func (c *Container) containerByteSize() int64 {
	bs := int64(c.sb.blockSize)
	if bs <= 0 {
		bs = 4096
	}
	bc := int64(c.sb.blockCount)
	if bc <= 0 {
		return bs
	}
	// Saturating multiply: if bc*bs overflows int64, clamp to MaxInt64.
	if bc > math.MaxInt64/bs {
		return math.MaxInt64
	}
	return bc * bs
}

// omapLookupRoot returns the physical block of an entry in the container or
// volume omap, given a virtual oid. xidWanted is the maximum acceptable
// transaction ID — pass ^uint64(0) to mean "the latest".
//
// This implementation handles single-level (root-is-leaf) trees only. For
// multi-level trees the leftmost path is descended, which is correct only
// when the desired oid sorts at or below the leftmost branch — see
// ErrUnsupported.
func (c *Container) omapLookup(omap *omapPhys, oid, xidWanted uint64) (paddr uint64, err error) {
	if omap == nil || omap.treeOID == 0 {
		return 0, fmt.Errorf("apfs: omap not loaded")
	}
	rootBlock, err := c.readBlock(omap.treeOID)
	if err != nil {
		return 0, fmt.Errorf("apfs: omap root: %w", err)
	}
	root, err := readBTreeNode(rootBlock)
	if err != nil {
		return 0, err
	}
	info, err := readRootBTreeInfo(rootBlock)
	if err != nil {
		return 0, err
	}
	g := newBTreeGuard()
	g.visited.Add(omap.treeOID) // the root node we are already standing on
	return c.omapLookupInNode(root, info, oid, xidWanted, g)
}

// omapLookupInNode performs a key search within a B-tree node. For the
// container omap each entry is exactly omap_key{oid,xid} = 16 bytes and
// each leaf value is omap_val{flags,size,paddr} = 16 bytes.
//
// Implementation: classic B-tree binary search. APFS sorts OMAP entries by
// (oid asc, xid asc); internal-node keys are the smallest key in their
// subtree. We find the rightmost entry whose key ≤ (oid, xidWanted) and
// either descend into the corresponding child (internal node) or return its
// value (leaf), provided the entry's oid matches the request.
func (c *Container) omapLookupInNode(n *btreeNode, info *btreeInfo, oid, xidWanted uint64, g *btreeGuard) (uint64, error) {
	r, err := newNodeReader(n, info)
	if err != nil {
		return 0, err
	}
	// fixed-shape OMAPs (single-leaf or 2-level all-fixed) AND
	// hybrid OMAPs (variable-shape internal nodes + fixed-shape
	// leaves — what our writer's promoteVolumeOMAPToTwoLevel emits;
	// also matches Apple's apfs.kext convention) are both supported
	// here. The kvloc/kvoff distinction is handled per-node by
	// nodeReader.
	nKeys := r.EntryCount()
	if nKeys == 0 {
		return 0, fmt.Errorf("apfs: empty omap node")
	}
	// cmp(i) is sgn(entry[i].key − target).
	cmp := func(i int) int {
		k, kerr := r.keyAt(i)
		if kerr != nil || len(k) < 16 {
			return 1
		}
		eOID := binary.LittleEndian.Uint64(k[0:8])
		eXID := binary.LittleEndian.Uint64(k[8:16])
		if eOID != oid {
			if eOID < oid {
				return -1
			}
			return 1
		}
		if eXID < xidWanted {
			return -1
		}
		if eXID > xidWanted {
			return 1
		}
		return 0
	}
	// Find smallest index where cmp > 0; the candidate is idx-1.
	lo, hi := 0, nKeys
	for lo < hi {
		mid := (lo + hi) / 2
		if cmp(mid) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	idx := lo - 1
	if n.IsLeaf() {
		if idx < 0 {
			return 0, fmt.Errorf("apfs: oid %d not found in omap", oid)
		}
		k, err := r.keyAt(idx)
		if err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint64(k[0:8]) != oid {
			return 0, fmt.Errorf("apfs: oid %d not found in omap", oid)
		}
		v, err := r.valueAt(idx)
		if err != nil {
			return 0, err
		}
		if len(v) < 16 {
			return 0, fmt.Errorf("apfs: omap value too short")
		}
		// omap_val: uint32 flags, uint32 size, uint64 paddr.
		return binary.LittleEndian.Uint64(v[8:16]), nil
	}
	// Internal node: when target precedes all entries (idx<0) we descend
	// into the leftmost child anyway because an entry with oid≥target may
	// still live there.
	if idx < 0 {
		idx = 0
	}
	childOID, err := r.childOIDAt(idx)
	if err != nil {
		return 0, err
	}
	childBlock, err := c.readBlock(childOID)
	if err != nil {
		return 0, err
	}
	if c.verifyHashes {
		if hash, ok := r.childHashAt(idx); ok {
			if err := verifyBlockHash(childBlock, hash); err != nil {
				return 0, fmt.Errorf("apfs: omap descent: %w", err)
			}
		}
	}
	cn, err := readBTreeNode(childBlock)
	if err != nil {
		return 0, err
	}
	cg, err := g.descend(n, cn, childOID)
	if err != nil {
		return 0, err
	}
	return c.omapLookupInNode(cn, info, oid, xidWanted, cg)
}

// OpenVolume materialises the volume at the given index of Volumes(). It
// resolves the APSB through the container omap, then loads the volume's own
// omap and FS-tree root.
func (c *Container) OpenVolume(index int) (*Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= len(c.sb.fsOIDs) {
		return nil, fmt.Errorf("apfs: volume index %d out of range", index)
	}
	if c.containerOmap == nil {
		return nil, fmt.Errorf("apfs: container omap not loaded")
	}
	apsbOID := c.sb.fsOIDs[index]
	apsbBlock, err := c.omapLookup(c.containerOmap, apsbOID, ^uint64(0))
	if err != nil {
		return nil, fmt.Errorf("apfs: lookup APSB: %w", err)
	}
	rawAPSB, err := c.readBlock(apsbBlock)
	if err != nil {
		return nil, err
	}
	apsb, err := readAPSB(rawAPSB)
	if err != nil {
		return nil, err
	}
	// Volume-level omap (apfs_omap_oid is physical, like the container omap).
	if apsb.omapOID == 0 {
		return nil, fmt.Errorf("apfs: volume omap missing")
	}
	volOmapBlock, err := c.readBlock(apsb.omapOID)
	if err != nil {
		return nil, err
	}
	volOmap, err := readOmapPhys(volOmapBlock)
	if err != nil {
		return nil, err
	}
	// FS-tree root oid is virtual: resolve through volOmap.
	fsRootBlock, err := c.omapLookup(volOmap, apsb.rootTreeOID, ^uint64(0))
	if err != nil {
		return nil, fmt.Errorf("apfs: lookup FS-tree root: %w", err)
	}
	rawRoot, err := c.readBlock(fsRootBlock)
	if err != nil {
		return nil, err
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return nil, err
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return nil, err
	}
	return &Volume{
		c:        c,
		apsbOID:  apsbOID,
		apsb:     apsb,
		volOmap:  volOmap,
		rootNode: rootNode,
		rootInfo: rootInfo,
		xidLimit: ^uint64(0),
	}, nil
}

// OpenSnapshot returns a read-only Volume that exposes the volume as
// it was at the snapshot's transaction id. The frozen APSB is resolved
// through the container OMAP with xid = snap.XID, and every subsequent
// virtual-oid resolution inside that volume is similarly clamped via
// Volume.xidLimit so the snapshot's FS-tree, OMAP and snap_meta
// tree all read their frozen state.
func (c *Container) OpenSnapshot(snap Snapshot) (*Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.containerOmap == nil {
		return nil, fmt.Errorf("apfs: container omap not loaded")
	}
	if snap.APSBOID == 0 {
		return nil, fmt.Errorf("apfs: snapshot has zero APSB oid")
	}
	apsbBlock, err := c.omapLookup(c.containerOmap, snap.APSBOID, snap.XID)
	if err != nil {
		return nil, fmt.Errorf("apfs: lookup snapshot APSB at xid %d: %w", snap.XID, err)
	}
	rawAPSB, err := c.readBlock(apsbBlock)
	if err != nil {
		return nil, err
	}
	apsb, err := readAPSB(rawAPSB)
	if err != nil {
		return nil, err
	}
	if apsb.omapOID == 0 {
		return nil, fmt.Errorf("apfs: snapshot APSB has no volume omap")
	}
	volOmapBlock, err := c.readBlock(apsb.omapOID)
	if err != nil {
		return nil, err
	}
	volOmap, err := readOmapPhys(volOmapBlock)
	if err != nil {
		return nil, err
	}
	fsRootBlock, err := c.omapLookup(volOmap, apsb.rootTreeOID, snap.XID)
	if err != nil {
		return nil, fmt.Errorf("apfs: lookup snapshot FS-tree root: %w", err)
	}
	rawRoot, err := c.readBlock(fsRootBlock)
	if err != nil {
		return nil, err
	}
	rootNode, err := readBTreeNode(rawRoot)
	if err != nil {
		return nil, err
	}
	rootInfo, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return nil, err
	}
	return &Volume{
		c:        c,
		apsbOID:  snap.APSBOID,
		apsb:     apsb,
		volOmap:  volOmap,
		rootNode: rootNode,
		rootInfo: rootInfo,
		xidLimit: snap.XID,
	}, nil
}

// Name returns the volume name (apfs_volname_t, NUL-trimmed UTF-8).
func (v *Volume) Name() string {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	return v.apsb.volumeName
}

// FS-tree key record types (low 4 bits of the leading uint64).
const (
	jTypeAny       uint8 = 0
	jTypeSnapMeta  uint8 = 1
	jTypeExtent    uint8 = 2
	jTypeInode     uint8 = 3
	jTypeXattr     uint8 = 4
	jTypeSibLink   uint8 = 5
	jTypeDStreamID uint8 = 6
	jTypeCryptoSt  uint8 = 7
	jTypeFileExt   uint8 = 8
	jTypeDirRec    uint8 = 9
	jTypeDirStats  uint8 = 10
	jTypeSnapName  uint8 = 11
	jTypeSibMap    uint8 = 12
)

// jKeyHeader returns (oid, type) decoded from the standard 8-byte j_key_t
// prefix that every FS-tree key starts with. The high 4 bits of the uint64
// hold the type and the low 60 bits hold the oid.
func jKeyHeader(k []byte) (uint64, uint8, error) {
	if len(k) < 8 {
		return 0, 0, fmt.Errorf("apfs: j_key_t too short")
	}
	w := binary.LittleEndian.Uint64(k[0:8])
	return w & 0x0FFFFFFFFFFFFFFF, uint8(w >> 60), nil
}

// ListInodes walks the entire FS-tree and returns every J_INODE_VAL
// projected through Inode. Names and data extents discovered in the
// same traversal are folded into the matching inode. This is now a full
// traversal — every leaf contributes, regardless of B-tree height.
func (v *Volume) ListInodes() ([]Inode, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	byID := make(map[uint64]*Inode)
	visit := func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil {
			return nil
		}
		switch typ {
		case jTypeInode:
			ino, perr := decodeInode(oid, val)
			if perr != nil {
				return nil
			}
			if existing, ok := byID[oid]; ok {
				ino.dataExtents = existing.dataExtents
				ino.Name = existing.Name
				if existing.ParentID != 0 {
					ino.ParentID = existing.ParentID
				}
			}
			byID[oid] = ino
		case jTypeDirRec:
			if len(k) < 12 || len(val) < 18 {
				return nil
			}
			name := decodeDirRecName(k, val)
			childOID := binary.LittleEndian.Uint64(val[0:8])
			ino, ok := byID[childOID]
			if !ok {
				ino = &Inode{ID: childOID}
				byID[childOID] = ino
			}
			ino.Name = name
			ino.ParentID = oid
		case jTypeFileExt:
			if ext, ok := decodeFileExtent(k, val); ok {
				ino, exists := byID[oid]
				if !exists {
					ino = &Inode{ID: oid}
					byID[oid] = ino
				}
				ino.dataExtents = append(ino.dataExtents, ext)
			}
		}
		return nil
	}
	if err := v.traverseFSTree(visit); err != nil {
		return nil, err
	}
	out := make([]Inode, 0, len(byID))
	for _, ino := range byID {
		out = append(out, *ino)
	}
	return out, nil
}

// Snapshot is one entry from the volume's snapshot metadata tree.
// It corresponds to a J_SNAP_META record (apfs_snap_meta_val): the frozen
// transaction id (XID), human-readable name, and the OID of the volume
// superblock captured by the snapshot.
type Snapshot struct {
	XID        uint64
	APSBOID    uint64 // sblock_oid: the frozen APSB to open for read access
	Name       string
	CreateTime uint64
	ChangeTime uint64
	Inum       uint64
	Flags      uint32
}

// ListSnapshots opens the volume's snapshot metadata tree and returns every
// J_SNAP_META record it contains. Returns an empty slice when the volume
// has no snapshots (apfs_snap_meta_tree_oid = 0).
func (v *Volume) ListSnapshots() ([]Snapshot, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	return v.listSnapshotsLocked()
}

// listSnapshotsLocked is the lock-free body of ListSnapshots. Callers
// MUST already hold v.c.mu (at least RLock).
func (v *Volume) listSnapshotsLocked() ([]Snapshot, error) {
	root, info, err := v.openSnapMetaTree()
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	var out []Snapshot
	visit := func(k, val []byte) error {
		_, typ, err := jKeyHeader(k)
		if err != nil || typ != jTypeSnapMeta {
			return nil
		}
		snap, ok := decodeSnapMeta(k, val)
		if ok {
			out = append(out, snap)
		}
		return nil
	}
	if err := v.traverseBTreeWithOmap(root, info, visit); err != nil {
		return nil, err
	}
	return out, nil
}

// LookupSnapshotByName resolves a snapshot by its human-readable name.
//
// Fast path (Apple-spec-compliant images): the snapshot metadata tree is
// expected to carry a J_SNAP_NAME record alongside every J_SNAP_META.
// J_SNAP_NAME records sort alphabetically by name within their (oid=0,
// type=jTypeSnapName) range, so a single seekAndIterate finds the entry
// in O(log n) and yields the matching XID; a second seekAndIterate then
// resolves the J_SNAP_META at that XID to populate the full
// Snapshot.
//
// Fallback path (synthetic test images that only carry J_SNAP_META): if
// the fast path returns no match, ListSnapshots is scanned linearly. This
// keeps the helper compatible with images built incrementally without
// the J_SNAP_NAME side records.
//
// Returns os.ErrNotExist when neither path turns up a match.
func (v *Volume) LookupSnapshotByName(name string) (Snapshot, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	if snap, ok, err := v.lookupSnapshotByNameFast(name); err != nil {
		return Snapshot{}, err
	} else if ok {
		return snap, nil
	}
	snaps, err := v.listSnapshotsLocked()
	if err != nil {
		return Snapshot{}, err
	}
	for _, s := range snaps {
		if s.Name == name {
			return s, nil
		}
	}
	return Snapshot{}, os.ErrNotExist
}

// lookupSnapshotByNameFast is the J_SNAP_NAME binary-search path. Returns
// (snap, true, nil) on match, (zero, false, nil) when no J_SNAP_NAME
// record matches, and (zero, false, err) on I/O / structural errors.
func (v *Volume) lookupSnapshotByNameFast(name string) (Snapshot, bool, error) {
	root, info, err := v.openSnapMetaTree()
	if err != nil {
		return Snapshot{}, false, err
	}
	if root == nil {
		return Snapshot{}, false, nil
	}
	target := buildSnapNameKey(name)
	var foundXID uint64
	var found bool
	visit := func(k, val []byte) (bool, error) {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return true, nil
		}
		if oid != 0 || typ != jTypeSnapName {
			return true, nil
		}
		candName, ok := decodeSnapNameKeyName(k)
		if !ok || candName != name {
			return true, nil
		}
		if len(val) >= 8 {
			foundXID = binary.LittleEndian.Uint64(val[0:8])
			found = true
		}
		return true, nil
	}
	if err := v.seekAndIterateTree(root, info, target, visit); err != nil {
		return Snapshot{}, false, err
	}
	if !found {
		return Snapshot{}, false, nil
	}
	snap, ok, err := v.lookupSnapMetaByXID(root, info, foundXID)
	if err != nil {
		return Snapshot{}, false, err
	}
	return snap, ok, nil
}

// lookupSnapMetaByXID does an O(log n) seek for the J_SNAP_META record
// keyed by xid. Used to materialise a Snapshot once the XID is
// known (whether from a J_SNAP_NAME hit or any other source).
func (v *Volume) lookupSnapMetaByXID(root *btreeNode, info *btreeInfo, xid uint64) (Snapshot, bool, error) {
	target := make([]byte, 8)
	binary.LittleEndian.PutUint64(target, xid|(uint64(jTypeSnapMeta)<<60))
	var snap Snapshot
	var found bool
	visit := func(k, val []byte) (bool, error) {
		oid, typ, jerr := jKeyHeader(k)
		if jerr != nil || oid != xid || typ != jTypeSnapMeta {
			return true, nil
		}
		if s, ok := decodeSnapMeta(k, val); ok {
			snap = s
			found = true
		}
		return true, nil
	}
	if err := v.seekAndIterateTree(root, info, target, visit); err != nil {
		return Snapshot{}, false, err
	}
	return snap, found, nil
}

// buildSnapNameKey builds the on-disk J_SNAP_NAME key for a name.
//
// Layout:
//
//	uint64 j_key_t   (oid = 0, type = jTypeSnapName)
//	uint16 name_len
//	[name bytes including a trailing NUL]
//
// Apple's APFS reference uses a sentinel oid for snap_name records; this
// package picks oid=0 to keep the encoding self-consistent — every
// snap_name record in a tree must use the same oid value, and oid=0
// places them after every J_SNAP_META record in sort order (since type=11
// dominates type=1 in the high nibble).
func buildSnapNameKey(name string) []byte {
	tail := append([]byte(name), 0)
	k := make([]byte, 10+len(tail))
	binary.LittleEndian.PutUint64(k[0:8], uint64(jTypeSnapName)<<60)
	binary.LittleEndian.PutUint16(k[8:10], uint16(len(tail)))
	copy(k[10:], tail)
	return k
}

// decodeSnapNameKeyName extracts the name from a J_SNAP_NAME key.
func decodeSnapNameKeyName(k []byte) (string, bool) {
	if len(k) < 10 {
		return "", false
	}
	nameLen := int(binary.LittleEndian.Uint16(k[8:10]))
	if 10+nameLen > len(k) {
		return "", false
	}
	raw := k[10 : 10+nameLen]
	if i := indexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return string(raw), true
}

// traverseBTreeWithOmap walks every leaf of an arbitrary FS-style B-tree
// (variable kv) under the volume's object map. Used for both the FS-tree
// proper and the snapshot metadata tree, which share the layout.
func (v *Volume) traverseBTreeWithOmap(n *btreeNode, info *btreeInfo, visit func(key, val []byte) error) error {
	return v.traverseBTreeWithOmapGuarded(n, info, visit, newBTreeGuard())
}

func (v *Volume) traverseBTreeWithOmapGuarded(n *btreeNode, info *btreeInfo, visit func(key, val []byte) error, g *btreeGuard) error {
	r, err := newNodeReader(n, info)
	if err != nil {
		return err
	}
	if n.IsLeaf() {
		for i := 0; i < r.EntryCount(); i++ {
			k, err := r.keyAt(i)
			if err != nil {
				return err
			}
			val, err := r.valueAt(i)
			if err != nil {
				return err
			}
			if err := visit(k, val); err != nil {
				return err
			}
		}
		return nil
	}
	// PHYSICAL trees (snap-meta, extent-ref) carry child paddrs as
	// 8-byte values directly; resolve via readBlock instead of going
	// through the volume OMAP. Otherwise (FS-tree etc.) values are
	// child OIDs that need OMAP lookup.
	isPhysical := info != nil && info.flags&btreeFlagPhysical != 0
	for i := 0; i < r.EntryCount(); i++ {
		var block []byte
		var paddr uint64
		if isPhysical {
			val, verr := r.valueAt(i)
			if verr != nil {
				return verr
			}
			if len(val) < 8 {
				return fmt.Errorf("apfs: physical internal val too short (%d) at idx %d", len(val), i)
			}
			paddr = binary.LittleEndian.Uint64(val[:8])
			block, err = v.c.readBlock(paddr)
		} else {
			block, paddr, err = v.readFSChildBlock(r, i)
		}
		if err != nil {
			return err
		}
		child, err := readBTreeNode(block)
		if err != nil {
			return err
		}
		cg, err := g.descend(n, child, paddr)
		if err != nil {
			return err
		}
		if err := v.traverseBTreeWithOmapGuarded(child, info, visit, cg); err != nil {
			return err
		}
	}
	return nil
}

// decodeSnapMeta decodes a J_SNAP_META (key, value) pair. Per Apple's
// apfs_snap_meta_val layout (50 bytes + name):
//
//	uint64  extentref_tree_oid
//	uint64  sblock_oid           // frozen APSB block oid (paddr-resolvable)
//	uint64  create_time
//	uint64  change_time
//	uint64  inum
//	uint32  extentref_tree_type
//	uint32  flags
//	uint16  name_len
//	[name_len bytes name, NUL-terminated]
//
// The XID is taken from the key's j_key_t prefix (low 60 bits of the
// uint64 = oid field, which holds the snapshot's transaction id).
func decodeSnapMeta(k, val []byte) (Snapshot, bool) {
	if len(k) < 8 || len(val) < 50 {
		return Snapshot{}, false
	}
	xid, _, _ := jKeyHeader(k)
	snap := Snapshot{
		XID:        xid,
		APSBOID:    binary.LittleEndian.Uint64(val[8:16]),
		CreateTime: binary.LittleEndian.Uint64(val[16:24]),
		ChangeTime: binary.LittleEndian.Uint64(val[24:32]),
		Inum:       binary.LittleEndian.Uint64(val[32:40]),
		Flags:      binary.LittleEndian.Uint32(val[44:48]),
	}
	nameLen := int(binary.LittleEndian.Uint16(val[48:50]))
	if 50+nameLen <= len(val) {
		raw := val[50 : 50+nameLen]
		if i := indexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		snap.Name = string(raw)
	}
	return snap, true
}

// XAttr is one extended-attribute record decoded from the FS-tree.
// EmbeddedValue is non-nil when the attribute payload is stored inline in
// the J_XATTR_VAL record (xattrFlagDataEmbedded). Stream xattrs (whose
// data lives in a separate J_DSTREAM_ID chain) leave EmbeddedValue nil and
// expose StreamID + StreamSize so the caller can fetch them later.
type XAttr struct {
	OwnerID       uint64
	Name          string
	Flags         uint16
	EmbeddedValue []byte
	StreamID      uint64 // valid when Flags & xattrFlagDataStream != 0
	StreamSize    uint64
}

// Sibling is one J_SIBLING_LINK record: an alternate (parent, name)
// path for the inode it belongs to (i.e., a hard link).
type Sibling struct {
	OwnerID   uint64 // the inode this sibling refers to
	SiblingID uint64
	ParentID  uint64
	Name      string
}

// xattr flags as defined by Apple.
const (
	xattrFlagDataStream   uint16 = 0x0001
	xattrFlagDataEmbedded uint16 = 0x0002
	xattrFlagFSOwned      uint16 = 0x0004
	xattrFlagReserved8    uint16 = 0x0008
)

// ListXAttrs walks the FS-tree and returns every J_XATTR record attached to
// inode owner.ID. Stream xattrs are reported with empty EmbeddedValue and
// non-zero StreamID; fetch their payload via `ReadXAttrStream` or
// `XAttrStreamReaderAt`.
func (v *Volume) ListXAttrs(owner Inode) ([]XAttr, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	var out []XAttr
	visit := func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil || typ != jTypeXattr || oid != owner.ID {
			return nil
		}
		x, ok := decodeXAttr(oid, k, val)
		if ok {
			out = append(out, x)
		}
		return nil
	}
	if err := v.traverseFSTree(visit); err != nil {
		return nil, err
	}
	return out, nil
}

// ReadXAttrStream returns the payload of an extended attribute stored as a
// stream (xattrFlagDataStream). For embedded xattrs it returns the payload
// already in x.EmbeddedValue. It collects every J_FILE_EXTENT keyed by the
// stream's xattr_obj_id, sorts them by logical offset, and concatenates
// (zero-filling sparse holes, trimming to x.StreamSize).
func (v *Volume) ReadXAttrStream(x XAttr) ([]byte, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	if x.Flags&xattrFlagDataStream == 0 {
		// Embedded or unknown layout — return the inline bytes as-is.
		return append([]byte(nil), x.EmbeddedValue...), nil
	}
	if x.StreamID == 0 {
		return nil, fmt.Errorf("apfs: stream xattr %q has zero stream id", x.Name)
	}
	var extents []containerExtent
	visit := func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil || typ != jTypeFileExt || oid != x.StreamID {
			return nil
		}
		if ext, ok := decodeFileExtent(k, val); ok {
			extents = append(extents, ext)
		}
		return nil
	}
	if err := v.traverseFSTree(visit); err != nil {
		return nil, err
	}
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].logicalOffset < extents[j].logicalOffset
	})
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	// Cap every untrusted allocation against the container's byte size. (C3.)
	maxBytes := v.c.containerByteSize()
	out := make([]byte, 0)
	var expected uint64
	for _, ext := range extents {
		if ext.logicalOffset > expected {
			pad, err := safeio.MakeBytes(int64(ext.logicalOffset-expected), maxBytes)
			if err != nil {
				return nil, fmt.Errorf("apfs: stream xattr %q sparse hole: %w", x.Name, err)
			}
			out = append(out, pad...)
			expected = ext.logicalOffset
		}
		if ext.logicalOffset < expected {
			return nil, fmt.Errorf("apfs: stream xattr %q has overlapping extents", x.Name)
		}
		chunk, err := safeio.MakeBytes(int64(ext.length), maxBytes)
		if err != nil {
			return nil, fmt.Errorf("apfs: stream xattr %q extent length: %w", x.Name, err)
		}
		if _, err := v.c.r.ReadAt(chunk, int64(ext.physBlock*bs)); err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		expected += ext.length
	}
	if x.StreamSize > 0 && uint64(len(out)) > x.StreamSize {
		out = out[:x.StreamSize]
	}
	return out, nil
}

// ListSiblings walks the FS-tree and returns every J_SIBLING_LINK record
// that names inode owner.ID. Each sibling is a hard-link path (parent +
// name) pointing at owner.
func (v *Volume) ListSiblings(owner Inode) ([]Sibling, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	var out []Sibling
	visit := func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil || typ != jTypeSibLink || oid != owner.ID {
			return nil
		}
		s, ok := decodeSibling(oid, k, val)
		if ok {
			out = append(out, s)
		}
		return nil
	}
	if err := v.traverseFSTree(visit); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeXAttr parses a J_XATTR_VAL record. Key layout: j_key_t (8 bytes) +
// uint16 name_len + name (NUL-terminated). Value layout: uint16 flags +
// uint16 xdata_len + [xdata_len bytes].
func decodeXAttr(oid uint64, k, val []byte) (XAttr, bool) {
	if len(k) < 10 || len(val) < 4 {
		return XAttr{}, false
	}
	nameLen := int(binary.LittleEndian.Uint16(k[8:10]))
	if 10+nameLen > len(k) {
		return XAttr{}, false
	}
	rawName := k[10 : 10+nameLen]
	if i := indexByte(rawName, 0); i >= 0 {
		rawName = rawName[:i]
	}
	flags := binary.LittleEndian.Uint16(val[0:2])
	xLen := int(binary.LittleEndian.Uint16(val[2:4]))
	if 4+xLen > len(val) {
		return XAttr{}, false
	}
	x := XAttr{
		OwnerID: oid,
		Name:    string(rawName),
		Flags:   flags,
	}
	if flags&xattrFlagDataEmbedded != 0 {
		x.EmbeddedValue = append([]byte(nil), val[4:4+xLen]...)
		return x, true
	}
	if flags&xattrFlagDataStream != 0 && xLen >= 16 {
		// J_XATTR_DSTREAM (24 bytes): xattr_obj_id (8) + j_dstream (size,
		// alloced_size, default_crypto_id, total_bytes_written = 32 bytes).
		// We only surface the object id and total length up-front; the
		// stream payload itself is not yet streamed.
		x.StreamID = binary.LittleEndian.Uint64(val[4:12])
		if xLen >= 24 {
			x.StreamSize = binary.LittleEndian.Uint64(val[12:20])
		}
		return x, true
	}
	return x, true
}

// decodeSibling parses a J_SIBLING_LINK record. Key layout: j_key_t +
// uint64 sibling_id. Value layout: uint64 parent_id + uint16 name_len +
// name (NUL-terminated).
func decodeSibling(oid uint64, k, val []byte) (Sibling, bool) {
	if len(k) < 16 || len(val) < 10 {
		return Sibling{}, false
	}
	siblingID := binary.LittleEndian.Uint64(k[8:16])
	parentID := binary.LittleEndian.Uint64(val[0:8])
	nameLen := int(binary.LittleEndian.Uint16(val[8:10]))
	if 10+nameLen > len(val) {
		return Sibling{}, false
	}
	rawName := val[10 : 10+nameLen]
	if i := indexByte(rawName, 0); i >= 0 {
		rawName = rawName[:i]
	}
	return Sibling{
		OwnerID:   oid,
		SiblingID: siblingID,
		ParentID:  parentID,
		Name:      string(rawName),
	}, true
}

// compareFSKey returns sgn(candidate − target) under APFS FS-tree ordering.
// The leading 8 bytes of every FS-tree key are a j_key_t — Apple sorts
// these primarily by OBJECT ID (low 60 bits), then by RECORD TYPE
// (high 4 bits), then by the type-specific tail. Naïve uint64-LE
// comparison would sort by type first because the type bits live in
// the high nibble; fsck_apfs's "btn: invalid key order" error fires
// when leaves are emitted in uint64 order rather than (oid, type)
// order.
//
// For J_DIR_REC keys on case-insensitive volumes (the hashed shape,
// apfs_drec_hashed_key_t) the tail is a uint32 name_len_and_hash
// followed by the name bytes. fsck_apfs sorts these by the **numeric**
// value of name_len_and_hash (the 22-bit hash dominates the low-10-bit
// length), THEN by name bytes — NOT by byte-wise lexicographic order
// of the LE encoding. Sorting these byte-wise emits the records in the
// wrong order on volumes that hash to a different first-byte ordering
// (e.g. "root" hashes to 0xb6… while "private-dir" hashes to 0xac…,
// so byte-wise puts root first while fsck expects private-dir first).
func compareFSKey(candidate, target []byte) int {
	if len(candidate) < 8 || len(target) < 8 {
		return bytes.Compare(candidate, target)
	}
	cP := binary.LittleEndian.Uint64(candidate[0:8])
	tP := binary.LittleEndian.Uint64(target[0:8])
	const oidMask = uint64(0x0FFFFFFFFFFFFFFF)
	cOID := cP & oidMask
	tOID := tP & oidMask
	if cOID < tOID {
		return -1
	}
	if cOID > tOID {
		return 1
	}
	cType := cP >> 60
	tType := tP >> 60
	if cType < tType {
		return -1
	}
	if cType > tType {
		return 1
	}
	if cType == uint64(jTypeDirRec) && len(candidate) >= 12 && len(target) >= 12 {
		cHash := binary.LittleEndian.Uint32(candidate[8:12])
		tHash := binary.LittleEndian.Uint32(target[8:12])
		if cHash < tHash {
			return -1
		}
		if cHash > tHash {
			return 1
		}
		return bytes.Compare(candidate[12:], target[12:])
	}
	if cType == uint64(jTypeXattr) && len(candidate) >= 10 && len(target) >= 10 {
		// J_XATTR keys: 2-byte name_len then name bytes. fsck_apfs's
		// sort order is by name string, not by (name_len, name) — so
		// "com.apple.FinderInfo" (name_len=21) sorts before "user.tag"
		// (name_len=9) even though byte-wise the LE name_len bytes
		// would put user.tag first. Skip the name_len field.
		cName := candidate[10:]
		tName := target[10:]
		// Strip trailing NUL for the compare; equal names with the
		// same NUL termination compare identically anyway.
		if len(cName) > 0 && cName[len(cName)-1] == 0 {
			cName = cName[:len(cName)-1]
		}
		if len(tName) > 0 && tName[len(tName)-1] == 0 {
			tName = tName[:len(tName)-1]
		}
		return bytes.Compare(cName, tName)
	}
	return bytes.Compare(candidate[8:], target[8:])
}

// lookupFSTreeFirst descends the FS-tree by binary search until it lands on
// the leaf entry whose key compares equal to targetKey. It returns the leaf
// (key, value) bytes, or os.ErrNotExist when no entry matches.
func (v *Volume) lookupFSTreeFirst(targetKey []byte) ([]byte, []byte, error) {
	return v.lookupFSTreeNode(v.rootNode, v.rootInfo, targetKey, newBTreeGuard())
}

func (v *Volume) lookupFSTreeNode(n *btreeNode, info *btreeInfo, targetKey []byte, g *btreeGuard) ([]byte, []byte, error) {
	r, err := newNodeReader(n, info)
	if err != nil {
		return nil, nil, err
	}
	nKeys := r.EntryCount()
	if nKeys == 0 {
		return nil, nil, os.ErrNotExist
	}
	cmp := func(i int) int {
		k, kerr := r.keyAt(i)
		if kerr != nil {
			return 1
		}
		return compareFSKey(k, targetKey)
	}
	// Find the rightmost entry with key ≤ target.
	lo, hi := 0, nKeys
	for lo < hi {
		mid := (lo + hi) / 2
		if cmp(mid) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	idx := lo - 1
	if n.IsLeaf() {
		if idx < 0 {
			return nil, nil, os.ErrNotExist
		}
		k, err := r.keyAt(idx)
		if err != nil {
			return nil, nil, err
		}
		if compareFSKey(k, targetKey) != 0 {
			return nil, nil, os.ErrNotExist
		}
		val, err := r.valueAt(idx)
		if err != nil {
			return nil, nil, err
		}
		return k, val, nil
	}
	if idx < 0 {
		idx = 0
	}
	block, paddr, err := v.readFSChildBlock(r, idx)
	if err != nil {
		return nil, nil, err
	}
	child, err := readBTreeNode(block)
	if err != nil {
		return nil, nil, err
	}
	cg, err := g.descend(n, child, paddr)
	if err != nil {
		return nil, nil, err
	}
	return v.lookupFSTreeNode(child, info, targetKey, cg)
}

// errIterStop is the sentinel error used by seekAndIterate to terminate
// recursion when the visit callback returns stop=true. It is never
// surfaced to callers; seekAndIterate converts it back to a nil error.
var errIterStop = errors.New("apfs: iteration stop")

// seekAndIterate descends the volume FS-tree to the first entry whose key
// compares ≥ target, then iterates forward through every (key, value) pair
// in ascending order calling visit. Iteration ends when visit returns
// stop=true (or an error), or when the tree is exhausted. The traversal
// honours v.xidLimit for OMAP child resolution, so snapshot views see the
// frozen tree.
//
// This is the foundation for range queries: callers seek to a prefix
// (e.g., "the first record with j_key.oid == 42") and stop themselves
// when the prefix changes, getting O(log n + matching records) cost.
func (v *Volume) seekAndIterate(target []byte, visit func(k, val []byte) (stop bool, err error)) error {
	return v.seekAndIterateTree(v.rootNode, v.rootInfo, target, visit)
}

// seekAndIterateTree is the generic version of seekAndIterate that operates
// on any FS-style B-tree root resolvable through the volume OMAP. Used
// internally to query the snapshot metadata tree (which shares the FS-tree
// shape) without duplicating the descent / iteration logic.
func (v *Volume) seekAndIterateTree(root *btreeNode, info *btreeInfo, target []byte, visit func(k, val []byte) (stop bool, err error)) error {
	err := v.seekIterNode(root, info, target, visit, newBTreeGuard())
	if errors.Is(err, errIterStop) {
		return nil
	}
	return err
}

// openSnapMetaTree returns the volume's snapshot metadata tree root and
// its btreeInfo trailer, or (nil, nil, nil) if the volume has no snapshot
// tree (apfs_snap_meta_tree_oid = 0). Used by ListSnapshots and
// LookupSnapshotByName.
//
// apfs_snap_meta_tree_type's storage-class bits decide how to read the
// oid: PHYSICAL (mkapfs / Apple's newfs_apfs default) means the oid IS
// the block address, VIRTUAL means resolve through the volume OMAP.
// Older synthetic test images use VIRTUAL.
func (v *Volume) openSnapMetaTree() (*btreeNode, *btreeInfo, error) {
	if v.apsb.snapMetaOID == 0 {
		return nil, nil, nil
	}
	var rootBlock uint64
	if v.apsb.snapMetaIsPhysical() {
		rootBlock = v.apsb.snapMetaOID
	} else {
		var err error
		rootBlock, err = v.c.omapLookup(v.volOmap, v.apsb.snapMetaOID, v.xidLimit)
		if err != nil {
			return nil, nil, fmt.Errorf("apfs: resolve snap_meta tree: %w", err)
		}
	}
	rawRoot, err := v.c.readBlock(rootBlock)
	if err != nil {
		return nil, nil, err
	}
	root, err := readBTreeNode(rawRoot)
	if err != nil {
		return nil, nil, err
	}
	info, err := readRootBTreeInfo(rawRoot)
	if err != nil {
		return nil, nil, err
	}
	return root, info, nil
}

// seekIterNode is the recursive worker behind seekAndIterate. For leaves it
// finds the first entry ≥ target by binary search and yields entries
// forward; for internal nodes it locates the rightmost child whose key
// ≤ target, descends with the original target, then continues into every
// subsequent sibling using a "smallest possible" sentinel so the forward
// iteration is preserved across subtrees.
func (v *Volume) seekIterNode(n *btreeNode, info *btreeInfo, target []byte, visit func(k, val []byte) (bool, error), g *btreeGuard) error {
	r, err := newNodeReader(n, info)
	if err != nil {
		return err
	}
	nKeys := r.EntryCount()
	if nKeys == 0 {
		return nil
	}
	if n.IsLeaf() {
		lo, hi := 0, nKeys
		for lo < hi {
			mid := (lo + hi) / 2
			k, kerr := r.keyAt(mid)
			if kerr != nil {
				return kerr
			}
			if compareFSKey(k, target) < 0 {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		for i := lo; i < nKeys; i++ {
			k, err := r.keyAt(i)
			if err != nil {
				return err
			}
			val, err := r.valueAt(i)
			if err != nil {
				return err
			}
			stop, verr := visit(k, val)
			if verr != nil {
				return verr
			}
			if stop {
				return errIterStop
			}
		}
		return nil
	}
	// Internal node: rightmost entry with key ≤ target.
	lo, hi := 0, nKeys
	for lo < hi {
		mid := (lo + hi) / 2
		k, kerr := r.keyAt(mid)
		if kerr != nil {
			return kerr
		}
		if compareFSKey(k, target) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	startChild := lo - 1
	if startChild < 0 {
		startChild = 0
	}
	if err := v.seekIterChild(n, r, info, startChild, target, visit, g); err != nil {
		return err
	}
	minTarget := make([]byte, 8) // (oid=0, type=0): less than any real key
	for i := startChild + 1; i < nKeys; i++ {
		if err := v.seekIterChild(n, r, info, i, minTarget, visit, g); err != nil {
			return err
		}
	}
	return nil
}

func (v *Volume) seekIterChild(parent *btreeNode, r *nodeReader, info *btreeInfo, idx int, target []byte, visit func(k, val []byte) (bool, error), g *btreeGuard) error {
	block, paddr, err := v.readFSChildBlock(r, idx)
	if err != nil {
		return err
	}
	child, err := readBTreeNode(block)
	if err != nil {
		return err
	}
	cg, err := g.descend(parent, child, paddr)
	if err != nil {
		return err
	}
	return v.seekIterNode(child, info, target, visit, cg)
}

// LookupInodeRecord locates the J_INODE_VAL for the given oid using B-tree
// binary search through the FS-tree (O(log n) reads instead of the linear
// scan performed by FindInode). The returned Inode has Mode, Size,
// IsDir and ParentID populated; Name and dataExtents are NOT populated
// (those records live under different keys in the tree). Use FindInode
// when full inode information is required.
func (v *Volume) LookupInodeRecord(oid uint64) (Inode, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	target := make([]byte, 8)
	binary.LittleEndian.PutUint64(target, oid|(uint64(jTypeInode)<<60))
	_, val, err := v.lookupFSTreeFirst(target)
	if err != nil {
		return Inode{}, err
	}
	ino, err := decodeInode(oid, val)
	if err != nil {
		return Inode{}, err
	}
	return *ino, nil
}

// LookupInodeRawValue returns the raw J_INODE_VAL bytes for the inode
// with the given oid. Used by debug helpers; production code should
// prefer LookupInodeRecord / FindInode.
func (v *Volume) LookupInodeRawValue(oid uint64) ([]byte, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	target := make([]byte, 8)
	binary.LittleEndian.PutUint64(target, oid|(uint64(jTypeInode)<<60))
	_, val, err := v.lookupFSTreeFirst(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(val))
	copy(out, val)
	return out, nil
}

// DebugWalkInodes calls visit(oid, rawJInodeVal) for every J_INODE record
// in the FS-tree, walking multi-level trees via traverseFSTree.
func (v *Volume) DebugWalkInodes(visit func(oid uint64, val []byte)) error {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	return v.traverseFSTree(func(k, val []byte) error {
		if len(k) < 8 {
			return nil
		}
		oid, typ, _ := jKeyHeader(k)
		if typ != jTypeInode {
			return nil
		}
		buf := make([]byte, len(val))
		copy(buf, val)
		visit(oid, buf)
		return nil
	})
}

// FindInode locates an inode by object id and returns a fully populated
// Inode (Mode, Size, IsDir, ParentID, Name and dataExtents).
//
// Implementation: two B-tree seeks via seekAndIterate, both O(log n + k)
// where k is the number of records visited.
//   - Phase 1 seeks (oid, type=0) and walks forward while j_key.oid == oid,
//     gathering J_INODE_VAL, J_FILE_EXTENT (and could trivially gather
//     xattrs / sibling links — those expose dedicated APIs already).
//   - Phase 2 seeks (parent_id, jTypeDirRec) and walks forward while the
//     j_key prefix stays at that (parent_id, type), looking for the drec
//     whose value's file_id field matches our oid; that drec carries the
//     directory entry name.
//
// Requires the FS-tree leaves to be sorted in canonical APFS order
// (by compareFSKey) — synthetic test images built with this package's
// helpers honour that automatically.
func (v *Volume) FindInode(oid uint64) (Inode, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	var ino Inode
	found := false
	target := make([]byte, 8)
	binary.LittleEndian.PutUint64(target, oid) // type=0 → smallest type for this oid
	err := v.seekAndIterate(target, func(k, val []byte) (bool, error) {
		kOID, typ, jerr := jKeyHeader(k)
		if jerr != nil {
			return false, nil
		}
		// kOID < oid: an entry that sorts before our target by full
		// uint64 key but for a different inode (e.g. inode 2's records
		// when looking for inode 1000). Skip and keep iterating.
		if kOID < oid {
			return false, nil
		}
		// kOID > oid: we've passed our oid — stop.
		if kOID != oid {
			return true, nil
		}
		switch typ {
		case jTypeInode:
			decoded, perr := decodeInode(oid, val)
			if perr == nil {
				ino = *decoded
				found = true
			}
		case jTypeFileExt:
			if ext, ok := decodeFileExtent(k, val); ok {
				ino.dataExtents = append(ino.dataExtents, ext)
			}
		}
		return false, nil
	})
	if err != nil {
		return Inode{}, err
	}
	if !found {
		return Inode{}, os.ErrNotExist
	}
	if ino.ParentID != 0 {
		drecTarget := make([]byte, 8)
		binary.LittleEndian.PutUint64(drecTarget, ino.ParentID|(uint64(jTypeDirRec)<<60))
		err = v.seekAndIterate(drecTarget, func(k, val []byte) (bool, error) {
			kOID, typ, jerr := jKeyHeader(k)
			if jerr != nil {
				return false, nil
			}
			if kOID != ino.ParentID || typ != jTypeDirRec {
				return true, nil
			}
			if len(val) >= 8 && binary.LittleEndian.Uint64(val[0:8]) == oid {
				ino.Name = decodeDirRecName(k, val)
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return Inode{}, err
		}
	}
	return ino, nil
}

// traverseFSTree calls visit for every (key, value) pair in every leaf of
// the volume's FS-tree, descending through every internal node. Internal
// nodes' child OIDs are virtual and resolved through the volume's object
// map (volOmap).
func (v *Volume) traverseFSTree(visit func(key, val []byte) error) error {
	return v.traverseFSNode(v.rootNode, v.rootInfo, visit, newBTreeGuard())
}

func (v *Volume) traverseFSNode(n *btreeNode, info *btreeInfo, visit func(key, val []byte) error, g *btreeGuard) error {
	r, err := newNodeReader(n, info)
	if err != nil {
		return err
	}
	if n.IsLeaf() {
		for i := 0; i < r.EntryCount(); i++ {
			k, err := r.keyAt(i)
			if err != nil {
				return err
			}
			val, err := r.valueAt(i)
			if err != nil {
				return err
			}
			if err := visit(k, val); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < r.EntryCount(); i++ {
		block, paddr, err := v.readFSChildBlock(r, i)
		if err != nil {
			return err
		}
		child, err := readBTreeNode(block)
		if err != nil {
			return err
		}
		cg, err := g.descend(n, child, paddr)
		if err != nil {
			return err
		}
		if err := v.traverseFSNode(child, info, visit, cg); err != nil {
			return err
		}
	}
	return nil
}

// decodeInode parses a J_INODE_VAL. Only the fields the public API exposes
// are decoded; the rest of the structure is skipped over.
func decodeInode(oid uint64, val []byte) (*Inode, error) {
	if len(val) < 92 {
		return nil, fmt.Errorf("apfs: J_INODE_VAL too short (%d)", len(val))
	}
	parent := binary.LittleEndian.Uint64(val[0:8])
	// val[8:16] private_id, val[16:24] create_time, val[24:32] mod_time, etc.
	mode := binary.LittleEndian.Uint16(val[80:82])
	size := uint64(0)
	// J_DSTREAM lives in extended fields (xfields). For directories size = 0;
	// for regular files the logical size is in xfields, but we extract a
	// best-effort value from the trailing apfs_dstream_t when present.
	if len(val) >= 92+24 {
		// xfields blob start: offset 92 contains 16-bit count + 16-bit used,
		// followed by xfield_t entries. Parsing them is intricate; we make a
		// scan pass for INO_EXT_TYPE_DSTREAM (0x08) which carries
		// j_dstream_t {size,alloced_size,default_crypto_id,total_bytes_written}.
		size = scanDStreamSize(val[92:])
	}
	isDir := (mode & 0xF000) == 0x4000
	return &Inode{
		ID:       oid,
		ParentID: parent,
		Mode:     mode,
		Size:     size,
		IsDir:    isDir,
	}, nil
}

// scanDStreamSize is a best-effort scan of the xfield blob for a J_DSTREAM
// entry. It returns 0 when no such entry is present.
func scanDStreamSize(blob []byte) uint64 {
	if off, ok := findDStreamSizeOffset(blob); ok {
		return binary.LittleEndian.Uint64(blob[off : off+8])
	}
	return 0
}

// findDStreamSizeOffset returns the byte offset within blob (an
// inode's xfield region, i.e. val[92:] for the standard J_INODE_VAL
// layout) where the J_DSTREAM.size uint64 lives, or (0, false) when no
// J_DSTREAM xfield is present. Used by both the read path
// (scanDStreamSize) and the write path (WriteFile metadata cascade).
//
// Apple's xfield data area: the FIRST field's data starts immediately
// after the xfield_t array (at blob_offset = 4 + 4*count, val_offset =
// 92 + 4 + 4*count — not necessarily 8-aligned in val). Each SUBSEQUENT
// field's data is 8-byte aligned **relative to the J_INODE_VAL start**,
// not relative to the xfields blob start. Since the xfields blob lives at
// val[92] and 92 mod 8 = 4, val-relative 8-alignment means
// `(blobOff + 4) mod 8 == 0` — in blob-relative coordinates the alignment
// is offset by 4. Inodes Apple writes for regular files commonly carry
// [INO_EXT_TYPE_NAME, INO_EXT_TYPE_DSTREAM] in that order; reading the
// DSTREAM at the wrong (blob-aligned-but-not-val-aligned) offset returns
// the size shifted left by 32 bits, because the actual `size` low bytes
// land in the upper half of our 64-bit read.
const apfsInodeXFieldsAlignBias = 4

func findDStreamSizeOffset(blob []byte) (int, bool) {
	if len(blob) < 4 {
		return 0, false
	}
	count := binary.LittleEndian.Uint16(blob[0:2])
	// each xfield_t header: u8 type, u8 flags, u16 size = 4 bytes.
	headerLen := int(count) * 4
	if 4+headerLen > len(blob) {
		return 0, false
	}
	// First field starts immediately after xfield_t array; no extra align.
	dataStart := 4 + headerLen
	off := 4
	dataOff := dataStart
	for i := 0; i < int(count); i++ {
		typ := blob[off]
		size := int(binary.LittleEndian.Uint16(blob[off+2 : off+4]))
		off += 4
		fieldOff := dataOff
		if typ == 0x08 && size >= 8 && fieldOff+8 <= len(blob) {
			return fieldOff, true
		}
		// Subsequent fields are 8-byte aligned relative to val start.
		dataOff = alignToValBoundary(dataOff + size)
	}
	return 0, false
}

// alignToValBoundary rounds a blob-relative offset up so that
// `offset + apfsInodeXFieldsAlignBias` is a multiple of 8 — i.e. so that
// the corresponding val-relative offset (offset + 92) is 8-byte aligned.
func alignToValBoundary(blobOff int) int {
	abs := blobOff + apfsInodeXFieldsAlignBias
	if rem := abs % 8; rem != 0 {
		blobOff += 8 - rem
	}
	return blobOff
}

// decodeDirRecName extracts the directory entry name from a (key, value)
// pair. APFS uses two distinct on-disk shapes for J_DIR_REC keys:
//
//   - Unhashed (apfs_drec_key_t, case-sensitive volumes): j_key (8) +
//     uint16 name_len (2) + NUL-terminated name. Total = 10 + name_len.
//   - Hashed   (apfs_drec_hashed_key_t, case-insensitive volumes —
//     APFS_INCOMPAT_CASE_INSENSITIVE): j_key (8) + uint32
//     name_len_and_hash (4) + NUL-terminated name. Total = 12 + name_len.
//     Within `name_len_and_hash`, the low 10 bits hold name_len and the
//     upper 22 bits hold a CRC-32C hash of the name.
//
// We detect which shape by checking whether the candidate name_len
// reconstructs the actual key length. The parser is shape-agnostic so
// it works on both Apple-produced unhashed containers (older volumes,
// `mkapfs --norm-sensitive`) and our hashed output (D-8).
func decodeDirRecName(k, _ []byte) string {
	if len(k) < 10 {
		return ""
	}
	// Try hashed first: the low 10 bits of the uint32 at offset 8 give
	// name_len, and the total key length should be 12 + name_len.
	if len(k) >= 12 {
		nameLenAndHash := binary.LittleEndian.Uint32(k[8:12])
		nameLen := int(nameLenAndHash & 0x3FF)
		if 12+nameLen == len(k) {
			raw := k[12 : 12+nameLen]
			if i := indexByte(raw, 0); i >= 0 {
				raw = raw[:i]
			}
			return string(raw)
		}
	}
	// Fall back to unhashed: uint16 name_len at offset 8.
	nameLen := int(binary.LittleEndian.Uint16(k[8:10]))
	if 10+nameLen > len(k) {
		return ""
	}
	raw := k[10 : 10+nameLen]
	if i := indexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return string(raw)
}

// decodeFileExtent extracts a (logicalOffset, length, physBlock) tuple from
// a J_FILE_EXTENT (key, value) pair. Returns ok=false if the record is too
// short or describes a sparse hole (phys_block_num = 0).
func decodeFileExtent(k, val []byte) (containerExtent, bool) {
	if len(k) < 16 || len(val) < 24 {
		return containerExtent{}, false
	}
	logical := binary.LittleEndian.Uint64(k[8:16])
	// J_FILE_EXTENT_VAL: u64 len_and_flags (low 56 bits = length in bytes),
	// u64 phys_block_num, u64 crypto_id.
	lenAndFlags := binary.LittleEndian.Uint64(val[0:8])
	length := lenAndFlags & ((uint64(1) << 56) - 1)
	phys := binary.LittleEndian.Uint64(val[8:16])
	if phys == 0 {
		return containerExtent{}, false
	}
	return containerExtent{
		logicalOffset: logical,
		length:        length,
		physBlock:     phys,
	}, true
}

// ReadFile reads the contents of a regular file by concatenating every
// J_FILE_EXTENT for the inode in logical-offset order. Sparse holes (gaps
// between extents) are zero-filled. The trailing zero region implied by
// inode.Size > sum(extent.length) is also zero-filled.
func (v *Volume) ReadFile(inode Inode) ([]byte, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	if inode.IsDir {
		return nil, fmt.Errorf("apfs: ReadFile on directory %q", inode.Name)
	}
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	// Cap every untrusted allocation against the container's byte size: an
	// inode.Size / ext.length / sparse-hole gap larger than the whole image
	// is malformed, so reject it rather than attempt a huge make(). (C3.)
	maxBytes := v.c.containerByteSize()
	if len(inode.dataExtents) == 0 {
		// Nothing on disk; honour the logical size with zeros.
		return safeio.MakeBytes(int64(inode.Size), maxBytes)
	}
	extents := make([]containerExtent, len(inode.dataExtents))
	copy(extents, inode.dataExtents)
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].logicalOffset < extents[j].logicalOffset
	})
	out := make([]byte, 0)
	var expected uint64
	for _, ext := range extents {
		if ext.logicalOffset > expected {
			// Sparse hole: pad with zeros up to the next extent's start.
			pad, err := safeio.MakeBytes(int64(ext.logicalOffset-expected), maxBytes)
			if err != nil {
				return nil, fmt.Errorf("apfs: sparse hole: %w", err)
			}
			out = append(out, pad...)
			expected = ext.logicalOffset
		}
		if ext.logicalOffset < expected {
			return nil, fmt.Errorf("apfs: overlapping extents at logical %d (already at %d)", ext.logicalOffset, expected)
		}
		chunk, err := safeio.MakeBytes(int64(ext.length), maxBytes)
		if err != nil {
			return nil, fmt.Errorf("apfs: extent length: %w", err)
		}
		if _, err := v.c.r.ReadAt(chunk, int64(ext.physBlock*bs)); err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		expected += ext.length
	}
	// Trailing zero region (size declared in the inode but not covered by
	// any extent) — zero-fill or truncate as appropriate.
	if expected < inode.Size {
		pad, err := safeio.MakeBytes(int64(inode.Size-expected), maxBytes)
		if err != nil {
			return nil, fmt.Errorf("apfs: trailing zero region: %w", err)
		}
		out = append(out, pad...)
	}
	if uint64(len(out)) > inode.Size {
		out = out[:inode.Size]
	}
	return out, nil
}
