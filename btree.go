package filesystem_apfs

// btree.go decodes APFS B-tree nodes (object type btree_node_phys_t).
// APFS uses a single B-tree shape across the container: it carries the
// object map (fixed key/value), the FS-tree (variable key/value), the
// extent-ref tree, the snapshot metadata tree, and so on. The shape of a
// node is uniform; only the keys/values inside differ.

import (
	"encoding/binary"
	"fmt"
)

// B-tree node flags (btn_flags).
const (
	btnFlagRoot        uint16 = 0x0001
	btnFlagLeaf        uint16 = 0x0002
	btnFlagFixedKVSize uint16 = 0x0004
	btnFlagHashed      uint16 = 0x0008
	btnFlagNoHeader    uint16 = 0x0010
)

// nlocOff is "no offset" — used in TOC entries to mark unused / removed.
// Same value Apple's apfs_raw.h calls APFS_BTOFF_INVALID; we re-export it
// under that name from the format encoder for self-documenting writes.
const nlocOff uint16 = 0xFFFF
const btoffInvalid uint16 = nlocOff

// B-tree info-footer flags (apfs_btree_info_fixed.bt_flags). Each flag
// describes a property of the tree as a whole (storage class, value
// alignment, …) rather than of any single node.
const (
	btreeFlagUint64Keys       uint32 = 0x00000001
	btreeFlagSequentialInsert uint32 = 0x00000002
	btreeFlagAllowGhosts      uint32 = 0x00000004
	btreeFlagEphemeral        uint32 = 0x00000008
	btreeFlagPhysical         uint32 = 0x00000010
	btreeFlagNonpersistent    uint32 = 0x00000020
	btreeFlagKVNonAligned     uint32 = 0x00000040
)

// btreeNode is the in-memory view of one B-tree node block.
type btreeNode struct {
	hdr        objPhys
	flags      uint16
	level      uint16
	nKeys      uint32
	tableSpace nloc // table-of-contents region (relative to btn_data)
	freeSpace  nloc
	keyFreeLst nloc
	valFreeLst nloc
	data       []byte // btn_data: TOC + keys + values
	// raw block (used for resolving offsets and reading the trailing btree_info
	// in the root node).
	block []byte
}

// nloc is "node location": a (offset, length) pair used throughout B-tree
// node bookkeeping.
type nloc struct {
	off uint16
	len uint16
}

func readNloc(b []byte) nloc {
	return nloc{
		off: binary.LittleEndian.Uint16(b[0:2]),
		len: binary.LittleEndian.Uint16(b[2:4]),
	}
}

// btreeNodeHeaderSize is the on-disk size of the node header that follows the
// object header: btn_flags(2) + btn_level(2) + btn_nkeys(4) + table_space(4) +
// free_space(4) + key_free_list(4) + val_free_list(4).
const btreeNodeHeaderSize = 24

// readBTreeNode decodes a B-tree node from a block of bytes (typically one
// container block, 4096 bytes by default).
func readBTreeNode(block []byte) (*btreeNode, error) {
	if len(block) < objPhysSize+btreeNodeHeaderSize {
		return nil, fmt.Errorf("apfs: btree_node: short block (%d)", len(block))
	}
	hdr, err := readObjPhys(block[:objPhysSize])
	if err != nil {
		return nil, err
	}
	objType := hdr.typ & 0x00FF
	if objType != objTypeBTree && objType != objTypeBTreeNode {
		return nil, fmt.Errorf("apfs: btree_node: wrong object type 0x%04x", hdr.typ)
	}
	off := objPhysSize
	flags := binary.LittleEndian.Uint16(block[off : off+2])
	level := binary.LittleEndian.Uint16(block[off+2 : off+4])
	nKeys := binary.LittleEndian.Uint32(block[off+4 : off+8])
	tableSpace := readNloc(block[off+8 : off+12])
	freeSpace := readNloc(block[off+12 : off+16])
	keyFreeLst := readNloc(block[off+16 : off+20])
	valFreeLst := readNloc(block[off+20 : off+24])
	dataStart := off + btreeNodeHeaderSize
	if dataStart > len(block) {
		return nil, fmt.Errorf("apfs: btree_node: data start past end of block")
	}
	return &btreeNode{
		hdr:        hdr,
		flags:      flags,
		level:      level,
		nKeys:      nKeys,
		tableSpace: tableSpace,
		freeSpace:  freeSpace,
		keyFreeLst: keyFreeLst,
		valFreeLst: valFreeLst,
		data:       block[dataStart:],
		block:      block,
	}, nil
}

// IsLeaf reports whether this node carries values (true) or child pointers
// (false).
func (n *btreeNode) IsLeaf() bool { return n.flags&btnFlagLeaf != 0 }

// IsRoot reports whether this is the root node of its tree.
func (n *btreeNode) IsRoot() bool { return n.flags&btnFlagRoot != 0 }

// HasFixedKVSize reports whether all keys and values in this tree are the
// same length (true for object maps; false for the FS-tree).
func (n *btreeNode) HasFixedKVSize() bool { return n.flags&btnFlagFixedKVSize != 0 }

// btreeInfoSize is the on-disk size of the btree_info_t trailer that lives
// at the end of every B-tree root node.
const btreeInfoSize = 40

// btreeInfo decodes the trailer of a root node. bt_fixed contains the fixed
// key/value lengths when btnFlagFixedKVSize is set; longest_key/longest_val
// describe the worst-case sizes for variable-shaped trees.
type btreeInfo struct {
	flags     uint32
	nodeSize  uint32
	keySize   uint32
	valSize   uint32
	longKey   uint32
	longVal   uint32
	keyCount  uint64
	nodeCount uint64
}

// readRootBTreeInfo parses the trailer of a root B-tree node from the raw
// block backing it. It must only be called for nodes where IsRoot() is true.
func readRootBTreeInfo(block []byte) (*btreeInfo, error) {
	if len(block) < btreeInfoSize {
		return nil, fmt.Errorf("apfs: btree_info: short block")
	}
	off := len(block) - btreeInfoSize
	bi := &btreeInfo{
		flags:     binary.LittleEndian.Uint32(block[off : off+4]),
		nodeSize:  binary.LittleEndian.Uint32(block[off+4 : off+8]),
		keySize:   binary.LittleEndian.Uint32(block[off+8 : off+12]),
		valSize:   binary.LittleEndian.Uint32(block[off+12 : off+16]),
		longKey:   binary.LittleEndian.Uint32(block[off+16 : off+20]),
		longVal:   binary.LittleEndian.Uint32(block[off+20 : off+24]),
		keyCount:  binary.LittleEndian.Uint64(block[off+24 : off+32]),
		nodeCount: binary.LittleEndian.Uint64(block[off+32 : off+40]),
	}
	return bi, nil
}

// kvLoc is the variable-key/value TOC entry: (key nloc, value nloc).
type kvLoc struct {
	key nloc
	val nloc
}

// kvOff is the fixed-key/value TOC entry: 16-bit offsets into the key and
// value areas, with the entry size implied by the tree's btreeInfo.
type kvOff struct {
	key uint16
	val uint16
}

// readKVOff parses a 4-byte fixed-shape TOC entry.
func readKVOff(b []byte) kvOff {
	return kvOff{
		key: binary.LittleEndian.Uint16(b[0:2]),
		val: binary.LittleEndian.Uint16(b[2:4]),
	}
}

// readKVLoc parses an 8-byte variable-shape TOC entry.
func readKVLoc(b []byte) kvLoc {
	return kvLoc{
		key: readNloc(b[0:4]),
		val: readNloc(b[4:8]),
	}
}

// nodeReader exposes the (key, value) pairs of a leaf node by lazily slicing
// into the underlying data. Internal nodes use the same TOC but the value
// area holds a uint64 child OID instead of an opaque value.
type nodeReader struct {
	node    *btreeNode
	fixed   bool
	keySize uint32 // only set when fixed
	valSize uint32 // only set when fixed
	tocBase int    // byte offset into node.data where the TOC starts
	keyBase int    // byte offset into node.data where the key area starts
	valBase int    // byte offset into node.data where the value area ENDS (values grow toward 0 from this point in fixed-shape trees)
}

// newNodeReader prepares a node for sequential or random key/value access.
// When the tree has fixed key/value sizes, info must be supplied (typically
// read from the root node trailer). For variable-shape trees, info may be
// nil.
func newNodeReader(n *btreeNode, info *btreeInfo) (*nodeReader, error) {
	r := &nodeReader{
		node:  n,
		fixed: n.HasFixedKVSize(),
	}
	r.tocBase = int(n.tableSpace.off)
	r.keyBase = r.tocBase + int(n.tableSpace.len)
	// In fixed-shape trees the value area grows from the end of the node
	// toward the key area. Apple stores values relative to the node end; for
	// non-root nodes that end is len(data) - 0 = len(data); for root nodes
	// it is len(data) - btreeInfoSize.
	dataLen := len(n.data)
	if n.IsRoot() {
		dataLen -= btreeInfoSize
	}
	r.valBase = dataLen
	if r.fixed {
		if info == nil {
			return nil, fmt.Errorf("apfs: nodeReader: fixed-shape tree requires btreeInfo")
		}
		r.keySize = info.keySize
		r.valSize = info.valSize
	}
	return r, nil
}

// EntryCount returns the number of populated TOC entries in the node.
func (r *nodeReader) EntryCount() int { return int(r.node.nKeys) }

// keyAt returns the bytes of the i-th key in the node.
func (r *nodeReader) keyAt(i int) ([]byte, error) {
	if i < 0 || i >= int(r.node.nKeys) {
		return nil, fmt.Errorf("apfs: keyAt: index %d out of range (nkeys=%d)", i, r.node.nKeys)
	}
	if r.fixed {
		entryOff := r.tocBase + i*4
		toc := readKVOff(r.node.data[entryOff : entryOff+4])
		start := r.keyBase + int(toc.key)
		end := start + int(r.keySize)
		if end > len(r.node.data) {
			return nil, fmt.Errorf("apfs: keyAt: key past end of node")
		}
		return r.node.data[start:end], nil
	}
	entryOff := r.tocBase + i*8
	toc := readKVLoc(r.node.data[entryOff : entryOff+8])
	if toc.key.off == nlocOff {
		return nil, fmt.Errorf("apfs: keyAt: removed entry %d", i)
	}
	start := r.keyBase + int(toc.key.off)
	end := start + int(toc.key.len)
	if end > len(r.node.data) {
		return nil, fmt.Errorf("apfs: keyAt: key past end of node")
	}
	return r.node.data[start:end], nil
}

// valueAt returns the bytes of the i-th value in the node.
//
// For leaf nodes this is the user-visible payload (omap_val, fs-tree value,
// etc.). For internal nodes it is an 8-byte child OID (to be looked up via
// the same object map).
func (r *nodeReader) valueAt(i int) ([]byte, error) {
	if i < 0 || i >= int(r.node.nKeys) {
		return nil, fmt.Errorf("apfs: valueAt: index %d out of range", i)
	}
	if r.fixed {
		entryOff := r.tocBase + i*4
		toc := readKVOff(r.node.data[entryOff : entryOff+4])
		// Internal-node values are uint64 child OIDs (8 bytes); leaf values
		// follow the tree-wide valSize.
		size := r.valSize
		if !r.node.IsLeaf() {
			size = 8
		}
		// Values in fixed-shape trees grow backward from val_end. Per
		// Apple's apfs.h, kvoff.v is the distance from val_end to the
		// START of the value, so the value occupies
		// [val_end - kvoff.v, val_end - kvoff.v + size]. mkapfs writes
		// kvoff.v = val_len for the first value, 2*val_len for the
		// second, and so on.
		start := r.valBase - int(toc.val)
		end := start + int(size)
		if start < 0 || end > len(r.node.data) {
			return nil, fmt.Errorf("apfs: valueAt: value out of range")
		}
		return r.node.data[start:end], nil
	}
	entryOff := r.tocBase + i*8
	toc := readKVLoc(r.node.data[entryOff : entryOff+8])
	if toc.val.off == nlocOff {
		return nil, fmt.Errorf("apfs: valueAt: removed entry %d", i)
	}
	// Variable-shape (kvloc) convention matches fixed-shape: val.off is
	// the distance from val_end (the values area's high boundary) to
	// the value's START (values grow backward toward keys). fsck_apfs
	// rejects val.off = 0 for variable entries with "invalid value
	// (0, len)" — the first stored value's off must equal its own
	// length.
	start := r.valBase - int(toc.val.off)
	end := start + int(toc.val.len)
	if start < 0 || end > len(r.node.data) {
		return nil, fmt.Errorf("apfs: valueAt: value out of range")
	}
	return r.node.data[start:end], nil
}

// childOIDAt returns the uint64 child OID stored as the value of an internal
// (non-leaf) node entry. APFS stores either a bare uint64 (8 bytes) for
// regular B-trees, or a btn_index_node_val { uint64 oid + 32-byte hash } for
// HASHED trees (sealed volumes). Either layout is accepted: only the
// leading 8 bytes are read.
func (r *nodeReader) childOIDAt(i int) (uint64, error) {
	if r.node.IsLeaf() {
		return 0, fmt.Errorf("apfs: childOIDAt: node is a leaf")
	}
	v, err := r.valueAt(i)
	if err != nil {
		return 0, err
	}
	if len(v) < 8 {
		return 0, fmt.Errorf("apfs: childOIDAt: expected at least 8 bytes, got %d", len(v))
	}
	return binary.LittleEndian.Uint64(v[:8]), nil
}

// childHashAt returns the 32-byte SHA-256 digest that follows the 8-byte
// child OID in a HASHED B-tree internal node, or (nil, false) when the
// tree is not hashed (i.e. value is exactly 8 bytes).
func (r *nodeReader) childHashAt(i int) ([]byte, bool) {
	if r.node.IsLeaf() {
		return nil, false
	}
	v, err := r.valueAt(i)
	if err != nil || len(v) <= 8 {
		return nil, false
	}
	return v[8:], true
}
