package filesystem_apfs

// compress_write.go is the compress-on-write counterpart to the decmpfs
// read path in compress.go. `CreateFileCompressed` writes a regular file
// whose content is stored transparently compressed the same way Apple's
// AppleFSCompression / `ditto --hfsCompression` stores it:
//
//   - the inode carries the UF_COMPRESSED bsd flag and the uncompressed
//     logical size in j_inode_val.uncompressed_size, and has NO data
//     stream (no J_FILE_EXTENT / J_DSTREAM_ID for the main fork);
//   - a `com.apple.decmpfs` xattr carries the 16-byte decmpfs header and,
//     for inline compression types, the compressed payload itself;
//   - for resource-fork compression the compressed payload lives in a
//     `com.apple.ResourceFork` xattr (embedded when small, a stream xattr
//     otherwise) laid out in Apple's real chunked offset-table format.
//
// The produced file reads back correctly both through this package's own
// `ReadFileTransparent` and through apfs.kext (macOS transparently
// decompresses it on read; verified end-to-end in the darwin mount test).
//
// Codecs produced:
//   - inline zlib  (type 3)  — stdlib compress/zlib
//   - inline LZFSE (type 11) — go-compressions/lzfse (LZVN block for the
//     small inline sizes we emit — fully interoperable with apfs.kext)
//   - rsrc  LZVN   (type 8)  — chunked LZVN, Apple byte-0 offset table
//     (exactly what `ditto --hfsCompression` writes; kext-read-verified)
//
// Selection: small files whose whole-file compressed body fits the inline
// xattr budget use inline compression; larger files use the LZVN resource
// fork. Chunks (and inline bodies) that do not shrink fall back to Apple's
// 0xFF "raw passthrough" so an incompressible input never inflates on disk.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/go-compressions/lzfse"
)

// CompressionCodec selects the codec CreateFileCompressed uses for the
// inline representation of a small file. The resource-fork representation
// (used for files larger than one 64 KiB chunk) is always chunked LZVN
// (decmpfs type 8) — byte-for-byte what `ditto --hfsCompression` writes.
//
// Only formats that are fully interoperable with apfs.kext are emitted:
// zlib (stdlib, correct at any size) and LZVN (Apple's block format,
// interoperable in both directions). The LZFSE bvx2 block format is
// deliberately NOT produced on the write path — it is accepted on the read
// path (types 11/12) but is not reliably round-trippable through Apple's
// decoder for all inputs.
type CompressionCodec int

const (
	// CompressAuto compresses inline with whichever of zlib / LZVN yields
	// the smaller body (the default).
	CompressAuto CompressionCodec = iota
	// CompressZlib forces zlib for the inline body (decmpfs type 3).
	CompressZlib
	// CompressLZVN forces LZVN for the inline body (decmpfs type 7).
	CompressLZVN
)

// bsdFlagUFCompressed is UF_COMPRESSED (from <sys/stat.h>): the bsd_flags
// bit that marks a file's content as transparently compressed. apfs.kext
// keys its decmpfs read path on this bit.
const bsdFlagUFCompressed uint32 = 0x00000020

// maxInlineDecmpfsWrite bounds the com.apple.decmpfs xattr payload (16-byte
// header + inline compressed body) chosen for inline compression. A file
// whose inline body would exceed this uses the resource-fork path instead.
// Kept well under a single 4 KiB FS-tree leaf so the xattr fits alongside
// the inode + drec records. Declared as a var so tests can force the
// resource-fork path on small inputs.
var maxInlineDecmpfsWrite = 3072

// maxEmbedRsrcWrite bounds a com.apple.ResourceFork payload stored as an
// embedded xattr; larger resource forks are written as a stream xattr.
var maxEmbedRsrcWrite = 1024

// decmpfsRep is the chosen on-disk representation of a compressed file:
// the decmpfs xattr payload plus, for resource-fork types, the resource
// fork contents.
type decmpfsRep struct {
	cmpType          uint32
	uncompressedSize uint64
	decmpfsPayload   []byte // com.apple.decmpfs value (header [+ inline body])
	rsrcFork         []byte // com.apple.ResourceFork value, or nil for inline
}

// CreateFileCompressed inserts a regular file under parentOID whose content
// is stored transparently compressed (com.apple.decmpfs). It picks the
// codec automatically (CompressAuto). Returns the new inode's object id.
//
// Preconditions match CreateFile: a writable container, a live (non
// snapshot) volume, a non-empty name, and — because a compressed file has
// no zero-length representation here — non-empty data. Use CreateFile for
// empty or deliberately uncompressed files.
func (v *Volume) CreateFileCompressed(parentOID uint64, name string, data []byte) (uint64, error) {
	return v.createFileCompressed(parentOID, name, data, CompressAuto)
}

// CreateFileCompressedCodec is CreateFileCompressed with an explicit inline
// codec choice.
func (v *Volume) CreateFileCompressedCodec(parentOID uint64, name string, data []byte, codec CompressionCodec) (uint64, error) {
	return v.createFileCompressed(parentOID, name, data, codec)
}

func (v *Volume) createFileCompressed(parentOID uint64, name string, data []byte, codec CompressionCodec) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: CreateFileCompressed on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: CreateFileCompressed: empty name")
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("apfs: CreateFileCompressed: empty data (use CreateFile)")
	}

	rep, err := buildDecmpfsRepresentation(data, codec)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateFileCompressed: %w", err)
	}

	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, fmt.Errorf("apfs: CreateFileCompressed: resolve FS-tree root: %w", err)
	}
	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}
	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	records := []fsLeafKV{
		{key: encodeInodeKey(newOID), val: encodeCompressedInodeValue(newOID, parentOID, rep.uncompressedSize, 0o100644, rep.rsrcFork != nil)},
		{key: encodeDrecKey(parentOID, name), val: encodeDrecValue(newOID, drecTypeRegFile)},
		{key: encodeXattrKey(newOID, decmpfsXAttrName), val: encodeXattrEmbeddedValue(rep.decmpfsPayload)},
	}
	if rep.rsrcFork != nil {
		if len(rep.rsrcFork) <= maxEmbedRsrcWrite {
			records = append(records, fsLeafKV{
				key: encodeXattrKey(newOID, resourceForkXAttrName),
				val: encodeXattrEmbeddedValue(rep.rsrcFork),
			})
		} else {
			sr, serr := v.buildStreamXAttrRecordsLocked(newOID, resourceForkXAttrName, rep.rsrcFork)
			if serr != nil {
				return 0, fmt.Errorf("apfs: CreateFileCompressed: rsrc stream: %w", serr)
			}
			records = append(records, sr...)
		}
	}

	if err := v.insertNewInodeRecordsLocked(records, parentOID, rebindToRoot, rootPaddr, leafXID); err != nil {
		return 0, fmt.Errorf("apfs: CreateFileCompressed: %w", err)
	}
	return newOID, nil
}

// buildDecmpfsRepresentation compresses data and chooses the inline vs
// resource-fork decmpfs representation. See the package-level notes above
// for the selection policy.
func buildDecmpfsRepresentation(data []byte, codec CompressionCodec) (decmpfsRep, error) {
	usize := uint64(len(data))

	inlineType, inlineBody, err := chooseInlineBody(data, codec)
	if err != nil {
		return decmpfsRep{}, err
	}
	// 0xFF "raw passthrough": if the codec did not shrink the data, store
	// the raw bytes prefixed with 0xFF (the reader and apfs.kext both honour
	// this for the inline zlib/LZVN types).
	if len(inlineBody) >= len(data) {
		inlineBody = append([]byte{0xFF}, data...)
	}
	// Inline is used only for files no larger than one decmpfs chunk whose
	// compressed body fits the inline xattr budget — matching Apple, and
	// keeping the inline decode a single-shot (no chunking).
	if len(data) <= rsrcMaxChunkSize && 16+len(inlineBody) <= maxInlineDecmpfsWrite {
		payload := append(buildDecmpfsHeader(inlineType, usize), inlineBody...)
		return decmpfsRep{cmpType: inlineType, uncompressedSize: usize, decmpfsPayload: payload}, nil
	}

	// Resource fork: chunked LZVN (decmpfs type 8) in Apple's byte-0
	// offset-table layout — the exact format `ditto --hfsCompression`
	// writes and apfs.kext reads. LZVN (not LZFSE bvx2) is used because the
	// LZVN stream format is fully interoperable with Apple's decoder.
	rsrc := buildLZVNRsrcFork(data)
	payload := buildDecmpfsHeader(decmpfsTypeLZVNResource, usize)
	return decmpfsRep{
		cmpType:          decmpfsTypeLZVNResource,
		uncompressedSize: usize,
		decmpfsPayload:   payload,
		rsrcFork:         rsrc,
	}, nil
}

// chooseInlineBody returns the decmpfs inline compression type and the
// compressed inline body for the requested codec. For CompressAuto it
// returns whichever of zlib / LZVN produced the smaller body.
func chooseInlineBody(data []byte, codec CompressionCodec) (uint32, []byte, error) {
	switch codec {
	case CompressZlib:
		return decmpfsTypeZlibInline, zlibDeflate(data), nil
	case CompressLZVN:
		return decmpfsTypeLZVNInline, lzfse.CompressLZVN(data), nil
	case CompressAuto:
		z := zlibDeflate(data)
		l := lzfse.CompressLZVN(data)
		if len(l) < len(z) {
			return decmpfsTypeLZVNInline, l, nil
		}
		return decmpfsTypeZlibInline, z, nil
	default:
		return 0, nil, fmt.Errorf("unknown compression codec %d", codec)
	}
}

// buildDecmpfsHeader serialises the 16-byte decmpfs header (magic "cmpf",
// compression type, uncompressed size).
func buildDecmpfsHeader(cmpType uint32, uncompressedSize uint64) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(h[4:8], cmpType)
	binary.LittleEndian.PutUint64(h[8:16], uncompressedSize)
	return h
}

// zlibDeflate returns data compressed as a zlib stream at default
// compression level. Writing to a bytes.Buffer never fails, so the write
// and close errors are structurally unreachable.
func zlibDeflate(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// buildLZVNRsrcFork builds a com.apple.ResourceFork payload in Apple's real
// chunked LZVN format (decmpfs type 8): the input is split into
// rsrcMaxChunkSize (64 KiB) chunks, each LZVN-compressed (or stored with a
// 0xFF passthrough prefix when compression does not help), preceded by an
// offset table of (N+1) little-endian uint32 offsets measured from byte 0.
// offset[0] == 4*(N+1) (start of the chunk data); offset[N] == total length.
// This is byte-for-byte the layout `ditto --hfsCompression` emits (verified
// against a real ditto image in testdata/golden_big_rsrc.bin) and is what
// apfs.kext reads.
func buildLZVNRsrcFork(data []byte) []byte {
	numChunks := (len(data) + rsrcMaxChunkSize - 1) / rsrcMaxChunkSize
	if numChunks == 0 {
		numChunks = 1
	}
	chunks := make([][]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		start := i * rsrcMaxChunkSize
		end := start + rsrcMaxChunkSize
		if end > len(data) {
			end = len(data)
		}
		raw := data[start:end]
		comp := lzfse.CompressLZVN(raw)
		if len(comp) >= len(raw) {
			// Raw passthrough: 0xFF prefix + verbatim bytes.
			pass := make([]byte, 0, len(raw)+1)
			pass = append(pass, 0xFF)
			pass = append(pass, raw...)
			comp = pass
		}
		chunks[i] = comp
	}

	tableBytes := 4 * (numChunks + 1)
	offsets := make([]uint32, numChunks+1)
	offsets[0] = uint32(tableBytes)
	for i := 0; i < numChunks; i++ {
		offsets[i+1] = offsets[i] + uint32(len(chunks[i]))
	}

	out := make([]byte, tableBytes, offsets[numChunks])
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], off)
	}
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// j_inode_flags bits relevant to compressed files (Apple File System
// Reference / apfs_raw.h).
const (
	inodeFlagHasRsrcFork        uint64 = 0x00004000 // INODE_HAS_RSRC_FORK
	inodeFlagNoRsrcFork         uint64 = 0x00008000 // INODE_NO_RSRC_FORK
	inodeFlagHasUncompressedSz  uint64 = 0x00040000 // INODE_HAS_UNCOMPRESSED_SIZE
)

// encodeCompressedInodeValue serialises a J_INODE_VAL for a transparently
// compressed regular file: the UF_COMPRESSED bsd flag is set, the logical
// size lives in j_inode_val.uncompressed_size (with the matching
// INODE_HAS_UNCOMPRESSED_SIZE internal flag so fsck_apfs does not warn),
// and there is no J_DSTREAM extended field (the file has no main data fork
// — the bytes live in the decmpfs xattr / resource fork). hasRsrcFork
// selects INODE_HAS_RSRC_FORK vs INODE_NO_RSRC_FORK to match whether a
// com.apple.ResourceFork xattr is present. The xf_blob header is emitted
// with a zero field count, matching apfs.kext's shape for compressed files
// (and this package's symlink inode, which likewise has no data fork).
func encodeCompressedInodeValue(oid, parentID, uncompressedSize uint64, mode uint16, hasRsrcFork bool) []byte {
	const baseLen = 92
	const xfHeader = 4
	val := make([]byte, baseLen+xfHeader)
	binary.LittleEndian.PutUint64(val[0:8], parentID)
	binary.LittleEndian.PutUint64(val[8:16], oid) // private_id = own oid
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(val[16:24], now)
	binary.LittleEndian.PutUint64(val[24:32], now)
	binary.LittleEndian.PutUint64(val[32:40], now)
	binary.LittleEndian.PutUint64(val[40:48], now)
	internalFlags := inodeFlagHasUncompressedSz
	if hasRsrcFork {
		internalFlags |= inodeFlagHasRsrcFork
	} else {
		internalFlags |= inodeFlagNoRsrcFork
	}
	binary.LittleEndian.PutUint64(val[48:56], internalFlags)
	binary.LittleEndian.PutUint32(val[56:60], 1)                  // nlink = 1
	binary.LittleEndian.PutUint32(val[60:64], 6)                  // default_protection_class F
	binary.LittleEndian.PutUint32(val[68:72], bsdFlagUFCompressed) // bsd_flags: UF_COMPRESSED
	binary.LittleEndian.PutUint32(val[72:76], uint32(os.Geteuid()))
	binary.LittleEndian.PutUint32(val[76:80], uint32(os.Getegid()))
	binary.LittleEndian.PutUint16(val[80:82], mode)
	binary.LittleEndian.PutUint64(val[84:92], uncompressedSize) // uncompressed_size
	// xf_blob header: count=0, used_data_len=0.
	binary.LittleEndian.PutUint16(val[baseLen:baseLen+2], 0)
	binary.LittleEndian.PutUint16(val[baseLen+2:baseLen+4], 0)
	return val
}

// buildStreamXAttrRecordsLocked allocates a fresh dstream for a large xattr
// payload and returns the FS-tree records that describe it: a J_FILE_EXTENT
// under a fresh xattr_obj_id plus the stream-flagged J_XATTR under
// targetOID. It performs the block allocation, extent-ref insertion and
// alloc-count bump inline; the caller inserts the returned records.
//
// Two details are byte-matched against how apfs.kext / AppleFSCompression
// store a com.apple.ResourceFork stream (reverse-engineered from a real
// `ditto --hfsCompression` image parsed back through this package):
//
//   - xattr_obj_id is drawn from the volume's filesystem object-id space
//     (apfs_next_obj_id, i.e. the same allocator as inode oids — Apple uses
//     inode_oid + 1), NOT the container virtual-oid pool. The kext resolves
//     the resource-fork extent through this id; a virtual-pool id makes it
//     read the wrong blocks.
//   - no J_DSTREAM_ID record is emitted for the xattr stream (Apple emits
//     one only for a file's main data fork, not for xattr streams).
//
// Callers MUST hold v.c.mu.
func (v *Volume) buildStreamXAttrRecordsLocked(targetOID uint64, name string, payload []byte) ([]fsLeafKV, error) {
	bs := v.physicalBlockSize()
	xattrObjID, err := v.nextInodeOID()
	if err != nil {
		return nil, err
	}
	extLen := uint64(len(payload))
	allocSize := ((extLen + bs - 1) / bs) * bs
	if allocSize == 0 {
		allocSize = bs
	}
	extBlocks := allocSize / bs
	firstBlock, err := v.nextFreeBlock()
	if err != nil {
		return nil, err
	}
	if v.allocCursor < firstBlock+extBlocks {
		v.allocCursor = firstBlock + extBlocks
	}
	if _, err := v.c.w.WriteAt(payload, int64(firstBlock*bs)); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}
	if err := v.c.markBlocksAllocated(firstBlock, extBlocks); err != nil {
		return nil, err
	}
	if err := v.appendExtentRefRecord(firstBlock, extBlocks, xattrObjID); err != nil {
		return nil, err
	}
	if err := v.bumpFSAllocCount(int64(extBlocks)); err != nil {
		return nil, err
	}
	return []fsLeafKV{
		{key: encodeFileExtentKey(xattrObjID, 0), val: encodeFileExtentValue(allocSize, firstBlock)},
		{key: encodeXattrKey(targetOID, name), val: encodeXattrStreamValue(xattrObjID, extLen, allocSize)},
	}, nil
}

// insertNewInodeRecordsLocked inserts the FS-tree records for a freshly
// created inode (its J_INODE_VAL, J_DIR_REC, and any xattr / extent /
// dstream records) into the volume's FS-tree, handling the single-leaf
// fit, single-leaf split, and multi-level dispatch paths plus parent
// nchildren maintenance. The caller must hold v.c.mu and must have resolved
// rootPaddr, rebindToRoot and (for the non-root case) the parentOID the
// drec binds to. This mirrors CreateFile's own insertion cascade.
func (v *Volume) insertNewInodeRecordsLocked(newRecords []fsLeafKV, parentOID uint64, rebindToRoot bool, rootPaddr, leafXID uint64) error {
	bs := v.physicalBlockSize()
	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return err
		}
		all := make([]fsLeafKV, 0, len(existing)+len(newRecords)+2)
		all = append(all, existing...)
		all = append(all, newRecords...)
		if rebindToRoot {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, parentOID)
			if err != nil {
				return fmt.Errorf("patch parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return fmt.Errorf("re-emit leaf: %w", err)
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return fmt.Errorf("write leaf at paddr %d: %w", rootPaddr, err)
			}
			return v.reloadRoot(rootPaddr)
		}
		return v.splitRootLeafAndWrite(all, rootPaddr, leafXID)
	}

	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return fmt.Errorf("descend: %w", err)
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return fmt.Errorf("insert: %w", err)
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return fmt.Errorf("refresh root inode: %w", err)
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return fmt.Errorf("refresh parent: %w", err)
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return fmt.Errorf("refresh root: %w", err)
		}
	}
	return nil
}
