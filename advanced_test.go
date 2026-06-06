package filesystem_apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"github.com/go-compressions/lzfse"
)

// xattrStreamValue builds a J_XATTR value that carries a stream reference
// (xattrFlagDataStream). xattr_obj_id = streamID, declared size = streamSize.
func xattrStreamValue(streamID, streamSize uint64) []byte {
	const xLen = 24
	v := make([]byte, 4+xLen)
	binary.LittleEndian.PutUint16(v[0:2], xattrFlagDataStream)
	binary.LittleEndian.PutUint16(v[2:4], xLen)
	binary.LittleEndian.PutUint64(v[4:12], streamID)
	binary.LittleEndian.PutUint64(v[12:20], streamSize)
	return v
}

// TestStreamXAttrRead verifies that ReadXAttrStream walks the FS-tree
// for J_FILE_EXTENT records keyed by the stream's xattr_obj_id and returns
// the concatenated payload trimmed to the declared stream size.
func TestStreamXAttrRead(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 12)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "StreamXAttr")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	const streamID uint64 = 0xBEEF
	const streamSize uint64 = 6000 // 4096 + 1904 partial
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
		{key: drecKey(1, "f"), val: buildDrecValue(101)},
		{key: xattrKey(101, "com.apple.ResourceFork"), val: xattrStreamValue(streamID, streamSize)},
		{key: fileExtKey(streamID, 0), val: buildFileExtentValue(4096, 10)},
		{key: fileExtKey(streamID, 4096), val: buildFileExtentValue(4096, 11)},
	})
	for i := 0; i < 4096; i++ {
		img.blocks[10][i] = 0x11
		img.blocks[11][i] = 0x22
	}

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	xs, err := v.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	if len(xs) != 1 {
		t.Fatalf("len(xs)=%d want 1", len(xs))
	}
	if xs[0].Flags&xattrFlagDataStream == 0 {
		t.Fatalf("expected stream flag")
	}
	if xs[0].StreamID != streamID || xs[0].StreamSize != streamSize {
		t.Fatalf("stream meta mismatch: id=%d size=%d", xs[0].StreamID, xs[0].StreamSize)
	}
	data, err := v.ReadXAttrStream(xs[0])
	if err != nil {
		t.Fatalf("ReadXAttrStream: %v", err)
	}
	if uint64(len(data)) != streamSize {
		t.Fatalf("len=%d want %d", len(data), streamSize)
	}
	if !bytes.Equal(data[:4096], bytes.Repeat([]byte{0x11}, 4096)) {
		t.Fatal("first half not 0x11")
	}
	if !bytes.Equal(data[4096:streamSize], bytes.Repeat([]byte{0x22}, int(streamSize-4096))) {
		t.Fatal("second half not 0x22")
	}
}

// TestHashedTreeChildOID verifies that internal-node values larger
// than 8 bytes (representing a hashed tree's btn_index_node_val: oid +
// 32-byte hash) are accepted by childOIDAt and the leading uint64 is read
// correctly. We set up a 2-level FS-tree whose internal node carries the
// 40-byte values.
func TestHashedTreeChildOID(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 10)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Hashed")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
		{oid: 201, paddr: 7},
	})
	// FS-tree internal root pointing to one leaf via a 40-byte hashed value.
	writeFSTreeInternalHashed(img.blocks[6], []fsHashedEntry{
		{key: jKey(101, jTypeInode), childOID: 201, hash: bytes.Repeat([]byte{0xCD}, 32)},
	})
	writeFSTreeLeafCustom(img.blocks[7], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, 0, 0o100644)},
		{key: drecKey(1, "h"), val: buildDrecValue(101)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := v.FindInode(101); err != nil {
		t.Fatalf("FindInode through hashed internal node: %v", err)
	}
}

// fsHashedEntry is an internal-node entry whose value is a 40-byte
// btn_index_node_val (8-byte child oid followed by a 32-byte hash).
type fsHashedEntry struct {
	key      []byte
	childOID uint64
	hash     []byte
}

// writeFSTreeInternalHashed mirrors writeFSTreeInternal but emits 40-byte
// values to simulate a sealed APFS volume.
func writeFSTreeInternalHashed(block []byte, entries []fsHashedEntry) {
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeFSTree))
	off := objPhysSize
	flags := btnFlagRoot | btnFlagHashed // not leaf — internal hashed
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 1)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	tocLen := uint16(len(entries) * 8)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + int(tocLen)
	endOfData := len(block) - btreeInfoSize

	keyOffs := []uint16{}
	keyLens := []uint16{}
	cur := 0
	for _, e := range entries {
		copy(block[keyArea+cur:], e.key)
		keyOffs = append(keyOffs, uint16(cur))
		keyLens = append(keyLens, uint16(len(e.key)))
		cur += len(e.key)
	}
	valOffs := []uint16{}
	valLens := []uint16{}
	cur = 0
	for _, e := range entries {
		v := make([]byte, 8+len(e.hash))
		binary.LittleEndian.PutUint64(v[:8], e.childOID)
		copy(v[8:], e.hash)
		// kvloc convention: val.off = cumulative INCLUDING this value.
		cur += len(v)
		valOffs = append(valOffs, uint16(cur))
		valLens = append(valLens, uint16(len(v)))
		copy(block[endOfData-cur:], v)
	}
	for i := range entries {
		base := dataStart + i*8
		binary.LittleEndian.PutUint16(block[base:base+2], keyOffs[i])
		binary.LittleEndian.PutUint16(block[base+2:base+4], keyLens[i])
		binary.LittleEndian.PutUint16(block[base+4:base+6], valOffs[i])
		binary.LittleEndian.PutUint16(block[base+6:base+8], valLens[i])
	}
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

// makeDecmpfsInlineZlib builds a com.apple.decmpfs xattr payload of type 3
// (zlib inline) containing zlib-compressed `data`.
func makeDecmpfsInlineZlib(data []byte) []byte {
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	_, _ = w.Write(data)
	_ = w.Close()
	out := make([]byte, 16+compressed.Len())
	binary.LittleEndian.PutUint32(out[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(out[4:8], decmpfsTypeZlibInline)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(data)))
	copy(out[16:], compressed.Bytes())
	return out
}

// makeDecmpfsInlineUncompressed builds a com.apple.decmpfs xattr payload of
// type 1 (uncompressed inline) carrying `data` verbatim.
func makeDecmpfsInlineUncompressed(data []byte) []byte {
	out := make([]byte, 16+len(data))
	binary.LittleEndian.PutUint32(out[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(out[4:8], decmpfsTypeUncompressedInline)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(data)))
	copy(out[16:], data)
	return out
}

// TestReadFileTransparentZlibInline verifies that ReadFileTransparent
// returns the decompressed bytes when a file carries a type-3 decmpfs xattr.
func TestReadFileTransparentZlibInline(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Cmpf")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	plain := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
		"This is a long enough payload to actually compress under zlib.")
	xattr := makeDecmpfsInlineZlib(plain)
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, uint64(len(plain)), 0o100644)},
		{key: drecKey(1, "doc.txt"), val: buildDrecValue(101)},
		{key: xattrKey(101, decmpfsXAttrName), val: xattrEmbeddedValue(xattr)},
	})

	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	got, err := v.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decompressed mismatch:\n got: %q\nwant: %q", got, plain)
	}
}

// TestReadFileTransparentUncompressedInline verifies type 1 (no
// compression, just inline data).
func TestReadFileTransparentUncompressedInline(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Cmpf1")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})

	plain := []byte("short literal payload")
	xattr := makeDecmpfsInlineUncompressed(plain)
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, uint64(len(plain)), 0o100644)},
		{key: drecKey(1, "p"), val: buildDrecValue(101)},
		{key: xattrKey(101, decmpfsXAttrName), val: xattrEmbeddedValue(xattr)},
	})
	r := &memReadAt{buf: img.bytes()}
	c, _ := OpenContainerFromBackend(r)
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, _ := v.FindInode(101)
	got, err := v.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got=%q want=%q", got, plain)
	}
}

// TestDecmpfsUnknownTypeRejected verifies that an unrecognised
// decmpfs compression type identifier surfaces as a clear error. (All
// types 1, 3, 4, 5, 7, 8, 11, 12 are implemented; anything outside that
// set is a structural error in the xattr.)
func TestDecmpfsUnknownTypeRejected(t *testing.T) {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], 99) // unknown
	binary.LittleEndian.PutUint64(hdr[8:16], 0)
	_, err := decompressDecmpfsInline(hdr)
	if err == nil {
		t.Fatal("expected error for unknown decmpfs type")
	}
}

// makeDecmpfsInlineLZFSE builds a com.apple.decmpfs xattr payload of type 11
// (LZFSE inline) carrying lzfse.Compress(data). data must be longer than
// encodeLZVNThreshold (4096) so lzfse.Compress emits LZFSE-V2 blocks rather
// than the LZVN-wrapped form.
func makeDecmpfsInlineLZFSE(t *testing.T, data []byte) []byte {
	t.Helper()
	body, err := lzfse.Compress(data)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	out := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(out[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(out[4:8], decmpfsTypeLZFSEInline)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(data)))
	copy(out[16:], body)
	return out
}

// makeDecmpfsInlineLZVN builds a com.apple.decmpfs xattr payload of type 7
// (LZVN inline). Apple stores raw LZVN payload (no bvxn block wrapper); we
// produce one by calling lzfse.Compress on a small input — which always
// emits a bvxn-wrapped LZVN block — then strip the 12-byte block header
// and the trailing 4-byte bvx$ EOS to recover the raw payload.
func makeDecmpfsInlineLZVN(t *testing.T, data []byte) []byte {
	t.Helper()
	wrapped, err := lzfse.Compress(data)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	if len(wrapped) < 16 {
		t.Fatalf("lzfse.Compress output too short: %d bytes", len(wrapped))
	}
	if got := binary.LittleEndian.Uint32(wrapped[0:4]); got != lzfseMagicLZVNBlock {
		t.Fatalf("expected LZVN block magic 0x%x, got 0x%x", lzfseMagicLZVNBlock, got)
	}
	rawPayload := wrapped[12 : len(wrapped)-4]
	out := make([]byte, 16+len(rawPayload))
	binary.LittleEndian.PutUint32(out[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(out[4:8], decmpfsTypeLZVNInline)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(data)))
	copy(out[16:], rawPayload)
	return out
}

// runDecmpfsRoundTrip wires a synthetic image with a single inode whose
// com.apple.decmpfs xattr is decmpfsXattr, then verifies ReadFileTransparent
// returns plain.
func runDecmpfsRoundTrip(t *testing.T, decmpfsXattr, plain []byte, volName, fname string) {
	t.Helper()
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, volName)
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	writeFSTreeLeafCustom(img.blocks[6], []fsLeafEntry{
		{key: jKey(101, jTypeInode), val: buildInodeValue(1, uint64(len(plain)), 0o100644)},
		{key: drecKey(1, fname), val: buildDrecValue(101)},
		{key: xattrKey(101, decmpfsXAttrName), val: xattrEmbeddedValue(decmpfsXattr)},
	})
	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	ino, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	got, err := v.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decompressed mismatch (len got=%d want=%d)", len(got), len(plain))
	}
}

// TestReadFileTransparentLZVNInline exercises decmpfs type 7. We use
// a small payload (<4096 bytes) so lzfse.Compress emits an LZVN block.
func TestReadFileTransparentLZVNInline(t *testing.T) {
	plain := bytes.Repeat([]byte("LZVN-inline payload sample. "), 80) // ~2240 bytes
	runDecmpfsRoundTrip(t, makeDecmpfsInlineLZVN(t, plain), plain, "LZVNvol", "lzvn.txt")
}

// TestReadFileTransparentLZFSEInline exercises decmpfs type 11. We
// use a 16 KiB payload of mixed content so lzfse.Compress emits LZFSE V2
// blocks (above the 4 KiB LZVN cutoff).
func TestReadFileTransparentLZFSEInline(t *testing.T) {
	plain := make([]byte, 16*1024)
	for i := range plain {
		plain[i] = byte(i*31 + 7)
	}
	runDecmpfsRoundTrip(t, makeDecmpfsInlineLZFSE(t, plain), plain, "LZFSEvol", "lzfse.bin")
}

// TestDecmpfsLZVNPassthrough verifies that the 0xFF "raw passthrough"
// optimisation is honoured for type 7 (Apple writes 0xFF + raw bytes when
// LZVN compression yields no benefit).
func TestDecmpfsLZVNPassthrough(t *testing.T) {
	plain := []byte("incompressible-noise-bytes-go-here")
	body := append([]byte{0xFF}, plain...)
	xattr := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(xattr[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(xattr[4:8], decmpfsTypeLZVNInline)
	binary.LittleEndian.PutUint64(xattr[8:16], uint64(len(plain)))
	copy(xattr[16:], body)
	runDecmpfsRoundTrip(t, xattr, plain, "LZVNraw", "raw.dat")
}
