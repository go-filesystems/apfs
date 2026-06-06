package filesystem_apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"github.com/go-compressions/lzfse"
)

// buildResourceForkChunked assembles a synthetic com.apple.ResourceFork xattr
// payload containing chunks compatible with decmpfsResourceFork. Each chunk
// is encoded with chunkEncode (which receives one logical chunk of plain
// bytes and returns its on-disk bytes).
//
// Layout produced (matches the canonical Apple decmpfs rsrc format):
//
//	+0x000  uint32 BE 0x00000100         (data_offset)
//	+0x004  uint32 BE map_offset (= 0x100 + dataLen, just past data)
//	+0x008  uint32 BE data_size
//	+0x00c  uint32 BE map_size  (= 0)
//	+0x010  240 bytes zero (reserved)
//	+0x100  uint32 BE 0x00000100         (compression header_size)
//	+0x104  uint32 BE total_size         (= dataLen-16)
//	+0x108  uint32 BE data_size
//	+0x10c  uint32 BE 0x00000032         (flags)
//	+0x110  uint32 LE numBlocks
//	+0x114  numBlocks * { uint32 LE offset (rel. to 0x104), uint32 LE length }
//	+...    chunk payloads
func buildResourceForkChunked(plain []byte, chunkSize int, chunkEncode func([]byte) []byte) []byte {
	// Split plaintext into N chunks of at most chunkSize bytes.
	var chunks [][]byte
	for i := 0; i < len(plain); i += chunkSize {
		end := i + chunkSize
		if end > len(plain) {
			end = len(plain)
		}
		chunks = append(chunks, chunkEncode(plain[i:end]))
	}
	if len(chunks) == 0 {
		chunks = [][]byte{chunkEncode(nil)}
	}
	numBlocks := len(chunks)

	descBase := hfsRsrcHeaderSize + 0x14
	descBytes := numBlocks * 8
	chunksStart := descBase + descBytes
	// chunk descriptors: offsets are relative to position 0x104 (data_offset+4).
	descRefBase := hfsRsrcHeaderSize + 4
	type rec struct{ off, length uint32 }
	descs := make([]rec, numBlocks)
	cur := chunksStart
	for i, c := range chunks {
		descs[i] = rec{off: uint32(cur - descRefBase), length: uint32(len(c))}
		cur += len(c)
	}
	totalDataLen := cur - hfsRsrcHeaderSize
	mapOff := hfsRsrcHeaderSize + totalDataLen

	out := make([]byte, mapOff)
	// HFS resource fork header
	binary.BigEndian.PutUint32(out[0:4], uint32(hfsRsrcHeaderSize))
	binary.BigEndian.PutUint32(out[4:8], uint32(mapOff))
	binary.BigEndian.PutUint32(out[8:12], uint32(totalDataLen))
	binary.BigEndian.PutUint32(out[12:16], 0) // map_size
	// Compression header
	binary.BigEndian.PutUint32(out[hfsRsrcHeaderSize+0:hfsRsrcHeaderSize+4], uint32(hfsRsrcHeaderSize))
	binary.BigEndian.PutUint32(out[hfsRsrcHeaderSize+4:hfsRsrcHeaderSize+8], uint32(totalDataLen-16))
	binary.BigEndian.PutUint32(out[hfsRsrcHeaderSize+8:hfsRsrcHeaderSize+12], uint32(len(plain)))
	binary.BigEndian.PutUint32(out[hfsRsrcHeaderSize+12:hfsRsrcHeaderSize+16], 0x32)
	binary.LittleEndian.PutUint32(out[hfsRsrcHeaderSize+0x10:hfsRsrcHeaderSize+0x14], uint32(numBlocks))
	// Descriptor array
	for i, d := range descs {
		base := descBase + i*8
		binary.LittleEndian.PutUint32(out[base:base+4], d.off)
		binary.LittleEndian.PutUint32(out[base+4:base+8], d.length)
	}
	// Chunk payloads
	cur = chunksStart
	for _, c := range chunks {
		copy(out[cur:cur+len(c)], c)
		cur += len(c)
	}
	return out
}

// runDecmpfsRsrcRoundTrip wires a synthetic image with a single inode
// carrying both com.apple.decmpfs and an embedded com.apple.ResourceFork
// xattr; verifies ReadFileTransparent returns plain.
func runDecmpfsRsrcRoundTrip(t *testing.T, decmpfsXattr, rsrc []byte, plain []byte, volName, fname string) {
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
		{key: xattrKey(101, resourceForkXAttrName), val: xattrEmbeddedValue(rsrc)},
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
		t.Fatalf("decompressed mismatch (got=%d bytes, want=%d)", len(got), len(plain))
	}
}

// makeDecmpfsRsrcZlibChunkSize is like makeDecmpfsRsrcZlib but takes an
// explicit chunk size so synthetic tests can produce multi-chunk forks
// without ballooning the embedded xattr beyond what fits in a 4 KiB block.
// The parser doesn't enforce Apple's 64 KiB chunk size — it reads whatever
// the descriptor table says — so a smaller chunk size still exercises the
// multi-chunk path faithfully.
func makeDecmpfsRsrcZlibChunkSize(plain []byte, chunkSize int) ([]byte, []byte) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeZlibResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkChunked(plain, chunkSize, func(chunk []byte) []byte {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		_, _ = w.Write(chunk)
		_ = w.Close()
		return buf.Bytes()
	})
	return header, rsrc
}

// TestReadFileTransparentZlibResource exercises decmpfs type 4 with a
// payload that spans 4 chunks of 256 bytes each (small enough to keep the
// synthetic xattr embedded within a single FS-tree leaf, large enough to
// exercise the multi-chunk decompression path).
func TestReadFileTransparentZlibResource(t *testing.T) {
	plain := bytes.Repeat([]byte("apfs zlib resource fork chunk content. "), 30) // ~1170 bytes
	header, rsrc := makeDecmpfsRsrcZlibChunkSize(plain, 256)
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "ZlibRsrc", "big.txt")
}

// TestReadFileTransparentRawResource exercises decmpfs type 5 — a
// chunked resource fork in which each chunk is stored verbatim. Uses two
// 256-byte chunks to exercise the multi-block path of the parser.
func TestReadFileTransparentRawResource(t *testing.T) {
	plain := make([]byte, 600)
	for i := range plain {
		plain[i] = byte(i*37 + 11)
	}
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeRawResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkChunked(plain, 256, func(chunk []byte) []byte {
		return append([]byte(nil), chunk...)
	})
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "RawRsrc", "raw.bin")
}

// buildResourceForkOffsetTable assembles a synthetic com.apple.ResourceFork
// xattr value whose data fork uses the offset-table layout consumed by
// decmpfsResourceForkOffsetTable (types 8 and 12). Each chunk is encoded
// with chunkEncode so the helper is reusable across LZVN, LZFSE, and
// passthrough variants.
//
// Layout produced:
//
//	+0x000  256-byte HFS+ resource fork header (data_offset=0x100)
//	+0x100  uint32 LE  num_chunks (N)
//	+0x104  (N+1) * uint32 LE  offsets, relative to position 0x100,
//	                           where chunk[i] occupies [offsets[i], offsets[i+1])
//	+...    chunk payloads
func buildResourceForkOffsetTable(plain []byte, chunkSize int, chunkEncode func([]byte) []byte) []byte {
	var chunks [][]byte
	for i := 0; i < len(plain); i += chunkSize {
		end := i + chunkSize
		if end > len(plain) {
			end = len(plain)
		}
		chunks = append(chunks, chunkEncode(plain[i:end]))
	}
	if len(chunks) == 0 {
		chunks = [][]byte{chunkEncode(nil)}
	}
	numBlocks := len(chunks)

	tableStart := 4
	tableLen := (numBlocks + 1) * 4
	chunkBase := tableStart + tableLen
	offsets := make([]uint32, numBlocks+1)
	cur := chunkBase
	for i, c := range chunks {
		offsets[i] = uint32(cur)
		cur += len(c)
	}
	offsets[numBlocks] = uint32(cur)
	totalDataLen := cur

	out := make([]byte, hfsRsrcHeaderSize+totalDataLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(hfsRsrcHeaderSize))
	binary.BigEndian.PutUint32(out[4:8], uint32(hfsRsrcHeaderSize+totalDataLen))
	binary.BigEndian.PutUint32(out[8:12], uint32(totalDataLen))
	binary.BigEndian.PutUint32(out[12:16], 0)

	binary.LittleEndian.PutUint32(out[hfsRsrcHeaderSize:hfsRsrcHeaderSize+4], uint32(numBlocks))
	for i, off := range offsets {
		base := hfsRsrcHeaderSize + tableStart + i*4
		binary.LittleEndian.PutUint32(out[base:base+4], off)
	}
	cur = hfsRsrcHeaderSize + chunkBase
	for _, c := range chunks {
		copy(out[cur:cur+len(c)], c)
		cur += len(c)
	}
	return out
}

// TestReadFileTransparentLZVNResource exercises decmpfs type 8 with a
// payload split across two chunks. Each chunk holds the raw LZVN payload
// produced by lzfse.Compress (with its bvxn/bvx$ envelope stripped, the
// same trick used by the inline test).
func TestReadFileTransparentLZVNResource(t *testing.T) {
	plain := bytes.Repeat([]byte("LZVN-rsrc-content="), 100) // ~1800 bytes
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeLZVNResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkOffsetTable(plain, 900, func(chunk []byte) []byte {
		wrapped, err := lzfse.Compress(chunk)
		if err != nil {
			t.Fatalf("lzfse.Compress: %v", err)
		}
		if len(wrapped) < 16 {
			t.Fatalf("compressed chunk too short")
		}
		// Strip the 12-byte bvxn header and the 4-byte bvx$ trailer to
		// recover the raw LZVN payload Apple stores per chunk.
		return wrapped[12 : len(wrapped)-4]
	})
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "LZVNRsrc", "lzvn-rsrc.bin")
}

// TestReadFileTransparentLZFSEResource exercises decmpfs type 12 with
// chunks that each carry a complete LZFSE block stream produced by
// lzfse.Compress (no header stripping needed).
func TestReadFileTransparentLZFSEResource(t *testing.T) {
	plain := make([]byte, 12*1024)
	for i := range plain {
		plain[i] = byte(i*53 + 19)
	}
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeLZFSEResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkOffsetTable(plain, 6*1024, func(chunk []byte) []byte {
		out, err := lzfse.Compress(chunk)
		if err != nil {
			t.Fatalf("lzfse.Compress: %v", err)
		}
		return out
	})
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "LZFSERsrc", "lzfse-rsrc.bin")
}

// TestReadFileTransparentLZVNRsrcPassthrough verifies that a per-chunk
// 0xFF passthrough is honoured for type 8 (and by extension the offset-table
// dispatcher).
func TestReadFileTransparentLZVNRsrcPassthrough(t *testing.T) {
	plain := []byte("identity-passthrough-payload-for-LZVN-rsrc")
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeLZVNResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkOffsetTable(plain, 200, func(chunk []byte) []byte {
		return append([]byte{0xFF}, chunk...)
	})
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "LZVNRsrcPT", "lzvn-pt.dat")
}

// TestReadFileTransparentZlibRsrcPassthrough verifies the per-chunk
// 0xFF "raw passthrough" optimisation inside a type-4 resource fork.
func TestReadFileTransparentZlibRsrcPassthrough(t *testing.T) {
	plain := bytes.Repeat([]byte{0xC3}, 512)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(header[4:8], decmpfsTypeZlibResource)
	binary.LittleEndian.PutUint64(header[8:16], uint64(len(plain)))
	rsrc := buildResourceForkChunked(plain, 256, func(chunk []byte) []byte {
		return append([]byte{0xFF}, chunk...) // passthrough marker
	})
	runDecmpfsRsrcRoundTrip(t, header, rsrc, plain, "ZlibRsrcPT", "pt.dat")
}
