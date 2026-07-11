package filesystem_apfs

// native_compress.go decodes Apple's transparent file compression
// (com.apple.decmpfs xattr). When a regular file carries a `com.apple.decmpfs`
// xattr the file's logical content is no longer in J_FILE_EXTENT records but
// in the xattr payload (small files, "inline" compression types) or in the
// resource fork xattr (`com.apple.ResourceFork`, large files / "rsrc"
// compression types).
//
// Implemented (read path — decompressDecmpfs / ReadFileTransparent):
//   - Type 1:  uncompressed inline (data verbatim after the 16-byte header)
//   - Type 3:  zlib inline (data zlib-compressed after the header, with the
//              Apple "raw passthrough" 0xFF prefix optimisation honoured)
//   - Type 4:  zlib in resource fork (per-chunk zlib + offset table at
//              hfsRsrcHeaderSize, see decmpfsResourceFork)
//   - Type 5:  raw in resource fork (per-chunk verbatim + offset table)
//   - Type 7:  LZVN inline (raw LZVN payload, decoded via go-compressions/lzfse)
//   - Type 8:  LZVN in resource fork (chunked LZVN with the LZVN-specific
//              offset table, decoded via decmpfsResourceForkOffsetTable)
//   - Type 11: LZFSE inline (LZFSE block stream, decoded via go-compressions/lzfse)
//   - Type 12: LZFSE in resource fork (chunked LZFSE blocks, same offset
//              table shape as type 8)
//
// Resource-fork variants require the caller (or ReadFileTransparent) to
// also fetch the file's com.apple.ResourceFork xattr — embedded or via
// the xattr stream. The full chain runs in ReadFileTransparent.
//
// Compress-on-write is implemented in compress_write.go
// (CreateFileCompressed): it produces the com.apple.decmpfs xattr and, for
// large files, the chunked com.apple.ResourceFork payload at write time.
// The write path emits only formats that are byte-exact interoperable with
// apfs.kext — inline zlib (type 3), inline LZVN (type 7) and chunked LZVN
// resource forks (type 8) — verified end-to-end via `fsck_apfs` + a kext
// mount read-back (TestCompatNative_KextReadsOurCompressedFiles).
//
// Not yet implemented:
//   - LZFSE (bvx2) compress-on-write: the read path decodes types 11/12,
//     but the bvx2 block format is not reliably round-trippable through
//     Apple's decoder, so the write path uses LZVN instead.
//   - Any decmpfs type beyond 12 (Apple has not published one as of
//     macOS 14; reserve the default-case error for that future).

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-compressions/lzfse"
	"github.com/go-volumes/safeio"
)

// maxDecmpfsSize caps the decompressed size of a transparently-compressed
// file. The decmpfs header's uncompressedSize is an attacker-controlled
// uint64 that drives buffer pre-allocation and decoder output; a value such
// as 2^60 would OOM the host. Real transparently-compressed files are well
// under this 1 GiB ceiling. Anything larger is rejected as a decompression
// bomb. (Finding C2.)
const maxDecmpfsSize = 1 << 30

// checkDecmpfsSize rejects an uncompressedSize that exceeds maxDecmpfsSize so
// no decoder pre-allocates or decompresses past the cap. Returns the value as
// an int64 ceiling for safeio helpers.
func checkDecmpfsSize(uncompressedSize uint64) (int64, error) {
	if uncompressedSize > maxDecmpfsSize {
		return 0, fmt.Errorf("apfs: decmpfs: uncompressed size %d exceeds cap %d: %w",
			uncompressedSize, maxDecmpfsSize, safeio.ErrTooLarge)
	}
	return int64(uncompressedSize), nil
}

// limitedDecompress reads the whole of zr but errors if the decoder produces
// more than hardCap bytes, defeating a zip-bomb whose declared
// uncompressedSize is small but whose stream expands without bound. hardCap
// is the absolute safety ceiling (e.g. maxDecmpfsSize or a per-chunk
// maximum), NOT the file's declared size: a legitimate stream may inflate to
// slightly more than its declared size and is later truncated by the caller.
// The +1 lets us detect "more than the cap" rather than silently truncating.
func limitedDecompress(zr io.Reader, hardCap int64) ([]byte, error) {
	lr := io.LimitReader(zr, hardCap+1)
	out, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > hardCap {
		return nil, fmt.Errorf("apfs: decmpfs: decompressed stream exceeds cap %d: %w",
			hardCap, safeio.ErrTooLarge)
	}
	return out, nil
}

// magic identifiers for the lzfse block stream wrapper. We construct one
// for the LZVN inline case so we can route the raw payload through the
// shared lzfse.Decompress entry point without exporting new helpers from
// the lzfse package.
const (
	lzfseMagicLZVNBlock     uint32 = 0x6e787662 // "bvxn"
	lzfseMagicEndOfStreamLE uint32 = 0x24787662 // "bvx$"
)

// decmpfsXAttrName is the well-known xattr name carrying the decmpfs header
// and (for inline compression) the compressed payload itself.
const decmpfsXAttrName = "com.apple.decmpfs"

// decmpfsMagic is "cmpf" stored little-endian as 0x636d7066.
const decmpfsMagic uint32 = 0x636d7066

// Compression type identifiers stored in the decmpfs header.
const (
	decmpfsTypeUncompressedInline uint32 = 1
	decmpfsTypeZlibInline         uint32 = 3
	decmpfsTypeZlibResource       uint32 = 4
	decmpfsTypeRawResource        uint32 = 5
	decmpfsTypeLZVNInline         uint32 = 7
	decmpfsTypeLZVNResource       uint32 = 8
	decmpfsTypeLZFSEInline        uint32 = 11
	decmpfsTypeLZFSEResource      uint32 = 12
)

// decmpfsHeader is the 16-byte structure that prefixes every decmpfs xattr.
type decmpfsHeader struct {
	magic            uint32
	compressionType  uint32
	uncompressedSize uint64
}

// readDecmpfsHeader decodes the 16-byte decmpfs header from buf.
func readDecmpfsHeader(buf []byte) (*decmpfsHeader, error) {
	if len(buf) < 16 {
		return nil, fmt.Errorf("apfs: decmpfs: header too short (%d)", len(buf))
	}
	h := &decmpfsHeader{
		magic:            binary.LittleEndian.Uint32(buf[0:4]),
		compressionType:  binary.LittleEndian.Uint32(buf[4:8]),
		uncompressedSize: binary.LittleEndian.Uint64(buf[8:16]),
	}
	if h.magic != decmpfsMagic {
		return nil, fmt.Errorf("apfs: decmpfs: bad magic 0x%08x (want 0x%08x)", h.magic, decmpfsMagic)
	}
	return h, nil
}

// decompressDecmpfsInline decodes an inline-compressed payload (the decmpfs
// xattr value, header + compressed data). Resource-fork variants (types 4,
// 5, 8, 12) return ErrUnsupported when called via this entry point;
// callers that have access to the file's com.apple.ResourceFork should use
// decompressDecmpfs instead.
func decompressDecmpfsInline(xattrPayload []byte) ([]byte, error) {
	return decompressDecmpfs(xattrPayload, nil)
}

// decompressDecmpfs decodes a com.apple.decmpfs xattr payload. For inline
// compression types only xattrPayload is consulted. For resource-fork types
// rsrcFork must carry the verbatim contents of the file's
// com.apple.ResourceFork xattr (256-byte HFS rsrc header + data fork).
func decompressDecmpfs(xattrPayload, rsrcFork []byte) ([]byte, error) {
	h, err := readDecmpfsHeader(xattrPayload)
	if err != nil {
		return nil, err
	}
	// Reject a decompression-bomb size before any decoder pre-allocates or
	// runs. (C2.)
	if _, err := checkDecmpfsSize(h.uncompressedSize); err != nil {
		return nil, err
	}
	body := xattrPayload[16:]
	switch h.compressionType {
	case decmpfsTypeUncompressedInline:
		// Body is the verbatim file content; the leading 0xFF marker that
		// some implementations write is not part of the spec for type 1
		// but is observed in the wild — strip it if present.
		if len(body) > 0 && body[0] == 0xFF {
			body = body[1:]
		}
		if uint64(len(body)) > h.uncompressedSize {
			body = body[:h.uncompressedSize]
		}
		return append([]byte(nil), body...), nil
	case decmpfsTypeZlibInline:
		return decmpfsZlibInline(body, h.uncompressedSize)
	case decmpfsTypeLZVNInline:
		return decmpfsLZVNInline(body, h.uncompressedSize)
	case decmpfsTypeLZFSEInline:
		return decmpfsLZFSEInline(body, h.uncompressedSize)
	case decmpfsTypeZlibResource:
		if rsrcFork == nil {
			return nil, fmt.Errorf("apfs: decmpfs: type 4 needs com.apple.ResourceFork (not provided)")
		}
		return decmpfsResourceFork(rsrcFork, decmpfsTypeZlibResource, h.uncompressedSize)
	case decmpfsTypeRawResource:
		if rsrcFork == nil {
			return nil, fmt.Errorf("apfs: decmpfs: type 5 needs com.apple.ResourceFork (not provided)")
		}
		return decmpfsResourceFork(rsrcFork, decmpfsTypeRawResource, h.uncompressedSize)
	case decmpfsTypeLZVNResource:
		if rsrcFork == nil {
			return nil, fmt.Errorf("apfs: decmpfs: type 8 needs com.apple.ResourceFork (not provided)")
		}
		return decmpfsResourceForkOffsetTable(rsrcFork, decmpfsTypeLZVNResource, h.uncompressedSize)
	case decmpfsTypeLZFSEResource:
		if rsrcFork == nil {
			return nil, fmt.Errorf("apfs: decmpfs: type 12 needs com.apple.ResourceFork (not provided)")
		}
		return decmpfsResourceForkOffsetTable(rsrcFork, decmpfsTypeLZFSEResource, h.uncompressedSize)
	default:
		return nil, fmt.Errorf("apfs: decmpfs: unknown compression type %d", h.compressionType)
	}
}

// decmpfsZlibInline decodes the body of a type-3 (zlib inline) decmpfs xattr.
// Apple stores either a real zlib stream or, when the data did not benefit
// from compression, the raw bytes prefixed with 0xFF. This helper handles
// both cases.
func decmpfsZlibInline(body []byte, expectedSize uint64) ([]byte, error) {
	if len(body) == 0 {
		if expectedSize != 0 {
			return nil, fmt.Errorf("apfs: decmpfs: empty zlib body but expected %d bytes", expectedSize)
		}
		return []byte{}, nil
	}
	if body[0] == 0xFF {
		// "Not actually compressed" passthrough.
		raw := body[1:]
		if uint64(len(raw)) > expectedSize {
			raw = raw[:expectedSize]
		}
		return append([]byte(nil), raw...), nil
	}
	if _, err := checkDecmpfsSize(expectedSize); err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("apfs: decmpfs: zlib reader: %w", err)
	}
	defer zr.Close()
	// Bound the inflate at the absolute decmpfs ceiling so a bomb can't OOM;
	// a legitimate over-inflate is truncated to expectedSize below.
	out, err := limitedDecompress(zr, maxDecmpfsSize)
	if err != nil {
		return nil, fmt.Errorf("apfs: decmpfs: zlib decode: %w", err)
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// decmpfsLZVNInline decodes the body of a type-7 (LZVN inline) decmpfs
// xattr. Apple stores either an Apple "raw passthrough" prefixed by 0xFF or
// the raw LZVN payload (no bvxn block wrapper). To reuse the shared
// lzfse.Decompress entry point we synthesise a minimal bvxn block + bvx$
// trailer around the raw payload.
func decmpfsLZVNInline(body []byte, expectedSize uint64) ([]byte, error) {
	if len(body) == 0 {
		if expectedSize != 0 {
			return nil, fmt.Errorf("apfs: decmpfs: empty LZVN body but expected %d bytes", expectedSize)
		}
		return []byte{}, nil
	}
	if body[0] == 0xFF {
		raw := body[1:]
		if uint64(len(raw)) > expectedSize {
			raw = raw[:expectedSize]
		}
		return append([]byte(nil), raw...), nil
	}
	wrapped := make([]byte, 0, 12+len(body)+4)
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[0:4], lzfseMagicLZVNBlock)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(expectedSize))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(body)))
	wrapped = append(wrapped, hdr...)
	wrapped = append(wrapped, body...)
	eos := make([]byte, 4)
	binary.LittleEndian.PutUint32(eos, lzfseMagicEndOfStreamLE)
	wrapped = append(wrapped, eos...)
	out, err := lzfse.Decompress(wrapped)
	if err != nil {
		return nil, fmt.Errorf("apfs: decmpfs: LZVN decode: %w", err)
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// decmpfsLZFSEInline decodes the body of a type-11 (LZFSE inline) decmpfs
// xattr. The body is already a complete LZFSE block stream (a sequence of
// bvxn / bvx1 / bvx2 / bvx- blocks terminated by bvx$), so we hand it
// directly to lzfse.Decompress.
func decmpfsLZFSEInline(body []byte, expectedSize uint64) ([]byte, error) {
	if len(body) == 0 {
		if expectedSize != 0 {
			return nil, fmt.Errorf("apfs: decmpfs: empty LZFSE body but expected %d bytes", expectedSize)
		}
		return []byte{}, nil
	}
	if body[0] == 0xFF {
		raw := body[1:]
		if uint64(len(raw)) > expectedSize {
			raw = raw[:expectedSize]
		}
		return append([]byte(nil), raw...), nil
	}
	out, err := lzfse.Decompress(body)
	if err != nil {
		return nil, fmt.Errorf("apfs: decmpfs: LZFSE decode: %w", err)
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// resourceForkXAttrName is the well-known xattr that stores the chunked
// compressed payload for resource-fork decmpfs types (4, 5, 8, 12).
const resourceForkXAttrName = "com.apple.ResourceFork"

// hfsRsrcHeaderSize is the size of the HFS+ resource fork header that
// always precedes the data fork.
const hfsRsrcHeaderSize = 0x100

// rsrcMaxChunkSize is the maximum uncompressed size of a single chunk in
// Apple's compressed resource fork format. Chunks at the end of the file
// may be smaller.
const rsrcMaxChunkSize = 0x10000

// decmpfsResourceFork decompresses a resource-fork-style decmpfs payload.
// rsrc is the verbatim contents of the file's com.apple.ResourceFork
// xattr (a 256-byte HFS+ resource fork header followed by the compression
// "data fork"). cmpType selects the per-chunk decoder (decmpfsTypeZlibResource
// or decmpfsTypeRawResource).
//
// Layout consumed (canonical from afsctool / xnu):
//
//	+0x000  uint32 BE data_offset       (= 0x100)
//	+0x004  uint32 BE map_offset
//	+0x008  uint32 BE data_size
//	+0x00c  uint32 BE map_size
//	+0x010  240 bytes reserved / stub map
//	+0x100  compression header (16 bytes BE)
//	+0x110  uint32 LE num_blocks
//	+0x114  num_blocks * { uint32 LE offset, uint32 LE length }
//	+...    chunk data
//
// Block descriptor offsets are relative to position 0x104 (the start of
// the compression header's total_size word, i.e., 4 bytes inside the
// compression header). This is the convention followed by Apple's xnu
// decmpfs and by afsctool.
func decmpfsResourceFork(rsrc []byte, cmpType uint32, expectedSize uint64) ([]byte, error) {
	if _, err := checkDecmpfsSize(expectedSize); err != nil {
		return nil, err
	}
	if len(rsrc) < hfsRsrcHeaderSize+20 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc: payload too short (%d)", len(rsrc))
	}
	dataOffset := int(binary.BigEndian.Uint32(rsrc[0:4]))
	if dataOffset != hfsRsrcHeaderSize {
		return nil, fmt.Errorf("apfs: decmpfs rsrc: unexpected data_offset 0x%x (want 0x%x)", dataOffset, hfsRsrcHeaderSize)
	}
	if dataOffset+20 > len(rsrc) {
		return nil, fmt.Errorf("apfs: decmpfs rsrc: data fork truncated")
	}
	// Compression header is 16 bytes BE; we only need num_blocks at +0x10
	// and the descriptor array that follows.
	descBase := dataOffset + 0x14 // start of (offset,length) descriptor array
	numBlocks := int(binary.LittleEndian.Uint32(rsrc[dataOffset+0x10 : dataOffset+0x14]))
	if numBlocks <= 0 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc: zero block count")
	}
	if descBase+numBlocks*8 > len(rsrc) {
		return nil, fmt.Errorf("apfs: decmpfs rsrc: descriptor array truncated (need %d blocks)", numBlocks)
	}
	// Block descriptor offsets are relative to dataOffset+4 (= start of
	// the total_size word within the compression header).
	descRefBase := dataOffset + 4
	out := make([]byte, 0, expectedSize)
	for i := 0; i < numBlocks; i++ {
		descOff := descBase + i*8
		off := int(binary.LittleEndian.Uint32(rsrc[descOff : descOff+4]))
		length := int(binary.LittleEndian.Uint32(rsrc[descOff+4 : descOff+8]))
		chunkStart := descRefBase + off
		chunkEnd := chunkStart + length
		if chunkStart < 0 || chunkEnd > len(rsrc) || chunkStart > chunkEnd {
			return nil, fmt.Errorf("apfs: decmpfs rsrc: block %d range [%d, %d) out of fork length %d", i, chunkStart, chunkEnd, len(rsrc))
		}
		chunk := rsrc[chunkStart:chunkEnd]
		decoded, err := decmpfsDecodeRsrcChunk(chunk, cmpType)
		if err != nil {
			return nil, fmt.Errorf("apfs: decmpfs rsrc: block %d: %w", i, err)
		}
		out = append(out, decoded...)
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// decmpfsResourceForkOffsetTable decompresses a type 8 (LZVN rsrc) or type
// 12 (LZFSE rsrc) resource fork. Two on-disk layouts are seen in the wild
// and both are accepted here:
//
//   - Apple's real format, as emitted by `ditto --hfsCompression`,
//     `AppleFSCompression` and the diskimages framework: NO 256-byte HFS
//     resource-fork header. The offset table sits at byte 0 as (N+1)
//     little-endian uint32 offsets measured from byte 0; offset[0] equals
//     4*(N+1) (the start of the chunk data) and offset[N] equals the total
//     resource length. This is the layout the macOS kext writes and reads.
//     Handled by decmpfsResourceForkAppleOffsetTable.
//
//   - The legacy 0x100-header layout (256-byte HFS resource-fork header
//     with data_offset = 0x100, then num_chunks + offset table relative to
//     0x100). Handled by decmpfsResourceForkOffsetTable0x100.
//
// The layout is selected by inspecting the first four bytes: a big-endian
// 0x100 there is the HFS resource-fork header of the legacy layout;
// anything else is treated as the Apple byte-0 offset table.
//
// For type 8 each chunk is the raw LZVN payload (no bvxn block wrapper);
// the decoder synthesises a bvxn envelope so it can route the payload
// through lzfse.Decompress. For type 12 each chunk is a complete LZFSE
// block stream (bvxn / bvx1 / bvx2 blocks terminated by bvx$); chunks are
// passed straight through. Both types honour the per-chunk Apple "raw
// passthrough" 0xFF prefix.
func decmpfsResourceForkOffsetTable(rsrc []byte, cmpType uint32, expectedSize uint64) ([]byte, error) {
	if _, err := checkDecmpfsSize(expectedSize); err != nil {
		return nil, err
	}
	if len(rsrc) < 8 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): payload too short (%d)", len(rsrc))
	}
	if binary.BigEndian.Uint32(rsrc[0:4]) != hfsRsrcHeaderSize {
		return decmpfsResourceForkAppleOffsetTable(rsrc, cmpType, expectedSize)
	}
	return decmpfsResourceForkOffsetTable0x100(rsrc, cmpType, expectedSize)
}

// decmpfsResourceForkAppleOffsetTable decodes the real Apple offset-table
// layout described above: (N+1) LE uint32 offsets from byte 0, offset[0]
// == 4*(N+1). This is what `ditto --hfsCompression` produces.
func decmpfsResourceForkAppleOffsetTable(rsrc []byte, cmpType uint32, expectedSize uint64) ([]byte, error) {
	first := binary.LittleEndian.Uint32(rsrc[0:4])
	if first < 8 || first%4 != 0 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): bad table start 0x%x", first)
	}
	tableEnd := int(first)
	numBlocks := int(first/4) - 1
	if numBlocks <= 0 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): zero block count")
	}
	if tableEnd > len(rsrc) {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): offset table truncated (need %d bytes, have %d)", tableEnd, len(rsrc))
	}
	out := make([]byte, 0, expectedSize)
	prev := tableEnd
	for i := 0; i < numBlocks; i++ {
		offStart := int(binary.LittleEndian.Uint32(rsrc[i*4 : i*4+4]))
		offEnd := int(binary.LittleEndian.Uint32(rsrc[(i+1)*4 : (i+1)*4+4]))
		if offStart != prev {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): block %d start %d != expected %d", i, offStart, prev)
		}
		if offEnd < offStart || offEnd > len(rsrc) {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): block %d range [%d,%d) out of fork length %d", i, offStart, offEnd, len(rsrc))
		}
		decoded, err := decmpfsDecodeRsrcOffsetChunk(rsrc[offStart:offEnd], cmpType)
		if err != nil {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(apple): block %d: %w", i, err)
		}
		out = append(out, decoded...)
		prev = offEnd
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// decmpfsResourceForkOffsetTable0x100 decodes the legacy 0x100-header
// offset-table layout (256-byte HFS resource-fork header, num_chunks +
// offset table relative to 0x100).
func decmpfsResourceForkOffsetTable0x100(rsrc []byte, cmpType uint32, expectedSize uint64) ([]byte, error) {
	if len(rsrc) < hfsRsrcHeaderSize+4 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): payload too short (%d)", len(rsrc))
	}
	dataOffset := int(binary.BigEndian.Uint32(rsrc[0:4]))
	if dataOffset != hfsRsrcHeaderSize {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): unexpected data_offset 0x%x", dataOffset)
	}
	numBlocks := int(binary.LittleEndian.Uint32(rsrc[dataOffset : dataOffset+4]))
	if numBlocks <= 0 {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): zero block count")
	}
	tableStart := dataOffset + 4
	tableEnd := tableStart + (numBlocks+1)*4
	if tableEnd > len(rsrc) {
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): offset table truncated (need %d entries)", numBlocks+1)
	}
	chunkPerSize := uint64(0)
	if expectedSize > 0 {
		chunkPerSize = (expectedSize + uint64(numBlocks) - 1) / uint64(numBlocks)
		_ = chunkPerSize // kept for future per-chunk size sanity checks
	}
	out := make([]byte, 0, expectedSize)
	for i := 0; i < numBlocks; i++ {
		startEntry := tableStart + i*4
		endEntry := startEntry + 4
		offStart := int(binary.LittleEndian.Uint32(rsrc[startEntry:endEntry]))
		offEnd := int(binary.LittleEndian.Uint32(rsrc[endEntry : endEntry+4]))
		if offEnd < offStart {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): block %d has end<start (%d<%d)", i, offEnd, offStart)
		}
		chunkStart := dataOffset + offStart
		chunkEnd := dataOffset + offEnd
		if chunkStart < tableEnd || chunkEnd > len(rsrc) {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): block %d range [%d,%d) out of fork length %d", i, chunkStart, chunkEnd, len(rsrc))
		}
		chunk := rsrc[chunkStart:chunkEnd]
		decoded, err := decmpfsDecodeRsrcOffsetChunk(chunk, cmpType)
		if err != nil {
			return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): block %d: %w", i, err)
		}
		out = append(out, decoded...)
	}
	if expectedSize > 0 && uint64(len(out)) > expectedSize {
		out = out[:expectedSize]
	}
	return out, nil
}

// decmpfsDecodeRsrcOffsetChunk decodes a single chunk of an offset-table
// resource fork (types 8 and 12). The 0xFF passthrough prefix is honoured
// for both codecs.
func decmpfsDecodeRsrcOffsetChunk(chunk []byte, cmpType uint32) ([]byte, error) {
	if len(chunk) == 0 {
		return nil, nil
	}
	if chunk[0] == 0xFF {
		raw := chunk[1:]
		if len(raw) > rsrcMaxChunkSize {
			raw = raw[:rsrcMaxChunkSize]
		}
		return append([]byte(nil), raw...), nil
	}
	switch cmpType {
	case decmpfsTypeLZVNResource:
		// Wrap the raw LZVN payload as a bvxn block + bvx$ trailer so we
		// can reuse lzfse.Decompress (the package's decoder dispatches on
		// block magic).
		nRaw := uint32(rsrcMaxChunkSize)
		nPayload := uint32(len(chunk))
		wrapped := make([]byte, 0, 12+len(chunk)+4)
		hdr := make([]byte, 12)
		binary.LittleEndian.PutUint32(hdr[0:4], lzfseMagicLZVNBlock)
		binary.LittleEndian.PutUint32(hdr[4:8], nRaw)
		binary.LittleEndian.PutUint32(hdr[8:12], nPayload)
		wrapped = append(wrapped, hdr...)
		wrapped = append(wrapped, chunk...)
		eos := make([]byte, 4)
		binary.LittleEndian.PutUint32(eos, lzfseMagicEndOfStreamLE)
		wrapped = append(wrapped, eos...)
		out, err := lzfse.Decompress(wrapped)
		if err != nil {
			return nil, fmt.Errorf("LZVN decode: %w", err)
		}
		return out, nil
	case decmpfsTypeLZFSEResource:
		out, err := lzfse.Decompress(chunk)
		if err != nil {
			return nil, fmt.Errorf("LZFSE decode: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("apfs: decmpfs rsrc(offset): unsupported codec for type %d", cmpType)
	}
}

// decmpfsDecodeRsrcChunk decodes a single resource-fork chunk. zlib chunks
// honour the Apple "raw passthrough" 0xFF prefix optimisation; raw chunks
// have no header and are returned verbatim (truncated to rsrcMaxChunkSize).
func decmpfsDecodeRsrcChunk(chunk []byte, cmpType uint32) ([]byte, error) {
	switch cmpType {
	case decmpfsTypeRawResource:
		if len(chunk) > rsrcMaxChunkSize {
			chunk = chunk[:rsrcMaxChunkSize]
		}
		return append([]byte(nil), chunk...), nil
	case decmpfsTypeZlibResource:
		if len(chunk) == 0 {
			return nil, nil
		}
		if chunk[0] == 0xFF {
			raw := chunk[1:]
			if len(raw) > rsrcMaxChunkSize {
				raw = raw[:rsrcMaxChunkSize]
			}
			return append([]byte(nil), raw...), nil
		}
		zr, err := zlib.NewReader(bytes.NewReader(chunk))
		if err != nil {
			return nil, fmt.Errorf("zlib reader: %w", err)
		}
		defer zr.Close()
		// A single decmpfs chunk decompresses to at most rsrcMaxChunkSize
		// (0x10000) bytes; bound the decode so a malicious chunk can't
		// expand without limit. (C2.)
		buf, err := limitedDecompress(zr, rsrcMaxChunkSize)
		if err != nil {
			return nil, fmt.Errorf("zlib decode: %w", err)
		}
		return buf, nil
	default:
		return nil, fmt.Errorf("apfs: decmpfs rsrc: unsupported chunk codec for type %d", cmpType)
	}
}

// findDecmpfsXAttr looks up the com.apple.decmpfs xattr in xs and returns
// its raw payload (header + compressed data), or (nil, nil) if absent.
func findDecmpfsXAttr(xs []XAttr) []byte {
	for _, x := range xs {
		if x.Name == decmpfsXAttrName {
			return x.EmbeddedValue
		}
	}
	return nil
}

// ReadFileTransparent reads a regular file and decompresses it on the fly
// when the file carries a com.apple.decmpfs xattr (transparent file
// compression). For uncompressed files it falls back to ReadFile.
//
// Supported decmpfs types:
//
//	inline  — 1 (uncompressed), 3 (zlib), 7 (LZVN), 11 (LZFSE)
//	rsrc-fork — 4 (zlib), 5 (raw), 8 (LZVN), 12 (LZFSE)
//
// Resource-fork variants automatically fetch the file's
// com.apple.ResourceFork xattr (embedded or stream).
func (v *Volume) ReadFileTransparent(inode Inode) ([]byte, error) {
	if inode.IsDir {
		return nil, fmt.Errorf("apfs: ReadFileTransparent on directory %q", inode.Name)
	}
	xs, err := v.ListXAttrs(inode)
	if err != nil {
		return nil, err
	}
	payload := findDecmpfsXAttr(xs)
	if payload == nil {
		return v.ReadFile(inode)
	}
	rsrc, rerr := v.fetchResourceFork(xs)
	if rerr != nil {
		return nil, rerr
	}
	return decompressDecmpfs(payload, rsrc)
}

// fetchResourceFork returns the contents of the com.apple.ResourceFork xattr
// for the inode whose xattrs are xs. Embedded payloads are returned
// directly; stream payloads are pulled in via ReadXAttrStream. Returns
// (nil, nil) when no ResourceFork xattr exists — that is a valid state for
// inline decmpfs types.
func (v *Volume) fetchResourceFork(xs []XAttr) ([]byte, error) {
	for _, x := range xs {
		if x.Name != resourceForkXAttrName {
			continue
		}
		if x.Flags&xattrFlagDataStream != 0 {
			return v.ReadXAttrStream(x)
		}
		return append([]byte(nil), x.EmbeddedValue...), nil
	}
	return nil, nil
}
