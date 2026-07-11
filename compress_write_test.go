package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// findInodeByID re-opens the container read-only and returns the inode with
// the given oid, failing the test if it is missing.
func findInodeByID(t *testing.T, path string, oid uint64) (*Container, *Volume, Inode) {
	t.Helper()
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("re-OpenContainer: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	inodes, err := v.ListInodes()
	if err != nil {
		c.Close()
		t.Fatalf("ListInodes: %v", err)
	}
	for i := range inodes {
		if inodes[i].ID == oid {
			return c, v, inodes[i]
		}
	}
	c.Close()
	t.Fatalf("inode %d not found", oid)
	return nil, nil, Inode{}
}

// roundTripCompressed formats a container, creates one compressed file with
// the given codec + data, then re-opens it read-only and returns the bytes
// decoded through ReadFileTransparent.
func roundTripCompressed(t *testing.T, codec CompressionCodec, data []byte) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "Cmp"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	oid, err := v.CreateFileCompressedCodec(1, "file.bin", data, codec)
	if err != nil {
		t.Fatalf("CreateFileCompressedCodec: %v", err)
	}
	if err := c.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c.Close()

	c2, v2, ino := findInodeByID(t, path, oid)
	defer c2.Close()
	// The file must carry a decmpfs xattr.
	xs, err := v2.ListXAttrs(ino)
	if err != nil {
		t.Fatalf("ListXAttrs: %v", err)
	}
	if findDecmpfsXAttr(xs) == nil {
		t.Fatalf("created file has no com.apple.decmpfs xattr")
	}
	got, err := v2.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	return got
}

func TestCreateFileCompressed_InlineZlib(t *testing.T) {
	data := bytes.Repeat([]byte("compress me with zlib inline. "), 20) // ~600B, compresses small
	got := roundTripCompressed(t, CompressZlib, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("zlib inline round-trip mismatch: got %d want %d", len(got), len(data))
	}
}

func TestCreateFileCompressed_InlineLZVN(t *testing.T) {
	data := bytes.Repeat([]byte("compress me with lzvn inline. "), 20)
	got := roundTripCompressed(t, CompressLZVN, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("lzvn inline round-trip mismatch")
	}
}

func TestCreateFileCompressed_InlineAuto(t *testing.T) {
	data := bytes.Repeat([]byte("auto codec picks the smaller body. "), 30)
	got := roundTripCompressed(t, CompressAuto, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("auto inline round-trip mismatch")
	}
}

func TestCreateFileCompressed_InlinePassthrough(t *testing.T) {
	// Incompressible small data: neither codec shrinks it, so the 0xFF raw
	// passthrough is used. Random-ish bytes.
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte((i*2654435761 + 1013904223) >> 13)
	}
	got := roundTripCompressed(t, CompressAuto, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("passthrough inline round-trip mismatch")
	}
}

func TestCreateFileCompressed_ResourceForkLZVN(t *testing.T) {
	// A file whose whole-file compressed body exceeds the inline budget →
	// resource-fork path with a stream xattr. Multi-chunk (> 64 KiB) too.
	var buf bytes.Buffer
	for i := 0; buf.Len() < 200*1024; i++ {
		buf.WriteString("resource fork chunked lzfse content line ")
		buf.WriteByte(byte('0' + i%10))
		buf.WriteByte('\n')
	}
	data := buf.Bytes()
	got := roundTripCompressed(t, CompressLZVN, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("rsrc lzvn round-trip mismatch: got %d want %d", len(got), len(data))
	}
}

func TestCreateFileCompressed_ResourceForkEmbedded(t *testing.T) {
	// Force the resource-fork path on a small input by lowering the inline
	// budget; the small resource fork is stored as an embedded xattr.
	defer func(old int) { maxInlineDecmpfsWrite = old }(maxInlineDecmpfsWrite)
	maxInlineDecmpfsWrite = 8
	data := bytes.Repeat([]byte("tiny rsrc embedded. "), 10)
	got := roundTripCompressed(t, CompressLZVN, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("embedded rsrc round-trip mismatch")
	}
}

func TestCreateFileCompressed_ResourceForkPassthroughChunk(t *testing.T) {
	// Incompressible data larger than one chunk forces per-chunk 0xFF
	// passthrough inside the resource fork.
	data := make([]byte, 130*1024)
	x := uint32(2463534242)
	for i := range data {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		data[i] = byte(x)
	}
	got := roundTripCompressed(t, CompressLZVN, data)
	if !bytes.Equal(got, data) {
		t.Fatalf("rsrc passthrough round-trip mismatch: got %d want %d", len(got), len(data))
	}
}

func TestCreateFileCompressed_MultiLevelTree(t *testing.T) {
	// Populate enough files to promote the FS-tree past a single leaf, then
	// create a compressed file so the multi-level insertion path runs.
	path := filepath.Join(t.TempDir(), "ml.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "ML"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	for i := 0; i < 200; i++ {
		name := "pad_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('0'+i%10))
		if _, err := v.CreateFile(1, name, []byte("padding")); err != nil {
			t.Fatalf("CreateFile pad %d: %v", i, err)
		}
	}
	data := bytes.Repeat([]byte("multi-level compressed payload. "), 25)
	oid, err := v.CreateFileCompressedCodec(1, "compressed.bin", data, CompressAuto)
	if err != nil {
		t.Fatalf("CreateFileCompressedCodec: %v", err)
	}
	if err := c.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c.Close()

	c2, v2, ino := findInodeByID(t, path, oid)
	defer c2.Close()
	got, err := v2.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("multi-level compressed round-trip mismatch")
	}
}

func TestCreateFileCompressed_ErrorBranches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "err.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := FormatContainer(path, 1<<22, "Err"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	// Read-only container rejects the write.
	roc, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	rov, err := roc.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := rov.CreateFileCompressed(1, "x", []byte("data")); err != ErrReadOnly {
		t.Fatalf("read-only: got %v want ErrReadOnly", err)
	}
	roc.Close()

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := v.CreateFileCompressed(1, "", []byte("d")); err == nil {
		t.Fatalf("empty name: expected error")
	}
	if _, err := v.CreateFileCompressed(1, "x", nil); err == nil {
		t.Fatalf("empty data: expected error")
	}
	if _, err := v.CreateFileCompressedCodec(1, "x", []byte("d"), CompressionCodec(99)); err == nil {
		t.Fatalf("bad codec: expected error")
	}
}

func TestBuildDecmpfsRepresentation_UnknownCodec(t *testing.T) {
	if _, err := buildDecmpfsRepresentation([]byte("data"), CompressionCodec(42)); err == nil {
		t.Fatalf("expected error for unknown codec")
	}
}

// TestReaderAppleOffsetTable_RoundTrip round-trips a resource fork we built
// (type 12, Apple byte-0 offset table) back through the reader, and also
// exercises the reader's error branches on that layout.
func TestReaderAppleOffsetTable_RoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("apple offset table lzfse round trip. "), 4000) // multi-chunk
	rsrc := buildLZVNRsrcFork(data)
	out, err := decmpfsResourceForkOffsetTable(rsrc, decmpfsTypeLZVNResource, uint64(len(data)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("apple offset-table round-trip mismatch: got %d want %d", len(out), len(data))
	}

	// Truncated table.
	if _, err := decmpfsResourceForkOffsetTable(rsrc[:4], decmpfsTypeLZVNResource, uint64(len(data))); err == nil {
		t.Fatalf("expected error on truncated fork")
	}
	// Bad table start (not a multiple of 4).
	bad := append([]byte(nil), rsrc...)
	bad[0] = 0x03
	if _, err := decmpfsResourceForkOffsetTable(bad, decmpfsTypeLZVNResource, uint64(len(data))); err == nil {
		t.Fatalf("expected error on bad table start")
	}
}

func TestReaderAppleOffsetTable_GoldenDitto(t *testing.T) {
	rsrc, err := os.ReadFile("testdata/golden_big_rsrc.bin")
	if err != nil {
		t.Skipf("golden fixture missing: %v", err)
	}
	out, err := decmpfsResourceForkOffsetTable(rsrc, decmpfsTypeLZVNResource, 200000)
	if err != nil {
		t.Fatalf("decode real ditto type-8 fork: %v", err)
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{'A'}, 200000)) {
		t.Fatalf("golden ditto decode mismatch (len=%d)", len(out))
	}
}

func TestCreateFileCompressed_SnapshotGuardAndView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "Snap"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if _, err := v.CreateSnapshot("s1"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// Snapshot guard: writes are refused while a snapshot exists.
	if _, err := v.CreateFileCompressed(2, "x.bin", bytes.Repeat([]byte("guarded "), 30)); err == nil {
		t.Fatalf("CreateFileCompressed after snapshot: expected guard error")
	}
	// Snapshot view (xidLimit != ∞) is read-only. A view volume shares the
	// same container (and its lock) but carries a bounded xidLimit.
	sv := *v
	sv.xidLimit = 1
	if _, err := sv.CreateFileCompressed(2, "y.bin", bytes.Repeat([]byte("view "), 30)); err == nil {
		t.Fatalf("CreateFileCompressed on snapshot view: expected error")
	}
}

func TestBuildLZVNRsrcFork_Empty(t *testing.T) {
	// Defensive numChunks==0 -> 1 branch: an empty input still yields a
	// well-formed single-chunk fork the reader decodes to empty.
	fork := buildLZVNRsrcFork(nil)
	out, err := decmpfsResourceForkOffsetTable(fork, decmpfsTypeLZVNResource, 0)
	if err != nil {
		t.Fatalf("decode empty fork: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty fork decoded to %d bytes, want 0", len(out))
	}
}

func TestReaderAppleOffsetTable_BlockRangeErrors(t *testing.T) {
	data := bytes.Repeat([]byte("range error probe. "), 5000) // multi-chunk
	fork := buildLZVNRsrcFork(data)
	// Corrupt the second offset-table entry to point backwards (offEnd<offStart
	// for block 0 / non-contiguous start for block 1).
	bad := append([]byte(nil), fork...)
	binary.LittleEndian.PutUint32(bad[4:8], 0) // offsets[1] = 0 < offsets[0]
	if _, err := decmpfsResourceForkOffsetTable(bad, decmpfsTypeLZVNResource, uint64(len(data))); err == nil {
		t.Fatalf("expected block-range error")
	}
	// Point the final offset (total length) past the fork so a chunk end
	// exceeds the fork length.
	bad2 := append([]byte(nil), fork...)
	last := int(binary.LittleEndian.Uint32(bad2[0:4])/4) - 1
	binary.LittleEndian.PutUint32(bad2[last*4:last*4+4], uint32(len(fork)+4096))
	if _, err := decmpfsResourceForkOffsetTable(bad2, decmpfsTypeLZVNResource, uint64(len(data))); err == nil {
		t.Fatalf("expected out-of-range block end error")
	}
}

func TestCreateFileCompressed_LeafSplit(t *testing.T) {
	// A compressed file whose large (near-max) embedded decmpfs xattr
	// overflows the single root leaf must drive the leaf-split branch of
	// insertNewInodeRecordsLocked. Incompressible ~3 KiB data stays inline
	// via 0xFF passthrough, producing a ~3 KiB decmpfs xattr.
	path := filepath.Join(t.TempDir(), "split.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "Split"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	incompressible := make([]byte, 3000)
	x := uint32(0x12345)
	for i := range incompressible {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		incompressible[i] = byte(x)
	}
	var oid uint64
	for i := 0; i < 3; i++ {
		o, err := v.CreateFileCompressedCodec(1, "big"+string(rune('a'+i))+".bin", incompressible, CompressZlib)
		if err != nil {
			t.Fatalf("CreateFileCompressedCodec %d: %v", i, err)
		}
		oid = o
	}
	if err := c.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c.Close()
	c2, v2, ino := findInodeByID(t, path, oid)
	defer c2.Close()
	got, err := v2.ReadFileTransparent(ino)
	if err != nil {
		t.Fatalf("ReadFileTransparent: %v", err)
	}
	if !bytes.Equal(got, incompressible) {
		t.Fatalf("leaf-split compressed round-trip mismatch")
	}
}
