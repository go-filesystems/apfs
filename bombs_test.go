package filesystem_apfs

// bombs_test.go — memory-bomb regression tests. Each road below is a few bytes
// of hostile metadata (an inode size, an extent length, a decmpfs header) that
// used to reserve far more than the image holds; each test asserts
// runtime.MemStats.TotalAlloc grows by a small budget while the road is refused.
// "Before" figures were measured on v0.4.1 (lzfse v0.5.0).

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	"github.com/go-compressions/lzfse"
	"github.com/go-volumes/safeio"
)

func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

const miB = 1 << 20

// bareReader hides everything but ReadAt, so the container cannot tell the size
// of its backing store.
type bareReader struct{ r *bytes.Reader }

func (b bareReader) ReadAt(p []byte, off int64) (int, error) { return b.r.ReadAt(p, off) }

// bareVolume is a Volume over r whose superblock claims blockCount blocks of
// 4 KiB: the claim is what the old ceiling was made of.
func bareVolume(r containerReader, blockCount uint64) *Volume {
	return &Volume{c: &Container{r: r, sb: &nxSuperblockNative{blockSize: 4096, blockCount: blockCount}}}
}

func noMoreThan(t *testing.T, what string, budget uint64, f func()) {
	t.Helper()
	if n := allocated(f); n >= budget {
		t.Errorf("%s allocated %d bytes, want < %d", what, n, budget)
	}
}

// ───────────────────────────── ReadFile ────────────────────────────────

// An inode declaring 1 GiB with no extents is "honoured with zeros", and the
// ceiling was blockCount*blockSize from the superblock: a claim of 2^40 blocks
// made 4 PiB the limit, so a 1 GiB sparse file allocated 1 GiB (measured) from a
// 1 MiB image. The zeros an image does not back are capped at maxZeroFill.
func TestBombReadFileSparseClaim(t *testing.T) {
	img := bytes.NewReader(make([]byte, miB))
	v := bareVolume(img, 1<<40)
	noMoreThan(t, "1 GiB + 1 declared size, no extents", miB, func() {
		_, err := v.ReadFile(Inode{Size: uint64(maxZeroFill) + 1})
		if !errors.Is(err, safeio.ErrTooLarge) {
			t.Errorf("err = %v, want safeio.ErrTooLarge", err)
		}
	})
}

// Exactness of the zero budget: lowered to 8 KiB for the test, a file of that
// size reads, one byte more is refused, and holes are charged the same way.
func TestZeroFillBudgetIsExact(t *testing.T) {
	old := maxZeroFill
	maxZeroFill = 8192
	t.Cleanup(func() { maxZeroFill = old })

	v := bareVolume(bytes.NewReader(make([]byte, 64*1024)), 16)
	if b, err := v.ReadFile(Inode{Size: 8192}); err != nil || len(b) != 8192 {
		t.Fatalf("size == budget: len %d, err %v", len(b), err)
	}
	if _, err := v.ReadFile(Inode{Size: 8193}); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("size == budget+1: err = %v, want ErrTooLarge", err)
	}
	// A hole of 8 KiB before a 4 KiB extent at block 1: 8192 zeros + 4096 data.
	ext := containerExtent{logicalOffset: 8192, length: 4096, physBlock: 1}
	if b, err := v.ReadFile(Inode{Size: 12288, dataExtents: []containerExtent{ext}}); err != nil || len(b) != 12288 {
		t.Fatalf("hole == budget: len %d, err %v", len(b), err)
	}
	ext.logicalOffset = 8193
	if _, err := v.ReadFile(Inode{Size: 12289, dataExtents: []containerExtent{ext}}); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("hole == budget+1: err = %v, want ErrTooLarge", err)
	}
}

// The extent record's length is a claim: 2 GiB over a 1 MiB image allocated
// 2 GiB (measured) before the read failed. With the image size known the extent
// must lie inside it; with the size unknown the buffer grows with the bytes
// that arrive.
func TestBombReadFileExtentClaim(t *testing.T) {
	huge := containerExtent{logicalOffset: 0, length: 2 << 30, physBlock: 0}
	in := Inode{Size: 2 << 30, dataExtents: []containerExtent{huge}}

	known := bareVolume(bytes.NewReader(make([]byte, miB)), 1<<40)
	noMoreThan(t, "2 GiB extent, size known", miB, func() {
		if _, err := known.ReadFile(in); !errors.Is(err, safeio.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})

	unknown := bareVolume(bareReader{bytes.NewReader(make([]byte, miB))}, 1<<40)
	noMoreThan(t, "2 GiB extent, size unknown", 8*miB, func() {
		if _, err := unknown.ReadFile(in); err == nil {
			t.Error("accepted a 2 GiB extent over a 1 MiB image")
		}
	})
}

// Extents may alias one physical run, so each can fit the container while the
// file does not: four 1 MiB extents all at block 0 of a 1 MiB image.
func TestBombReadFileAliasedExtents(t *testing.T) {
	img := make([]byte, miB)
	for i := range img {
		img[i] = byte(i)
	}
	v := bareVolume(bytes.NewReader(img), 256)
	one := []containerExtent{{logicalOffset: 0, length: miB, physBlock: 0}}
	b, err := v.ReadFile(Inode{Size: miB, dataExtents: one})
	if err != nil || !bytes.Equal(b, img) {
		t.Fatalf("one extent of exactly the image: len %d, err %v", len(b), err)
	}
	four := make([]containerExtent, 4)
	for i := range four {
		four[i] = containerExtent{logicalOffset: uint64(i) * miB, length: miB, physBlock: 0}
	}
	noMoreThan(t, "four aliased 1 MiB extents", 2*miB+miB/2, func() {
		if _, err := v.ReadFile(Inode{Size: 4 * miB, dataExtents: four}); !errors.Is(err, safeio.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
}

// A real file's bytes still come out right across the 1 MiB growth steps of the
// unknown-size path.
func TestUnknownSizeReadIsExact(t *testing.T) {
	img := make([]byte, 3*miB+4096)
	for i := range img {
		img[i] = byte(i * 31)
	}
	ext := []containerExtent{{logicalOffset: 0, length: uint64(len(img)), physBlock: 0}}
	for name, r := range map[string]containerReader{"known": bytes.NewReader(img), "unknown": bareReader{bytes.NewReader(img)}} {
		v := bareVolume(r, uint64(len(img)/4096))
		b, err := v.ReadFile(Inode{Size: uint64(len(img)), dataExtents: ext})
		if err != nil || !bytes.Equal(b, img) {
			t.Errorf("%s: len %d, err %v", name, len(b), err)
		}
	}
}

// ───────────────────────────── decmpfs ─────────────────────────────────

func zlibOf(n int) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(make([]byte, n))
	w.Close()
	return b.Bytes()
}

// The zlib inline decoder was bounded by the global 1 GiB cap, not by the
// declared size: a header declaring 100 bytes over a stream inflating to 64 MiB
// allocated 64 MiB+ (measured) and truncated afterwards. The ceiling is the
// declared size plus one chunk of slack. Exact: +64 KiB passes (and truncates),
// one byte more is refused.
func TestBombDecmpfsZlibCeiling(t *testing.T) {
	const declared = 100
	hdr := makeDecmpfsHeader(decmpfsTypeZlibInline, declared)

	bomb := append(append([]byte(nil), hdr...), zlibOf(64*miB)...)
	noMoreThan(t, "64 MiB zlib stream under a 100-byte header", 2*miB, func() {
		if _, err := decompressDecmpfs(bomb, nil); !errors.Is(err, safeio.ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
	out, err := decompressDecmpfs(append(append([]byte(nil), hdr...), zlibOf(declared+rsrcMaxChunkSize)...), nil)
	if err != nil || len(out) != declared {
		t.Errorf("declared+64 KiB: len %d, err %v", len(out), err)
	}
	if _, err := decompressDecmpfs(append(append([]byte(nil), hdr...), zlibOf(declared+rsrcMaxChunkSize+1)...), nil); !errors.Is(err, safeio.ErrTooLarge) {
		t.Errorf("declared+64 KiB+1: err = %v, want ErrTooLarge", err)
	}
}

// An LZVN block declaring 1 GiB over a 17-byte payload allocated 1 GiB with
// lzfse v0.5.0; v0.6.0 refuses it from the payload size (LZVN yields at most
// 136 bytes per payload byte), and the apfs ceiling now follows the header.
func TestBombDecmpfsLZVNInline(t *testing.T) {
	hdr := makeDecmpfsHeader(decmpfsTypeLZVNInline, 1<<30)
	body := make([]byte, 17)
	noMoreThan(t, "LZVN inline, 1 GiB declared, 17-byte payload", miB, func() {
		if _, err := decompressDecmpfs(append(append([]byte(nil), hdr...), body...), nil); err == nil {
			t.Error("accepted a 17-byte LZVN payload declaring 1 GiB")
		}
	})
}

// uncompressedBlock is an LZFSE stream holding n raw bytes ("bvx-" + "bvx$").
func uncompressedBlock(n int) []byte {
	b := make([]byte, 8, 8+n+4)
	binary.LittleEndian.PutUint32(b[0:], 0x2d787662)
	binary.LittleEndian.PutUint32(b[4:], uint32(n))
	b = append(b, make([]byte, n)...)
	return binary.LittleEndian.AppendUint32(b, 0x24787662)
}

func TestLZFSEFixtureDecodes(t *testing.T) {
	if out, err := lzfse.Decompress(uncompressedBlock(1000)); err != nil || len(out) != 1000 {
		t.Fatalf("fixture: len %d, err %v", len(out), err)
	}
}

// Type 12 chunks decode to at most rsrcMaxChunkSize (the LZVN case already
// declared it); the LZFSE case used the 1 GiB default. Exact at 64 KiB.
func TestDecmpfsLZFSEChunkCeiling(t *testing.T) {
	if out, err := decmpfsDecodeRsrcOffsetChunk(uncompressedBlock(rsrcMaxChunkSize), decmpfsTypeLZFSEResource); err != nil || len(out) != rsrcMaxChunkSize {
		t.Errorf("chunk of exactly 64 KiB: len %d, err %v", len(out), err)
	}
	if _, err := decmpfsDecodeRsrcOffsetChunk(uncompressedBlock(rsrcMaxChunkSize+1), decmpfsTypeLZFSEResource); !errors.Is(err, safeio.ErrTooLarge) {
		t.Errorf("chunk of 64 KiB + 1: err = %v, want ErrTooLarge", err)
	}
}

// appleOffsetTable lays out the type 8/12 resource fork the Apple way: (N+1)
// LE offsets from byte 0, then the chunks. Every chunk here is a 0xFF raw
// passthrough so no codec is involved.
func appleOffsetTable(chunks ...[]byte) []byte {
	n := len(chunks)
	off := uint32(4 * (n + 1))
	hdr := binary.LittleEndian.AppendUint32(nil, off)
	var body []byte
	for _, c := range chunks {
		raw := append([]byte{0xFF}, c...)
		body = append(body, raw...)
		off += uint32(len(raw))
		hdr = binary.LittleEndian.AppendUint32(hdr, off)
	}
	return append(hdr, body...)
}

// make([]byte, 0, expectedSize) reserved the header's whole claim: 1 GiB
// declared over a three-chunk fork allocated 1 073 741 824 bytes (measured). The
// capacity is now at most what the chunks can produce, and the loop stops once
// the declared size is reached.
func TestBombDecmpfsRsrcCapacity(t *testing.T) {
	rsrc := appleOffsetTable([]byte("aaaa"), []byte("bbbb"), []byte("cc"))
	noMoreThan(t, "1 GiB declared over 3 chunks", miB, func() {
		out, err := decmpfsResourceForkOffsetTable(rsrc, decmpfsTypeLZVNResource, 1<<30)
		if err != nil || string(out) != "aaaabbbbcc" {
			t.Errorf("out %q, err %v", out, err)
		}
	})
	// Truncation at the declared size is unchanged, and later chunks are not
	// decoded once it is reached.
	out, err := decmpfsResourceForkOffsetTable(rsrc, decmpfsTypeLZVNResource, 6)
	if err != nil || string(out) != "aaaabb" {
		t.Errorf("declared 6: %q, %v", out, err)
	}
}

// A u32 block count off the disk: numBlocks*8 and (numBlocks+1)*4 wrap an int on
// a 32-bit target before they are compared with the fork's length.
func TestDecmpfsRsrcHugeBlockCount(t *testing.T) {
	rsrc := make([]byte, hfsRsrcHeaderSize+0x20)
	binary.BigEndian.PutUint32(rsrc[0:], hfsRsrcHeaderSize)
	binary.LittleEndian.PutUint32(rsrc[hfsRsrcHeaderSize+0x10:], 0x7FFFFFFF)
	if _, err := decmpfsResourceFork(rsrc, decmpfsTypeRawResource, 100); err == nil {
		t.Error("type 4/5 fork with 2^31-1 blocks accepted")
	}
	binary.LittleEndian.PutUint32(rsrc[hfsRsrcHeaderSize:], 0x40000000)
	if _, err := decmpfsResourceForkOffsetTable0x100(rsrc, decmpfsTypeLZVNResource, 100); err == nil {
		t.Error("0x100-layout fork with 2^30 blocks accepted")
	}
}

// FuzzDecmpfsBombs drives the whole decmpfs decoder with an arbitrary header
// body and resource fork. Properties: no panic, and no call allocates more than
// a fixed budget plus a multiple of its input (zlib inflates ~1000:1, LZVN
// 136:1).
func FuzzDecmpfsBombs(f *testing.F) {
	for _, ct := range []uint32{decmpfsTypeZlibInline, decmpfsTypeLZVNInline, decmpfsTypeLZFSEInline,
		decmpfsTypeZlibResource, decmpfsTypeRawResource, decmpfsTypeLZVNResource, decmpfsTypeLZFSEResource} {
		f.Add(ct, uint64(1<<30), make([]byte, 17), appleOffsetTable([]byte("abc")))
		f.Add(ct, uint64(100), zlibOf(1<<20), []byte{})
	}
	f.Add(decmpfsTypeLZFSEInline, uint64(70000), uncompressedBlock(70000), []byte{})
	f.Fuzz(func(t *testing.T, ct uint32, declared uint64, body, rsrc []byte) {
		payload := append(makeDecmpfsHeader(ct, declared), body...)
		n := allocated(func() { _, _ = decompressDecmpfs(payload, rsrc) })
		if limit := uint64(64*miB) + 2048*uint64(len(payload)+len(rsrc)); n > limit {
			t.Fatalf("type %d declared %d: %d bytes allocated for %d+%d input bytes", ct, declared, n, len(payload), len(rsrc))
		}
	})
}
