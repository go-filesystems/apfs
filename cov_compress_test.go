package filesystem_apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"github.com/go-compressions/lzfse"
)

// makeDecmpfsHeader builds the 16-byte decmpfs xattr header.
func makeDecmpfsHeader(compType uint32, decompressedSize uint64) []byte {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], compType)
	binary.LittleEndian.PutUint64(hdr[8:16], decompressedSize)
	return hdr
}

func TestReadDecmpfsHeader_TooShort(t *testing.T) {
	if _, err := readDecmpfsHeader([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestReadDecmpfsHeader_BadMagic(t *testing.T) {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xDEADBEEF) // wrong magic
	if _, err := readDecmpfsHeader(hdr); err == nil {
		t.Fatal("expected error on bad magic")
	}
}

func TestDecompressDecmpfs_UnknownType(t *testing.T) {
	hdr := makeDecmpfsHeader(99, 0) // 99 not a valid type
	if _, err := decompressDecmpfs(hdr, nil); err == nil {
		t.Fatal("expected error on unknown compression type")
	}
}

func TestDecompressDecmpfs_Type1_UncompressedInline(t *testing.T) {
	const body = "type-1-inline-uncompressed"
	hdr := makeDecmpfsHeader(decmpfsTypeUncompressedInline, uint64(len(body)))
	full := append(hdr, []byte(body)...)
	got, err := decompressDecmpfs(full, nil)
	if err != nil {
		t.Fatalf("type 1: %v", err)
	}
	if string(got) != body {
		t.Errorf("type 1: got %q, want %q", got, body)
	}
}

func TestDecompressDecmpfs_Type1_With0xFFPrefix(t *testing.T) {
	const body = "with-0xff-prefix"
	hdr := makeDecmpfsHeader(decmpfsTypeUncompressedInline, uint64(len(body)))
	full := append(hdr, 0xFF)
	full = append(full, []byte(body)...)
	got, err := decompressDecmpfs(full, nil)
	if err != nil {
		t.Fatalf("type 1 with 0xFF: %v", err)
	}
	if string(got) != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestDecompressDecmpfs_Type3_Zlib(t *testing.T) {
	const body = "real-zlib-payload-here"
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	zw.Close()
	hdr := makeDecmpfsHeader(decmpfsTypeZlibInline, uint64(len(body)))
	full := append(hdr, buf.Bytes()...)
	got, err := decompressDecmpfs(full, nil)
	if err != nil {
		t.Fatalf("type 3: %v", err)
	}
	if string(got) != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

// Resource-fork types reject when rsrcFork is nil.
func TestDecompressDecmpfs_ResourceTypes_NoRsrcFork(t *testing.T) {
	for _, typ := range []uint32{
		decmpfsTypeZlibResource,
		decmpfsTypeRawResource,
		decmpfsTypeLZVNResource,
		decmpfsTypeLZFSEResource,
	} {
		hdr := makeDecmpfsHeader(typ, 100)
		if _, err := decompressDecmpfs(hdr, nil); err == nil {
			t.Errorf("type %d with nil rsrcFork: expected error", typ)
		}
	}
}

func TestDecompressDecmpfsInline_Wrapper(t *testing.T) {
	// Wrapper just calls decompressDecmpfs(payload, nil). Pass a
	// resource-type header → it must error (no rsrc fork available).
	hdr := makeDecmpfsHeader(decmpfsTypeZlibResource, 100)
	if _, err := decompressDecmpfsInline(hdr); err == nil {
		t.Fatal("decompressDecmpfsInline rsrc-type: expected error")
	}
	// Inline-type passes through.
	hdr2 := makeDecmpfsHeader(decmpfsTypeUncompressedInline, 0)
	if _, err := decompressDecmpfsInline(hdr2); err != nil {
		t.Errorf("decompressDecmpfsInline empty: %v", err)
	}
}

// TestDecmpfsLZFSEInline_RealRoundTrip uses our own pkg/go-compressions/lzfse
// `Compress` to produce a valid bvxn block stream, feeds it through the
// type-11 (LZFSE inline) decoder, and verifies a byte-for-byte
// round-trip.
func TestDecmpfsLZFSEInline_RealRoundTrip(t *testing.T) {
	// Make the payload long enough that the LZFSE encoder emits a
	// real compressed block (not just the uncompressed-passthrough
	// fallback).
	original := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 64)
	compressed, err := lzfse.Compress(original)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("lzfse.Compress: returned empty bytes")
	}
	got, err := decmpfsLZFSEInline(compressed, uint64(len(original)))
	if err != nil {
		t.Fatalf("decmpfsLZFSEInline: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(original))
	}
}

// TestDecompressDecmpfs_Type11_LZFSE_RoundTrip plumbs LZFSE through
// the public decompressDecmpfs entry point.
func TestDecompressDecmpfs_Type11_LZFSE_RoundTrip(t *testing.T) {
	original := bytes.Repeat([]byte("LZFSE-via-public-entrypoint "), 100)
	compressed, err := lzfse.Compress(original)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	hdr := makeDecmpfsHeader(decmpfsTypeLZFSEInline, uint64(len(original)))
	full := append(hdr, compressed...)
	got, err := decompressDecmpfs(full, nil)
	if err != nil {
		t.Fatalf("decompressDecmpfs type 11: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(original))
	}
}
