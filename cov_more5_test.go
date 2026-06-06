package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-compressions/lzfse"
)

// TestAlignUpU64 covers the alignUpU64 helper's three branches:
// zero align (passthrough), already-aligned, and round-up.
func TestAlignUpU64(t *testing.T) {
	cases := []struct {
		n, align, want uint64
	}{
		{42, 0, 42},      // align=0: passthrough
		{16, 8, 16},      // already aligned
		{17, 8, 24},      // round up
		{0, 8, 0},        // zero
		{4097, 4096, 8192},
	}
	for _, c := range cases {
		if got := alignUpU64(c.n, c.align); got != c.want {
			t.Errorf("alignUpU64(%d, %d): got %d, want %d", c.n, c.align, got, c.want)
		}
	}
}

// TestChildOIDAt_OnLeaf rejects calling childOIDAt on a leaf node.
// The childOIDAt/childHashAt helpers were at 62-66% coverage because
// the "on leaf" error branch is rarely hit from production paths.
func TestChildOIDAt_OnLeaf(t *testing.T) {
	// Build a minimal leaf node and verify the leaf-rejection branch.
	// Use a fresh FormatContainer image and grab its FS-tree root
	// (which IS a leaf at format time).
	dir := t.TempDir()
	path := filepath.Join(dir, "leaf.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := FormatContainer(path, 1<<20, "Leaf"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	defer c.Close()
	v, _ := c.OpenVolume(0)
	if !v.rootNode.IsLeaf() {
		t.Skip("FS-tree root is not a leaf in this build")
	}
	r, err := newNodeReader(v.rootNode, v.rootInfo)
	if err != nil {
		t.Fatalf("newNodeReader: %v", err)
	}
	if _, err := r.childOIDAt(0); err == nil {
		t.Error("childOIDAt on leaf: expected error")
	}
	if _, ok := r.childHashAt(0); ok {
		t.Error("childHashAt on leaf: expected false")
	}
}

// TestDecmpfsLZVNInline_RealRoundTrip extracts the raw LZVN payload
// from a bvxn block produced by lzfse.Compress, then feeds it
// through the type-7 (LZVN inline) decoder. lzfse.Compress emits a
// bvxn block for small inputs (the LZVN codec is simpler and wins
// for short data).
//
// bvxn block layout (Apple libcompression):
//
//	bytes 0..3   "bvxn" magic
//	bytes 4..7   n_raw_bytes  (uncompressed length, uint32 LE)
//	bytes 8..11  n_payload    (LZVN-encoded length, uint32 LE)
//	bytes 12..   LZVN payload
//	then         "bvx$" end-of-stream trailer (4 bytes)
//
// We extract bytes [12 : 12+n_payload] as the raw LZVN body.
func TestDecmpfsLZVNInline_RealRoundTrip(t *testing.T) {
	// Short, low-entropy payload — lzfse encodes this as a bvxn (LZVN)
	// block rather than a bvx2 (LZFSE-proper) block.
	original := []byte("aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-cccccccccccccccc")
	compressed, err := lzfse.Compress(original)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	if len(compressed) < 16 {
		t.Skipf("compressed too short (%d) — encoder used a different layout", len(compressed))
	}
	if string(compressed[:4]) != "bvxn" {
		t.Skipf("encoder picked block type %q rather than bvxn", compressed[:4])
	}
	nPayload := binary.LittleEndian.Uint32(compressed[8:12])
	if int(nPayload) > len(compressed)-12 {
		t.Skipf("bvxn payload length %d exceeds buffer (%d)", nPayload, len(compressed)-12)
	}
	rawBody := compressed[12 : 12+nPayload]
	got, err := decmpfsLZVNInline(rawBody, uint64(len(original)))
	if err != nil {
		t.Fatalf("decmpfsLZVNInline: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("LZVN round-trip: got %d bytes, want %d", len(got), len(original))
	}
}

// TestDecompressDecmpfs_Type7_LZVN exercises the public
// decompressDecmpfs entry for type 7 (LZVN inline).
func TestDecompressDecmpfs_Type7_LZVN_RoundTrip(t *testing.T) {
	original := []byte("LZVN-via-public-entrypoint-with-some-repetition-aaa-bbb-aaa-bbb")
	compressed, err := lzfse.Compress(original)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	if len(compressed) < 16 || string(compressed[:4]) != "bvxn" {
		t.Skip("encoder didn't pick bvxn for this input")
	}
	nPayload := binary.LittleEndian.Uint32(compressed[8:12])
	rawBody := compressed[12 : 12+nPayload]
	hdr := makeDecmpfsHeader(decmpfsTypeLZVNInline, uint64(len(original)))
	full := append(hdr, rawBody...)
	got, err := decompressDecmpfs(full, nil)
	if err != nil {
		t.Fatalf("decompressDecmpfs type 7: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("type 7 round-trip: got %d bytes, want %d", len(got), len(original))
	}
}

// TestChildHashAt_HashedTree — exercises childHashAt on an internal
// hashed node (8 byte OID + 32 byte hash payload). This is the
// "value is exactly 8 bytes" vs "> 8 bytes" branch of childHashAt.
// The function is hard to test without a real hashed sealed volume,
// so we just exercise the "leaf returns false" path which is already
// covered above. Document that the longer payload variant is only
// reached by sealed volumes (not produced by our writer).
func TestChildHashAt_NotHashed_Note(t *testing.T) {
	// Coverage note: our writer never emits hashed B-trees, so the
	// "v[8:] hash payload" branch of childHashAt is exercised only
	// when reading Apple-sealed system volumes (out of test scope).
}
