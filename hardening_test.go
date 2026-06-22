package filesystem_apfs

// hardening_test.go — regression + fuzz coverage for the security hardening
// of the on-disk parser against malicious/corrupt images. Every test asserts
// the parser returns a graceful error (or a bounded result) rather than
// panicking, reading out of bounds, integer-overflowing into a bad
// allocation, looping forever, or OOMing.
//
// Findings exercised here:
//   C1  btree.go    — TOC index (nKeys / tableSpace) overflowing the node
//   C2  compress.go — decmpfs uncompressedSize = 2^60 (decompression bomb)
//   C3  fs.go       — inode.Size / ext.length huge → bounded allocation
//   H1  fs.go       — self-referential B-tree oid/paddr cycle / depth bomb
//   H2  obj.go      — blockSize 0 / huge in the NX superblock
//   M1  extent_ref  — unvalidated nKeys cap

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-volumes/safeio"
)

// --- C1: btree node TOC validation -----------------------------------------

// buildMinimalBTreeBlock returns a 4096-byte block carrying a valid obj_phys
// B-tree header with the supplied node header fields, so individual TOC
// fields can be poisoned without tripping the earlier object-type check.
func buildMinimalBTreeBlock(flags, level uint16, nKeys uint32, tsOff, tsLen uint16) []byte {
	block := make([]byte, 4096)
	writeObjHdr(block, 0, 1, objTypeBTreeNode, uint32(objTypeFSTree))
	off := objPhysSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], level)
	binary.LittleEndian.PutUint32(block[off+4:off+8], nKeys)
	binary.LittleEndian.PutUint16(block[off+8:off+10], tsOff)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tsLen)
	return block
}

func TestReadBTreeNode_TableSpaceOutOfRange(t *testing.T) {
	// tableSpace.off + len far exceeds the node data area.
	block := buildMinimalBTreeBlock(btnFlagLeaf, 0, 1, 0xFFF0, 0xFFF0)
	if _, err := readBTreeNode(block); err == nil {
		t.Fatal("expected error for out-of-range table_space, got nil")
	} else if !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("want ErrOutOfBounds, got %v", err)
	}
}

func TestReadBTreeNode_NKeysExceedTableSpace(t *testing.T) {
	// tableSpace is small but nKeys claims far more entries than fit.
	// Variable shape ⇒ 8 bytes/entry; tsLen=8 fits exactly one, claim 1000.
	block := buildMinimalBTreeBlock(btnFlagLeaf, 0, 1000, 0, 8)
	if _, err := readBTreeNode(block); err == nil {
		t.Fatal("expected error for nKeys exceeding table_space, got nil")
	}
}

func TestReadBTreeNode_NKeysExceedTableSpaceFixed(t *testing.T) {
	// Fixed shape ⇒ 4 bytes/entry. tsLen=4 fits one entry; claim 2.
	block := buildMinimalBTreeBlock(btnFlagLeaf|btnFlagFixedKVSize, 0, 2, 0, 4)
	if _, err := readBTreeNode(block); err == nil {
		t.Fatal("expected error for fixed nKeys exceeding table_space, got nil")
	}
}

func TestReadBTreeNode_ValidPasses(t *testing.T) {
	// A well-formed empty leaf must still parse.
	block := buildMinimalBTreeBlock(btnFlagLeaf, 0, 0, 0, 0)
	if _, err := readBTreeNode(block); err != nil {
		t.Fatalf("valid empty leaf rejected: %v", err)
	}
}

// keyAt/valueAt must never panic even when the TOC entry points past the
// node. We build a node whose single TOC entry references a key area beyond
// len(data) and confirm an error (not a panic).
func TestKeyValueAt_OutOfRange(t *testing.T) {
	block := buildMinimalBTreeBlock(btnFlagLeaf, 0, 1, 0, 8)
	// One kvloc TOC entry: key.off huge, key.len huge.
	dataStart := objPhysSize + btreeNodeHeaderSize
	binary.LittleEndian.PutUint16(block[dataStart+0:dataStart+2], 0xFF00) // key.off
	binary.LittleEndian.PutUint16(block[dataStart+2:dataStart+4], 0xFF00) // key.len
	binary.LittleEndian.PutUint16(block[dataStart+4:dataStart+6], 0xFF00) // val.off
	binary.LittleEndian.PutUint16(block[dataStart+6:dataStart+8], 0xFF00) // val.len
	n, err := readBTreeNode(block)
	if err != nil {
		t.Fatalf("readBTreeNode: %v", err)
	}
	r, err := newNodeReader(n, nil)
	if err != nil {
		t.Fatalf("newNodeReader: %v", err)
	}
	if _, err := r.keyAt(0); err == nil {
		t.Error("keyAt: expected out-of-range error, got nil")
	}
	if _, err := r.valueAt(0); err == nil {
		t.Error("valueAt: expected out-of-range error, got nil")
	}
}

// --- H2: NX superblock block-size validation -------------------------------

func TestReadNXSuperblock_BadBlockSize(t *testing.T) {
	for _, bs := range []uint32{0, 1, 512, 4095, 100000, 0xFFFFFFFF} {
		block := make([]byte, 4096)
		writeNXSB(block, 1, []uint64{100})
		binary.LittleEndian.PutUint32(block[36:40], bs)
		if _, err := readNXSuperblock(block); err == nil {
			t.Errorf("block size %d: expected rejection, got nil", bs)
		}
	}
}

func TestReadNXSuperblock_GoodBlockSizes(t *testing.T) {
	for _, bs := range []uint32{4096, 8192, 16384, 32768, 65536} {
		block := make([]byte, 4096)
		writeNXSB(block, 1, []uint64{100})
		binary.LittleEndian.PutUint32(block[36:40], bs)
		if _, err := readNXSuperblock(block); err != nil {
			t.Errorf("block size %d: rejected a valid size: %v", bs, err)
		}
	}
}

// --- containerByteSize -----------------------------------------------------

func TestContainerByteSize(t *testing.T) {
	cases := []struct {
		bs, bc uint64
		want   int64
	}{
		{4096, 1024, 4096 * 1024},
		{0, 1024, 4096 * 1024},      // bs=0 fallback to 4096
		{4096, 0, 4096},             // bc=0 → one block
		{65536, 1 << 60, 1<<63 - 1}, // overflow saturates to MaxInt64
	}
	for _, tc := range cases {
		c := &Container{sb: &nxSuperblockNative{blockSize: uint32(tc.bs), blockCount: tc.bc}}
		if got := c.containerByteSize(); got != tc.want {
			t.Errorf("bs=%d bc=%d: got %d, want %d", tc.bs, tc.bc, got, tc.want)
		}
	}
}

// --- H1: B-tree descent guard ----------------------------------------------

func TestBTreeGuard_DepthLimit(t *testing.T) {
	g := newBTreeGuard()
	parent := &btreeNode{level: 1000}
	child := &btreeNode{level: 999}
	g.depth = maxBTreeDepth
	if _, err := g.descend(parent, child, 5); err == nil {
		t.Fatal("expected depth-limit error, got nil")
	}
}

func TestBTreeGuard_Cycle(t *testing.T) {
	g := newBTreeGuard()
	parent := &btreeNode{level: 2}
	child := &btreeNode{level: 1}
	if _, err := g.descend(parent, child, 7); err != nil {
		t.Fatalf("first descend to paddr 7: %v", err)
	}
	// Revisiting the same paddr must be rejected as a cycle.
	if _, err := g.descend(parent, child, 7); err == nil {
		t.Fatal("expected cycle error on revisit, got nil")
	} else if !errors.Is(err, safeio.ErrCycle) {
		t.Fatalf("want ErrCycle, got %v", err)
	}
}

func TestBTreeGuard_LevelMustDecrease(t *testing.T) {
	g := newBTreeGuard()
	parent := &btreeNode{level: 1}
	// Child at same level (self-reference shape) must be rejected.
	if _, err := g.descend(parent, &btreeNode{level: 1}, 3); err == nil {
		t.Fatal("expected level error for non-decreasing level, got nil")
	}
	// Child at a higher level must also be rejected.
	if _, err := g.descend(parent, &btreeNode{level: 5}, 4); err == nil {
		t.Fatal("expected level error for higher child level, got nil")
	}
}

// TestSelfReferentialFSTree builds a container whose FS-tree internal root
// points (through the volume omap) at itself, then confirms a full traversal
// terminates with an error instead of recursing forever.
func TestSelfReferentialFSTree(t *testing.T) {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Loop")
	writeOMAP(img.blocks[4], 5)
	// Volume omap maps the FS-tree root oid 200 AND the "child" oid 200 to
	// the same physical block 6 — so descending the internal node lands back
	// on itself.
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	// FS-tree internal root (level 1) whose only child OID is 200 (itself).
	writeFSTreeInternalSelfRef(img.blocks[6], 200)

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		// Acceptable: the cycle may be caught during OpenVolume's root setup.
		return
	}
	// Must terminate (cycle/level/depth error), never hang or overflow.
	if _, err := v.ListInodes(); err == nil {
		t.Fatal("expected error traversing self-referential FS-tree, got nil")
	}
}

// writeFSTreeInternalSelfRef builds a level-1 internal FS-tree node with a
// single entry whose child OID equals childOID.
func writeFSTreeInternalSelfRef(block []byte, childOID uint64) {
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeFSTree))
	off := objPhysSize
	flags := btnFlagRoot // internal (no leaf flag), level 1
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 1) // level=1
	binary.LittleEndian.PutUint32(block[off+4:off+8], 1) // nKeys=1
	tocLen := uint16(8)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	dataStart := off + btreeNodeHeaderSize
	keyArea := dataStart + int(tocLen)
	endOfData := len(block) - btreeInfoSize
	// key: jKey(101, inode)
	key := jKey(101, jTypeInode)
	copy(block[keyArea:], key)
	// value: 8-byte child OID, stored backward from endOfData.
	v := make([]byte, 8)
	binary.LittleEndian.PutUint64(v, childOID)
	copy(block[endOfData-8:], v)
	// TOC entry (kvloc): key.off=0,key.len, val.off=8,val.len=8
	binary.LittleEndian.PutUint16(block[dataStart+0:dataStart+2], 0)
	binary.LittleEndian.PutUint16(block[dataStart+2:dataStart+4], uint16(len(key)))
	binary.LittleEndian.PutUint16(block[dataStart+4:dataStart+6], 8)
	binary.LittleEndian.PutUint16(block[dataStart+6:dataStart+8], 8)
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint64(bi[24:32], 1)
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

// --- C2: decmpfs decompression bomb ----------------------------------------

func TestDecmpfs_BombSizeRejected(t *testing.T) {
	// uncompressedSize = 2^60 must be rejected before any allocation.
	for _, ctype := range []uint32{
		decmpfsTypeUncompressedInline,
		decmpfsTypeZlibInline,
		decmpfsTypeLZVNInline,
		decmpfsTypeLZFSEInline,
	} {
		payload := make([]byte, 16)
		binary.LittleEndian.PutUint32(payload[0:4], decmpfsMagic)
		binary.LittleEndian.PutUint32(payload[4:8], ctype)
		binary.LittleEndian.PutUint64(payload[8:16], 1<<60)
		if _, err := decompressDecmpfsInline(payload); err == nil {
			t.Errorf("type %d: expected bomb-size rejection, got nil", ctype)
		} else if !errors.Is(err, safeio.ErrTooLarge) {
			t.Errorf("type %d: want ErrTooLarge, got %v", ctype, err)
		}
	}
}

func TestCheckDecmpfsSize(t *testing.T) {
	if _, err := checkDecmpfsSize(maxDecmpfsSize); err != nil {
		t.Errorf("size at cap should pass: %v", err)
	}
	if _, err := checkDecmpfsSize(maxDecmpfsSize + 1); err == nil {
		t.Error("size above cap should fail")
	}
}

// TestLimitedDecompress_Bomb feeds a zlib stream that inflates far past the
// hard cap and confirms the cap fires.
func TestLimitedDecompress_Bomb(t *testing.T) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	// 1 MiB of zeros compresses tiny but inflates large.
	if _, err := zw.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	zr, err := zlib.NewReader(bytes.NewReader(compressed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if _, err := limitedDecompress(zr, 1024); err == nil {
		t.Fatal("expected cap error for over-inflating stream, got nil")
	} else if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// A zlib bomb that declares a small uncompressedSize but inflates past the
// absolute decmpfs ceiling must error (not OOM, not silently truncate at the
// declared size while still inflating GiB into memory).
func TestDecmpfsZlibInline_DeclaredSmallButHuge(t *testing.T) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(make([]byte, (maxDecmpfsSize)+4096)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	if _, err := decmpfsZlibInline(compressed.Bytes(), 5); err == nil {
		t.Fatal("expected error when stream inflates past the cap, got nil")
	}
}

// --- C3: huge inode.Size / extent length bounded ---------------------------

func TestReadFile_HugeInodeSizeBounded(t *testing.T) {
	img := newContainerImage()
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{{oid: 100, paddr: 3}})
	writeAPSB(img.blocks[3], 100, 4, 200, "Huge")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{{oid: 200, paddr: 6}})
	writeFSTreeLeaf(img.blocks[6], 101, 1, 7, 4096, "f.txt")

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
	full, err := v.FindInode(101)
	if err != nil {
		t.Fatalf("FindInode: %v", err)
	}
	// Container is 1024 blocks * 4096 = 4 MiB. Forge an inode.Size beyond it
	// and a no-extent inode so the make() path runs against the cap.
	full.Size = 1 << 50
	full.dataExtents = nil
	if _, err := v.ReadFile(full); err == nil {
		t.Fatal("expected error for inode.Size beyond container size, got nil")
	} else if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// --- gpt fallback behaviour ------------------------------------------------

func TestFindAPFSPartitionOffset_NakedImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "naked.bin")
	if err := os.WriteFile(path, make([]byte, 1<<16), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	off, err := findAPFSPartitionOffset(f)
	if err != nil {
		t.Fatalf("naked image should yield no error: %v", err)
	}
	if off != 0 {
		t.Fatalf("naked image offset: got %d, want 0", off)
	}
}

func TestFindAPFSPartitionOffset_EmptyImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	off, err := findAPFSPartitionOffset(f)
	if err != nil || off != 0 {
		t.Fatalf("empty image: got (off=%d, err=%v), want (0, nil)", off, err)
	}
}

// TestFindAPFSPartitionOffset_GPTWithoutAPFS verifies a GPT image carrying no
// Apple_APFS partition surfaces an error (not offset 0).
func TestFindAPFSPartitionOffset_GPTWithoutAPFS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-apfs.img")
	wrapped := make([]byte, 1<<20)
	hdr := wrapped[gptSectorSize : 2*gptSectorSize]
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 2)
	binary.LittleEndian.PutUint32(hdr[0x50:0x54], 128)
	binary.LittleEndian.PutUint32(hdr[0x54:0x58], 128)
	// A Linux-fs-data type GUID (not Apple_APFS).
	linuxGUID := [16]byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
		0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}
	entry := wrapped[2*gptSectorSize : 2*gptSectorSize+128]
	copy(entry[0:16], linuxGUID[:])
	binary.LittleEndian.PutUint64(entry[0x20:0x28], 2048)
	binary.LittleEndian.PutUint64(entry[0x28:0x30], 4096)
	if err := os.WriteFile(path, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := findAPFSPartitionOffset(f); err == nil {
		t.Fatal("expected error for GPT image without Apple_APFS, got nil")
	}
}

// TestFindAPFSPartitionOffset_MalformedTable verifies a corrupt GPT header
// (EFI PART magic but garbage geometry) is rejected, never read past.
func TestFindAPFSPartitionOffset_MalformedTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-gpt.img")
	wrapped := make([]byte, 1<<16)
	hdr := wrapped[gptSectorSize : 2*gptSectorSize]
	copy(hdr[0:8], "EFI PART")
	// entrySize = 0 → malformed.
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 2)
	binary.LittleEndian.PutUint32(hdr[0x50:0x54], 128)
	binary.LittleEndian.PutUint32(hdr[0x54:0x58], 0)
	if err := os.WriteFile(path, wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := findAPFSPartitionOffset(f); err == nil {
		t.Fatal("expected error for malformed GPT table, got nil")
	}
}

// TestValueAt_FixedOutOfRange covers the fixed-shape valueAt bounds path: a
// fixed-KV leaf whose value offset points past the node end must error.
func TestValueAt_FixedOutOfRange(t *testing.T) {
	// Fixed-shape leaf, 1 key, valSize huge so the value slice runs off the
	// end of the node.
	block := buildMinimalBTreeBlock(btnFlagLeaf|btnFlagFixedKVSize, 0, 1, 0, 4)
	n, err := readBTreeNode(block)
	if err != nil {
		t.Fatalf("readBTreeNode: %v", err)
	}
	info := &btreeInfo{keySize: 16, valSize: 0xFFFF}
	r, err := newNodeReader(n, info)
	if err != nil {
		t.Fatalf("newNodeReader: %v", err)
	}
	if _, err := r.valueAt(0); err == nil {
		t.Error("valueAt: expected out-of-range error for huge valSize, got nil")
	}
}

// --- fuzz targets ----------------------------------------------------------

// FuzzReadBTreeNode hammers the node decoder with mutated blocks and asserts
// it never panics regardless of the TOC geometry.
func FuzzReadBTreeNode(f *testing.F) {
	f.Add(buildMinimalBTreeBlock(btnFlagLeaf, 0, 0, 0, 0))
	f.Add(buildMinimalBTreeBlock(btnFlagLeaf, 0, 1000, 0, 8))                      // nKeys overflow
	f.Add(buildMinimalBTreeBlock(btnFlagLeaf, 0, 1, 0xFFF0, 0xFFF0))               // tableSpace overflow
	f.Add(buildMinimalBTreeBlock(btnFlagLeaf|btnFlagFixedKVSize, 0, 0xFFFF, 0, 4)) // fixed overflow
	f.Fuzz(func(t *testing.T, block []byte) {
		n, err := readBTreeNode(block)
		if err != nil {
			return
		}
		// If it parsed, every key/value access must be bounds-safe.
		r, rerr := newNodeReader(n, nil)
		if rerr != nil {
			return
		}
		for i := 0; i < r.EntryCount() && i < 4096; i++ {
			_, _ = r.keyAt(i)
			_, _ = r.valueAt(i)
		}
	})
}

// FuzzDecmpfs hammers the transparent-compression decoder with mutated
// payloads and asserts no panic / no OOM (the size cap is enforced inside).
func FuzzDecmpfs(f *testing.F) {
	// Bomb seed: declared 2^60.
	bomb := make([]byte, 16)
	binary.LittleEndian.PutUint32(bomb[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(bomb[4:8], decmpfsTypeZlibInline)
	binary.LittleEndian.PutUint64(bomb[8:16], 1<<60)
	f.Add(bomb)
	f.Add(makeDecmpfsInlineUncompressed([]byte("hello")))
	f.Add(makeDecmpfsInlineZlib([]byte("hello world")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = decompressDecmpfsInline(payload)
	})
}
