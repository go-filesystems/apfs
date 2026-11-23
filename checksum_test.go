package filesystem_apfs

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-simd/adler32/fletcher64"
)

// fletcher64Ref is the straightforward reduce-after-every-word form of the
// algorithm in the Apple File System Reference ("Fletcher 64 Checksum
// Algorithm"); the shared kernel defers the reduction and must agree with it.
func fletcher64Ref(buf []byte) uint64 {
	const mod = uint64(0xFFFFFFFF)
	var s1, s2 uint64
	for i := 0; i+4 <= len(buf); i += 4 {
		s1 = (s1 + uint64(binary.LittleEndian.Uint32(buf[i:i+4]))) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - ((s1 + s2) % mod)
	c2 := mod - ((s1 + c1) % mod)
	return (c2 << 32) | c1
}

// TestObjectChecksumIsTheSharedKernel is the regression test for moving the
// kernel to github.com/go-simd/adler32/fletcher64: a block sealed by this
// package carries exactly the o_cksum the pre-move local kernel produced (the
// known answer for the byte(i*7+3) pattern over 4088 bytes, taken from
// v0.7.0), and verifyObjectBlock accepts it.
func TestObjectChecksumIsTheSharedKernel(t *testing.T) {
	block := make([]byte, 4096)
	for i := 8; i < len(block); i++ {
		block[i] = byte((i-8)*7 + 3)
	}
	sealBlock(block)
	if got, want := binary.LittleEndian.Uint64(block[0:8]), uint64(0x1c193445c3b48774); got != want {
		t.Fatalf("sealed o_cksum = %#016x, want %#016x (the v0.7.0 kernel's)", got, want)
	}
	if got := fletcher64.Sum(block[8:]); got != binary.LittleEndian.Uint64(block[0:8]) {
		t.Fatalf("shared kernel %#016x disagrees with the sealed o_cksum", got)
	}
	if err := verifyObjectBlock(0, block); err != nil {
		t.Fatalf("a freshly sealed block must verify: %v", err)
	}
	block[100] ^= 1
	if err := verifyObjectBlock(0, block); err == nil {
		t.Fatal("a flipped bit must fail verification")
	}
}

func TestFletcher64MatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 3, 4, 8, 4088, 4096, 4100, 16384, 65528} {
		b := make([]byte, n)
		rng.Read(b)
		if got, want := fletcher64.Sum(b), fletcher64Ref(b); got != want {
			t.Fatalf("len %d: %#x != %#x", n, got, want)
		}
		for i := range b {
			b[i] = 0xFF // worst case for overflow of the deferred sums
		}
		if got, want := fletcher64.Sum(b), fletcher64Ref(b); got != want {
			t.Fatalf("len %d (0xFF): %#x != %#x", n, got, want)
		}
	}
}

// checksumImage formats a container holding one file and returns its path.
func checksumImage(t *testing.T) string {
	t.Helper()
	img := filepath.Join(t.TempDir(), "img")
	fsys, err := Format(img, 64<<20, FormatConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/hello.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	return img
}

func flipByte(t *testing.T, img string, off int64) {
	t.Helper()
	f, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatal(err)
	}
}

// Every block of the image that carries an object header and is read when the
// first volume is listed must be covered: flip one payload byte in each such
// block in turn and require a typed error (or a clean fall-back), never success
// with wrong data and never a panic.
func TestEveryObjectBlockIsVerified(t *testing.T) {
	base := checksumImage(t)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	detected := 0
	for bn := 0; bn*4096 < len(raw) && bn < 64; bn++ {
		blk := raw[bn*4096 : (bn+1)*4096]
		switch binary.LittleEndian.Uint16(blk[24:26]) & 0x00FF {
		case uint16(objTypeBTree), uint16(objTypeBTreeNode), uint16(objTypeOMAP), uint16(objTypeAPFSVolume):
		default:
			continue
		}
		cp := append([]byte(nil), raw...)
		cp[bn*4096+100] ^= 0x01
		img := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(img, cp, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := OpenContainerOptions(img, Options{})
		if err == nil {
			v, verr := c.OpenVolume(0)
			if verr == nil {
				_, verr = v.ListInodes()
			}
			err = verr
			c.Close()
		}
		var ce *ChecksumError
		if errors.As(err, &ce) && errors.Is(err, ErrChecksum) {
			detected++
		}
	}
	if detected == 0 {
		t.Fatal("no tampered object block was detected")
	}
}

func TestIgnoreChecksumsOptOut(t *testing.T) {
	img := checksumImage(t)
	raw, _ := os.ReadFile(img)
	// Find the directory leaf holding the name and rewrite one letter.
	idx := -1
	for i := 0; i+9 <= len(raw); i++ {
		if string(raw[i:i+9]) == "hello.txt" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("name not in image")
	}
	raw[idx] = 'j'
	if err := os.WriteFile(img, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fsys, err := OpenWithOptions(img, -1, Options{})
	if err == nil {
		_, err = fsys.ListDir("/")
		fsys.Close()
	}
	var ce *ChecksumError
	if !errors.As(err, &ce) {
		t.Fatalf("default open: want *ChecksumError, got %v", err)
	}
	fsys, err = OpenWithOptions(img, -1, Options{IgnoreChecksums: true})
	if err != nil {
		t.Fatalf("IgnoreChecksums open: %v", err)
	}
	defer fsys.Close()
	ents, err := fsys.ListDir("/")
	if err != nil {
		t.Fatalf("IgnoreChecksums ListDir: %v", err)
	}
	found := false
	for _, e := range ents {
		if e.Name() == "jello.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("forged name not served under IgnoreChecksums: %v", ents)
	}
}

// A block-zero superblock that fails its checksum makes the reader fall back
// to the newest valid superblock of the checkpoint descriptor area.
func TestBlockZeroChecksumFallsBackToCheckpoint(t *testing.T) {
	img := checksumImage(t)
	flipByte(t, img, 200) // payload byte of block 0's NX superblock
	c, err := OpenContainerOptions(img, Options{})
	if err != nil {
		t.Fatalf("expected fall-back to an older checkpoint, got %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ListInodes(); err != nil {
		t.Fatal(err)
	}
	// Under IgnoreChecksums nothing is verified and block zero is used as is.
	c2, err := OpenContainerOptions(img, Options{IgnoreChecksums: true})
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
}

// When no checkpoint verifies, the error is typed and nothing panics.
func TestAllCheckpointsCorruptIsTypedError(t *testing.T) {
	img := checksumImage(t)
	raw, _ := os.ReadFile(img)
	sb, err := readNXSuperblock(raw[:4096])
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < uint64(sb.xpDescBlocks&0x7FFFFFFF) && i < 64; i++ {
		raw[(sb.xpDescBase+i)*4096+100] ^= 0x01
	}
	raw[100] ^= 0x01
	if err := os.WriteFile(img, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = OpenContainerOptions(img, Options{})
	var ce *ChecksumError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ChecksumError, got %v", err)
	}
	if _, err := Open(img, -1); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Open: want ErrChecksum, got %v", err)
	}
}

func TestVerifyObjectBlockShortAndExact(t *testing.T) {
	var ce *ChecksumError
	err := verifyObjectBlock(7, make([]byte, objPhysSize-1))
	if err == nil || errors.As(err, &ce) {
		t.Fatalf("short block: want a plain error, got %v", err)
	}
	// Exactly objPhysSize bytes: the header alone is a complete block.
	b := make([]byte, objPhysSize)
	sealBlock(b)
	if err := verifyObjectBlock(7, b); err != nil {
		t.Fatalf("sealed %d-byte block refused: %v", objPhysSize, err)
	}
	b[20] ^= 1
	err = verifyObjectBlock(7, b)
	if !errors.As(err, &ce) || ce.Block != 7 || ce.Stored == ce.Computed {
		t.Fatalf("want *ChecksumError for block 7, got %v", err)
	}
}

// Read-path allocation and time baseline (go test -bench ReadPath -benchmem).
func BenchmarkReadPath(b *testing.B) {
	img := filepath.Join(b.TempDir(), "img")
	fsys, err := Format(img, 64<<20, FormatConfig{})
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []string{"/a.txt", "/b.txt", "/c.txt"} {
		if err := fsys.WriteFile(n, []byte("payload"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	fsys.Close()
	c, err := OpenContainerAuto(img)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.ListInodes(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFletcher64Block(b *testing.B) {
	buf := make([]byte, 4088)
	rand.New(rand.NewSource(2)).Read(buf)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		_ = fletcher64.Sum(buf)
	}
}
