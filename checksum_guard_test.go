package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flakyReader serves an in-memory image and fails selected reads.
type flakyReader struct {
	data     []byte
	failOff  int64 // byte offset whose reads fail (-1: none)
	failFrom int   // first read (1-based count at failOff) that fails
	seen     int
}

func (f *flakyReader) ReadAt(p []byte, off int64) (int, error) {
	if off == f.failOff {
		f.seen++
		if f.seen >= f.failFrom {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return bytes.NewReader(f.data).ReadAt(p, off)
}

func checksumRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(checksumImage(t))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func notChecksum(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want an error containing %q, got nil", want)
	}
	var ce *ChecksumError
	if errors.As(err, &ce) || errors.Is(err, ErrChecksum) {
		t.Fatalf("want a non-checksum error, got %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("want %q in %v", want, err)
	}
}

func TestOpenReadErrorsAreRefusedNotFallenBack(t *testing.T) {
	raw := checksumRaw(t)
	sb, err := readNXSuperblock(raw[:4096])
	if err != nil {
		t.Fatal(err)
	}
	// Block 0 unreadable.
	_, err = OpenContainerFromBackend(&flakyReader{data: raw, failOff: 0, failFrom: 1})
	notChecksum(t, err, "read block 0")
	// Block 0 readable once (parse) and not again (checkpoint verification).
	_, err = OpenContainerFromBackend(&flakyReader{data: raw, failOff: 0, failFrom: 2})
	notChecksum(t, err, "read superblock block 0")
	// Container omap block unreadable.
	_, err = OpenContainerFromBackend(&flakyReader{data: raw, failOff: int64(sb.omapOID) * 4096, failFrom: 1})
	notChecksum(t, err, "read container omap")
	// Control: the same backend with no failure opens.
	c, err := OpenContainerFromBackend(&flakyReader{data: raw, failOff: -1})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// A non-checksum failure of the current checkpoint must not trigger the
// fall-back: only a checksum mismatch means "try an older checkpoint".
func TestNonChecksumFailureDoesNotFallBack(t *testing.T) {
	raw := checksumRaw(t)
	// Point block 0's omap OID at block 0 itself (a sealed NXSB, not an omap).
	binary.LittleEndian.PutUint64(raw[160:168], 0)
	sealBlock(raw[:4096])
	// omapOID 0 means "no omap": opens.
	c, err := OpenContainerFromBackend(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("omapOID 0: %v", err)
	}
	c.Close()
	// Name a sealed NX superblock (the first descriptor block) as the omap:
	// wrong object type, a plain error. The descriptor area still holds a
	// good older checkpoint, which must NOT be used.
	raw = checksumRaw(t)
	sb, _ := readNXSuperblock(raw[:4096])
	binary.LittleEndian.PutUint64(raw[160:168], sb.xpDescBase)
	sealBlock(raw[:4096])
	_, err = OpenContainerFromBackend(bytes.NewReader(raw))
	notChecksum(t, err, "wrong object type")
}

func TestOlderCheckpointsBounds(t *testing.T) {
	raw := checksumRaw(t)
	c, err := OpenContainerFromBackend(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	base := *c.sb
	if base.xpDescBlocks == 0 {
		t.Fatal("formatted image has no descriptor area")
	}
	cands := c.olderCheckpoints(&base)
	if len(cands) == 0 {
		t.Fatal("no checkpoint found in the descriptor area")
	}
	for i := 1; i < len(cands); i++ {
		if cands[i-1].sb.xid < cands[i].sb.xid {
			t.Fatal("candidates not newest-first")
		}
	}
	zero := base
	zero.xpDescBlocks = 0
	if got := c.olderCheckpoints(&zero); len(got) != 0 {
		t.Fatalf("zero-length descriptor area yielded %d", len(got))
	}
	noncontig := base
	noncontig.xpDescBlocks |= 0x80000000
	if got := c.olderCheckpoints(&noncontig); len(got) != 0 {
		t.Fatalf("non-contiguous descriptor area yielded %d", len(got))
	}
	huge := base
	huge.xpDescBlocks = 0x7FFFFFFF
	if got := c.olderCheckpoints(&huge); len(got) == 0 || len(got) > maxDescScan {
		t.Fatalf("huge descriptor area: %d candidates", len(got))
	}
	other := base
	other.uuid[0] ^= 0xFF
	if got := c.olderCheckpoints(&other); len(got) != 0 {
		t.Fatalf("a checkpoint of another container yielded %d", len(got))
	}
}

func TestOpenOptionsFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := OpenContainerOptions(missing, Options{}); err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("missing file (ro): %v", err)
	}
	if _, err := OpenContainerRWOptions(missing, Options{}); err == nil || !strings.Contains(err.Error(), "rw open") {
		t.Fatalf("missing file (rw): %v", err)
	}
	// GPT signature with a truncated header: refused, never read as APFS.
	bad := filepath.Join(t.TempDir(), "gpt")
	buf := make([]byte, 1024)
	copy(buf[512:], "EFI PART")
	if err := os.WriteFile(bad, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContainerOptions(bad, Options{}); err == nil {
		t.Fatal("malformed GPT opened")
	}
	// RW open of a valid image works and keeps its writer.
	c, err := OpenContainerRWOptions(checksumImage(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if c.w == nil {
		t.Fatal("RW container has no writer")
	}
	c.Close()
}

func tamperedImage(t *testing.T) string {
	t.Helper()
	img := checksumImage(t)
	raw, _ := os.ReadFile(img)
	idx := bytes.Index(raw, []byte("hello.txt"))
	if idx < 0 {
		t.Fatal("name not in image")
	}
	raw[idx] = 'j'
	if err := os.WriteFile(img, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return img
}

func TestOpenEntryPointsRefuseTamperedImage(t *testing.T) {
	img := tamperedImage(t)
	list := func(open func() error) error { return open() }
	err := list(func() error {
		fsys, err := OpenWithOptions(img, -1, Options{})
		if err == nil {
			defer fsys.Close()
			_, err = fsys.ListDir("/")
		}
		return err
	})
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	err = list(func() error {
		fsys, err := OpenWithKeys(img, -1, "pw")
		if err == nil {
			defer fsys.Close()
			_, err = fsys.ListDir("/")
		}
		return err
	})
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("OpenWithKeys: %v", err)
	}
	// A file the reader does not recognise is still ErrNoHeader.
	junk := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(junk, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithOptions(junk, -1, Options{}); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("junk: want ErrNoHeader, got %v", err)
	}
}

func TestReadBlockRefusals(t *testing.T) {
	raw := checksumRaw(t)
	sb, _ := readNXSuperblock(raw[:4096])
	// Tamper the container omap block (an object).
	raw[sb.omapOID*4096+100] ^= 1
	c, err := OpenContainerFromBackend(bytes.NewReader(raw))
	if err == nil {
		c.Close()
		t.Fatal("tampered omap opened")
	}
	if !errors.Is(err, ErrChecksum) {
		t.Fatal(err)
	}
	c, err = OpenContainerFromBackend(bytes.NewReader(checksumRaw(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Past the end of the backend: a plain read error, not a checksum error.
	_, err = c.readBlock(uint64(len(raw))/4096 + 10)
	if err == nil || errors.Is(err, ErrChecksum) {
		t.Fatalf("beyond EOF: %v", err)
	}
	// An all-zero block fails the checksum unless verification is off.
	zeroRaw := make([]byte, 4096*8)
	copy(zeroRaw, checksumRaw(t)[:4096*3])
	c2 := &Container{r: bytes.NewReader(zeroRaw), sb: c.sb}
	if _, err := c2.readBlock(5); !errors.Is(err, ErrChecksum) {
		t.Fatalf("zero block: want ErrChecksum, got %v", err)
	}
	c2.SetIgnoreChecksums(true)
	if _, err := c2.readBlock(5); err != nil {
		t.Fatalf("zero block under IgnoreChecksums: %v", err)
	}
}
