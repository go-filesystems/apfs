package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	apfsfde "github.com/go-fde/apfs"
)

const fdeTestPass = "s3cret"

// fdeFiles is what the round trip writes and expects to read back.
func fdeFiles() map[string][]byte {
	rng := rand.New(rand.NewSource(7))
	big := make([]byte, 300<<10+123) // several blocks, a partial last one
	rng.Read(big)
	return map[string][]byte{
		"/hello.txt":   []byte("hello, FileVault\n"),
		"/dir/big.bin": big,
	}
}

// formatEncryptedWithFiles formats a 32 MiB FileVault container, writes
// fdeFiles through the writer (which writes plaintext: the container
// metadata is plaintext, so the plain opener can write), then encrypts the
// volume the way apfs.kext lays an encrypted volume out (see
// encryptVolumeLikeFileVault). It returns the image path.
func formatEncryptedWithFiles(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fv.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(path, 32<<20, "Vault", []byte(fdeTestPass)); err != nil {
		t.Fatal(err)
	}
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("plain open of the fresh container: %v", err)
	}
	d := fs.(*driver)
	if err := d.MkDir("/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	for p, data := range fdeFiles() {
		if err := d.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	encryptVolumeLikeFileVault(t, path)
	return path
}

// encryptVolumeLikeFileVault turns the plaintext volume of a
// FormatContainerEncrypted image into the on-disk shape of a software-
// encrypted one (Apple File System Reference, "Encryption"; apfs-fuse
// BTree::GetNode, ApfsDir::ReadFile): every object of the volume object map
// gets OMAP_VAL_ENCRYPTED and is AES-XTS-encrypted with the VEK, tweak base
// paddr*(bs/512); every file extent gets crypto_id = its first block and its
// blocks are encrypted with tweak base crypto_id*(bs/512). The container
// metadata, the volume superblock and the volume object map stay plaintext.
func encryptVolumeLikeFileVault(t testing.TB, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vk, err := apfsfde.UnlockVolumeKey(f, []byte(fdeTestPass), apfsfde.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := apfsfde.NewSectorCipher(vk.VEK)
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenContainer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatal(err)
	}
	const bs = 4096
	const units = bs / apfsfde.SectorSize
	readBlk := func(p uint64) []byte {
		b := make([]byte, bs)
		if _, err := f.ReadAt(b, int64(p)*bs); err != nil {
			t.Fatal(err)
		}
		return b
	}
	writeBlk := func(p uint64, b []byte) {
		if _, err := f.WriteAt(b, int64(p)*bs); err != nil {
			t.Fatal(err)
		}
	}
	omapRoot := v.volOmap.treeOID
	omapBlk := readBlk(omapRoot)
	on, err := readBTreeNode(omapBlk)
	if err != nil || !on.IsLeaf() {
		t.Fatalf("volume omap root is not a single leaf (err %v): the helper only handles that", err)
	}
	oinfo, err := readRootBTreeInfo(omapBlk)
	if err != nil {
		t.Fatal(err)
	}
	or, err := newNodeReader(on, oinfo)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := 0
	for i := 0; i < or.EntryCount(); i++ {
		val, err := or.valueAt(i)
		if err != nil {
			t.Fatal(err)
		}
		paddr := binary.LittleEndian.Uint64(val[8:16])
		node := readBlk(paddr)
		if n, err := readBTreeNode(node); err == nil && n.IsLeaf() {
			var info *btreeInfo
			if n.IsRoot() {
				info, _ = readRootBTreeInfo(node)
			}
			if nr, err := newNodeReader(n, info); err == nil {
				for j := 0; j < nr.EntryCount(); j++ {
					k, kerr := nr.keyAt(j)
					ev, verr := nr.valueAt(j)
					if kerr != nil || verr != nil {
						continue
					}
					_, typ, err := jKeyHeader(k)
					if err != nil || typ != jTypeFileExt || len(ev) < 24 {
						continue
					}
					length := binary.LittleEndian.Uint64(ev[0:8]) & (1<<56 - 1)
					phys := binary.LittleEndian.Uint64(ev[8:16])
					if phys == 0 {
						continue
					}
					binary.LittleEndian.PutUint64(ev[16:24], phys) // crypto_id
					data := make([]byte, (length+bs-1)/bs*bs)
					if _, err := f.ReadAt(data, int64(phys)*bs); err != nil {
						t.Fatal(err)
					}
					if err := sc.Encrypt(data, phys*units); err != nil {
						t.Fatal(err)
					}
					if _, err := f.WriteAt(data, int64(phys)*bs); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		sealBlock(node)
		if err := sc.Encrypt(node, paddr*units); err != nil {
			t.Fatal(err)
		}
		writeBlk(paddr, node)
		binary.LittleEndian.PutUint32(val[0:4], binary.LittleEndian.Uint32(val[0:4])|omapValEncrypted)
		encrypted++
	}
	if encrypted == 0 {
		t.Fatal("the volume object map maps nothing")
	}
	sealBlock(omapBlk)
	writeBlk(omapRoot, omapBlk)
}

func checkFDEFiles(t *testing.T, d *driver) {
	t.Helper()
	ents, err := d.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir /: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "dir" || names[1] != "hello.txt" {
		t.Fatalf("root lists %q, want [dir hello.txt]", names)
	}
	for p, want := range fdeFiles() {
		got, err := d.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ReadFile %s: %d bytes differ from the %d written", p, len(got), len(want))
		}
	}
	// Streaming reads at offsets that are not data-unit aligned.
	_, ino, err := d.resolvePath("/dir/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	ra, err := d.v.FileReaderAt(ino)
	if err != nil {
		t.Fatal(err)
	}
	want := fdeFiles()["/dir/big.bin"]
	for _, w := range [][2]int{{0, 17}, {511, 2}, {4095, 4098}, {100_000, 70_001}, {len(want) - 300, 300}} {
		buf := make([]byte, w[1])
		n, err := ra.ReadAt(buf, int64(w[0]))
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d, %d): %v", w[0], w[1], err)
		}
		if !bytes.Equal(buf[:n], want[w[0]:w[0]+n]) || n != w[1] {
			t.Fatalf("ReadAt(%d, %d): %d bytes, content differs", w[0], w[1], n)
		}
	}
}

// memDev is an in-memory BlockRW, as the browser playground has.
type memDev struct {
	mu     sync.Mutex
	b      []byte
	closed bool
	writes int
}

func (m *memDev) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memDev) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	m.writes++
	m.mu.Unlock()
	return copy(m.b[off:], p), nil
}
func (m *memDev) Close() error { m.closed = true; return nil }
func (m *memDev) Size() int64  { return int64(len(m.b)) }

func TestOpenFDE_ReadsEncryptedVolume(t *testing.T) {
	path := formatEncryptedWithFiles(t)

	// The volume really is encrypted now: the plain opener cannot read it.
	if fs, err := Open(path, -1); err == nil {
		got, rerr := fs.(*driver).ReadFile("/hello.txt")
		fs.Close()
		if rerr == nil && bytes.Equal(got, fdeFiles()["/hello.txt"]) {
			t.Fatal("the plain opener read the file: the test image is not encrypted")
		}
	}

	t.Run("path", func(t *testing.T) {
		fs, err := OpenFDE(path, []byte(fdeTestPass), 0)
		if err != nil {
			t.Fatalf("OpenFDE: %v", err)
		}
		defer fs.Close()
		checkFDEFiles(t, fs.(*driver))
	})
	t.Run("block device", func(t *testing.T) {
		img, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		dev := &memDev{b: img}
		fs, err := OpenFDEFromBlockDeviceLimited(dev, []byte(fdeTestPass), -1,
			apfsfde.Limits{MaxPBKDF2Iterations: formatEncryptedPBKDF2Iterations, MaxArgon2Time: 1, MaxArgon2MemoryKiB: 64})
		if err != nil {
			t.Fatalf("OpenFDEFromBlockDeviceLimited: %v", err)
		}
		d := fs.(*driver)
		checkFDEFiles(t, d)
		// Read-only: a write is refused and nothing reaches the device.
		if err := d.WriteFile("/new.txt", []byte("x"), 0o644); err == nil {
			t.Fatal("a write to a FileVault volume was accepted")
		}
		if dev.writes != 0 {
			t.Fatalf("%d writes reached the device", dev.writes)
		}
		if err := fs.Close(); err != nil || !dev.closed {
			t.Fatalf("Close: err %v, device closed %v", err, dev.closed)
		}
	})
}

// The repro of the defect: the empty volume FormatContainerEncrypted writes.
func TestOpenFDE_FreshFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(path, 32<<20, "Vault", []byte(fdeTestPass)); err != nil {
		t.Fatal(err)
	}
	fs, err := OpenFDE(path, []byte(fdeTestPass), 0)
	if err != nil {
		t.Fatalf("OpenFDE on a fresh FormatContainerEncrypted image: %v", err)
	}
	defer fs.Close()
	if _, err := fs.(*driver).ListDir("/"); err != nil {
		t.Fatal(err)
	}
	if got := fs.(*driver).Label(); got != "Vault" {
		t.Fatalf("label %q, want Vault", got)
	}
}

func TestOpenFDE_GPT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpt.img")
	if err := FormatContainerEncryptedGPT(path, 34<<20, "Vault", []byte(fdeTestPass)); err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{-1, 0} {
		fs, err := OpenFDE(path, []byte(fdeTestPass), idx)
		if err != nil {
			t.Fatalf("partIndex %d: %v", idx, err)
		}
		fs.Close()
	}
	if _, err := OpenFDE(path, []byte(fdeTestPass), 5); err == nil {
		t.Fatal("partition 5 of a one-partition image opened")
	}
}

func TestOpenFDE_ErrorsAreDistinct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(path, 32<<20, "Vault", []byte(fdeTestPass)); err != nil {
		t.Fatal(err)
	}
	_, err := OpenFDE(path, []byte("wrong"), 0)
	if !errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrLimit) {
		t.Fatalf("wrong passphrase: err = %v, want ErrWrongPassphrase only", err)
	}
	img, _ := os.ReadFile(path)
	dev := &memDev{b: img}
	_, err = OpenFDEFromBlockDeviceLimited(dev, []byte(fdeTestPass), -1, apfsfde.Limits{MaxPBKDF2Iterations: 1000})
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("100000 iterations under a 1000 limit: err = %v, want ErrLimit only", err)
	}
	if !dev.closed {
		t.Fatal("the device was not closed on error")
	}
	// Not APFS at all.
	_, err = OpenFDEFromBlockDevice(&memDev{b: make([]byte, 1<<20)}, []byte("x"), -1)
	if err == nil {
		t.Fatal("zeros opened")
	}
}

// The old read path wrapped the whole device in an apfsfde.Device, which
// decrypts the plaintext container metadata too. This is the regression
// witness: that shape cannot open the image the new path reads.
func TestOpenFDE_WholeDeviceDecryptionCannotOpen(t *testing.T) {
	path := formatEncryptedWithFiles(t)
	dev, err := apfsfde.Open(path, []byte(fdeTestPass))
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if _, err := OpenContainerFromBackend(dev); err == nil {
		t.Fatal("whole-device decryption opened the container: the image's metadata is not plaintext")
	}
}

// FuzzOpenUnlocked corrupts one block of an encrypted image (the bytes are
// the block's PLAINTEXT when the block is encrypted, so the parsers behind
// the XTS layer see them) and drives the read path after unlock: open, list,
// read, stream. Key derivation is skipped (the key is known), so each exec
// costs the read path only. It must not panic or hang.
func FuzzOpenUnlocked(f *testing.F) {
	path := formatEncryptedWithFiles(f)
	img, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	vk, err := apfsfde.UnlockVolumeKey(bytes.NewReader(img), []byte(fdeTestPass), apfsfde.DefaultLimits)
	if err != nil {
		f.Fatal(err)
	}
	sc, _ := apfsfde.NewSectorCipher(vk.VEK)
	// Seeds: the blocks the open path touches, unchanged.
	for _, blk := range []uint16{0, 1, 2, 3, 4, 5, 10, 11, 12, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26} {
		f.Add(blk, false, img[int(blk)*4096:int(blk+1)*4096])
	}
	nBlocks := len(img) / 4096
	f.Fuzz(func(t *testing.T, blk uint16, encrypt bool, data []byte) {
		if int(blk) >= nBlocks {
			return
		}
		m := append([]byte(nil), img...)
		b := make([]byte, 4096)
		copy(b, data)
		if encrypt {
			_ = sc.Encrypt(b, uint64(blk)*8)
		}
		copy(m[int(blk)*4096:], b)
		d, err := openUnlocked(readOnly{bytes.NewReader(m)}, func() error { return nil }, vk)
		if err != nil {
			return
		}
		defer d.Close()
		_, _ = d.ListDir("/")
		_, _ = d.ListDir("/dir")
		_, _ = d.ReadFile("/hello.txt")
		_, _ = d.ReadFile("/dir/big.bin")
		if _, ino, err := d.resolvePath("/dir/big.bin"); err == nil {
			if ra, err := d.v.FileReaderAt(ino); err == nil {
				_, _ = ra.ReadAt(make([]byte, 1000), 4000)
			}
		}
	})
}

func BenchmarkOpenListRead(b *testing.B) {
	enc := formatEncryptedWithFiles(b)
	plain := filepath.Join(b.TempDir(), "plain.img")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := FormatContainer(plain, 32<<20, "Plain"); err != nil {
		b.Fatal(err)
	}
	fs, err := Open(plain, -1)
	if err != nil {
		b.Fatal(err)
	}
	fs.(*driver).MkDir("/dir", 0o755)
	for p, data := range fdeFiles() {
		fs.(*driver).WriteFile(p, data, 0o644)
	}
	fs.Close()
	run := func(b *testing.B, open func() (*driver, error)) {
		b.SetBytes(int64(len(fdeFiles()["/dir/big.bin"])))
		for b.Loop() {
			d, err := open()
			if err != nil {
				b.Fatal(err)
			}
			if _, err := d.ListDir("/"); err != nil {
				b.Fatal(err)
			}
			if _, err := d.ReadFile("/dir/big.bin"); err != nil {
				b.Fatal(err)
			}
			d.Close()
		}
	}
	// Key derivation (PBKDF2, 100000 iterations) dominates an open; the
	// read path is measured with it and, separately, after it.
	b.Run("plain", func(b *testing.B) {
		run(b, func() (*driver, error) {
			fs, err := OpenFDE_plainForBench(plain)
			return fs, err
		})
	})
	b.Run("filevault", func(b *testing.B) {
		run(b, func() (*driver, error) {
			fs, err := OpenFDE(enc, []byte(fdeTestPass), -1)
			if err != nil {
				return nil, err
			}
			return fs.(*driver), nil
		})
	})
	b.Run("filevault-read-only", func(b *testing.B) {
		fs, err := OpenFDE(enc, []byte(fdeTestPass), -1)
		if err != nil {
			b.Fatal(err)
		}
		d := fs.(*driver)
		defer d.Close()
		b.SetBytes(int64(len(fdeFiles()["/dir/big.bin"])))
		for b.Loop() {
			if _, err := d.ListDir("/"); err != nil {
				b.Fatal(err)
			}
			if _, err := d.ReadFile("/dir/big.bin"); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("plain-read-only", func(b *testing.B) {
		d, err := OpenFDE_plainForBench(plain)
		if err != nil {
			b.Fatal(err)
		}
		defer d.Close()
		b.SetBytes(int64(len(fdeFiles()["/dir/big.bin"])))
		for b.Loop() {
			if _, err := d.ListDir("/"); err != nil {
				b.Fatal(err)
			}
			if _, err := d.ReadFile("/dir/big.bin"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// OpenFDE_plainForBench opens the plain image read-only, as OpenFDE does the
// encrypted one, so the two rows differ only by encryption.
func OpenFDE_plainForBench(path string) (*driver, error) {
	c, err := OpenContainerAuto(path)
	if err != nil {
		return nil, err
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &driver{c: c, v: v}, nil
}
