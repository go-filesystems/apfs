package filesystem_apfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

func offsetPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>12)
	}
	return b
}

// bigDriver is a container holding /big, a file of fileSize bytes whose
// content is a function of the offset.
func bigDriver(t testing.TB, fileSize int) (*driver, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainer(path, int64(fileSize)+64<<20, "Big"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	data := offsetPattern(fileSize)
	if _, err := v.CreateFile(apfsRootDirInoNum, "big", data); err != nil {
		c.Close()
		t.Fatalf("CreateFile: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &driver{c: c, v: v}, data
}

// A READ at an offset past 64 MiB must not need the file whole.
func TestOpenFileReadsARangePast64MiB(t *testing.T) {
	const fileSize = 72 << 20
	d, want := bigDriver(t, fileSize)
	var o filesystem.Opener = d
	f, err := o.OpenFile("/big")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != fileSize {
		t.Fatalf("Size = %d", f.Size())
	}
	for _, off := range []int64{0, 4095, 64 << 20, 66<<20 + 123, fileSize - 10} {
		buf := make([]byte, 4096)
		n, err := f.ReadAt(buf, off)
		wantN := min(int64(len(buf)), fileSize-off)
		if int64(n) != wantN || (n < len(buf)) != errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d) = %d, %v; want %d", off, n, err, wantN)
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d): wrong bytes", off)
		}
	}
	if n, err := f.ReadAt(make([]byte, 8), fileSize); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at the end = %d, %v", n, err)
	}
}

func TestOpenFileRefusalsAndMountMode(t *testing.T) {
	d, _ := bigDriver(t, 1<<20)
	if _, err := d.OpenFile("/nope"); err == nil {
		t.Error("a missing file was opened")
	}
	if _, err := d.OpenFile("/"); err == nil {
		t.Error("a directory was opened")
	}
	// Mount mode: the host's own file.
	mnt := t.TempDir()
	if err := os.WriteFile(filepath.Join(mnt, "f"), []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	md := &driver{mountpoint: mnt}
	f, err := md.OpenFile("/f")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if n, err := f.ReadAt(buf, 6); n != 5 || err != nil || string(buf) != "world" || f.Size() != 11 {
		t.Errorf("mount mode ReadAt = %d %v %q size %d", n, err, buf, f.Size())
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
	if _, err := md.OpenFile("/missing"); err == nil {
		t.Error("a missing host file was opened")
	}
	if _, err := md.OpenFile("/"); err == nil {
		t.Error("a host directory was opened as a file")
	}
}

// BenchmarkReadRangeOfBigFile: a 1 MiB read at 66 MiB of a 72 MiB file through
// OpenFile/ReadAt and through ReadFile. Allocations are exact; times are not
// under load.
func BenchmarkReadRangeOfBigFile(b *testing.B) {
	d, _ := bigDriver(b, 72<<20)
	b.Run("OpenFile-ReadAt", func(b *testing.B) {
		f, err := d.OpenFile("/big")
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, 1<<20)
		b.SetBytes(int64(len(buf)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := f.ReadAt(buf, 66<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReadFile-whole", func(b *testing.B) {
		b.SetBytes(1 << 20)
		b.ReportAllocs()
		for b.Loop() {
			data, err := d.ReadFile("/big")
			if err != nil {
				b.Fatal(err)
			}
			_ = data[66<<20 : 67<<20]
		}
	})
}
