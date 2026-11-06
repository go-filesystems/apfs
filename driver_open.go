package filesystem_apfs

// driver_open.go — filesystem.Opener for the driver: positional reads of a
// file, one range at a time, over the extent reader (read_streaming.go), so
// that a server answering a READ of a few bytes of a large file (NFS, SFTP) does
// not materialise the whole file (ReadFile) for every request.

import (
	"fmt"
	"io"
	"os"

	filesystem "github.com/go-filesystems/interface"
)

var _ filesystem.Opener = (*driver)(nil)

// OpenFile opens the regular file at path for positional reads. Nothing of the
// file is read here; each ReadAt reads the extents of its own window, holes read
// as zeros. In mount mode the host's own file is opened.
func (d *driver) OpenFile(path string) (filesystem.File, error) {
	if d.mountpoint != "" {
		f, err := os.Open(mountPathToReal(d.mountpoint, path))
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err == nil && !st.Mode().IsRegular() {
			err = fmt.Errorf("apfs: %q is not a regular file", path)
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		return &mountFile{f: f, size: st.Size()}, nil
	}
	d.opMu.RLock()
	defer d.opMu.RUnlock()
	_, ino, err := d.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if ino.IsDir {
		return nil, fmt.Errorf("apfs: %q is a directory", path)
	}
	ra, err := d.v.FileReaderAt(ino)
	if err != nil {
		return nil, err
	}
	size := ino.Size
	if size > 1<<62 {
		size = 1 << 62
	}
	return &volumeFile{d: d, ra: ra, size: int64(size)}, nil
}

// volumeFile is a file of the volume: reads take the driver's read lock, so
// that a write that is going on does not change the extents under a read.
type volumeFile struct {
	d    *driver
	ra   io.ReaderAt
	size int64
}

func (f *volumeFile) Size() int64 { return f.size }

func (f *volumeFile) ReadAt(p []byte, off int64) (int, error) {
	f.d.opMu.RLock()
	defer f.d.opMu.RUnlock()
	return f.ra.ReadAt(p, off)
}

func (f *volumeFile) Close() error { return nil }

// mountFile is a file of the host's mounted copy of the image.
type mountFile struct {
	f    *os.File
	size int64
}

func (f *mountFile) Size() int64                             { return f.size }
func (f *mountFile) ReadAt(p []byte, off int64) (int, error) { return f.f.ReadAt(p, off) }
func (f *mountFile) Close() error                            { return f.f.Close() }
