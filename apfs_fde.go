package filesystem_apfs

// apfs_fde.go integrates the go-fde/apfs FileVault 2 decryption layer
// with the real-APFS reader. `OpenFDE` and `OpenFromBlockDevice` are
// thin wrappers around the `*Container` / `*Volume` API exposed via
// `driver` (driver.go).

import (
	"fmt"

	apfsfde "github.com/go-fde/apfs"
	filesystem "github.com/go-filesystems/interface"
)

// BlockRW is the minimal interface for an arbitrary read-write block
// device accepted by OpenFromBlockDevice. Kept for source-level
// compatibility with callers that still pass custom backends.
type BlockRW interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Close() error
}

// OpenFDE opens a FileVault 2-encrypted APFS container at imagePath,
// unlocking it with passphrase, and returns a Filesystem backed by
// the decrypted container.
//
// If imagePath does not look like a FileVault container, an error is
// returned; the caller should fall back to Open.
func OpenFDE(imagePath string, passphrase []byte, partIndex int) (filesystem.Filesystem, error) {
	_ = partIndex
	ok, err := apfsfde.Detect(imagePath)
	if err != nil {
		return nil, fmt.Errorf("apfs: detect FDE: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("apfs: %s is not a FileVault-encrypted APFS container", imagePath)
	}
	return openEncryptedFilesystem(imagePath, passphrase)
}

// openEncryptedFilesystem unlocks the FileVault keybag via
// pkg/go-fde/apfs, then plugs the decrypted block device into the
// real-APFS reader via OpenContainerFromBackend. The returned
// driver owns the *apfsfde.Device and closes it on Close().
func openEncryptedFilesystem(path string, passphrase []byte) (filesystem.Filesystem, error) {
	adev, err := apfsfde.Open(path, passphrase)
	if err != nil {
		return nil, fmt.Errorf("apfs: unlock FDE: %w", err)
	}
	c, err := openContainerFromFDEDevice(adev)
	if err != nil {
		adev.Close()
		return nil, err
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &driver{c: c, v: v}, nil
}

// openContainerFromFDEDevice wraps an *apfsfde.Device as a
// containerReader (+ optional containerWriter) and opens the
// resulting Container. The wrapper also forwards Close so closing
// the Container closes the underlying decrypted device.
func openContainerFromFDEDevice(dev *apfsfde.Device) (*Container, error) {
	w := &fdeContainerBackend{dev: dev}
	return OpenContainerFromBackend(w)
}

// fdeContainerBackend is the minimal Reader+Writer+Closer wrapper
// over a *apfsfde.Device satisfying the containerReader /
// containerWriter / closer interfaces expected by
// OpenContainerFromBackend.
type fdeContainerBackend struct {
	dev *apfsfde.Device
}

func (f *fdeContainerBackend) ReadAt(p []byte, off int64) (int, error)  { return f.dev.ReadAt(p, off) }
func (f *fdeContainerBackend) WriteAt(p []byte, off int64) (int, error) { return f.dev.WriteAt(p, off) }
func (f *fdeContainerBackend) Close() error                             { return f.dev.Close() }

// OpenFromBlockDevice opens an APFS container from any read-write
// block device satisfying BlockRW. Useful for QCOW2 or memory-
// backed backends. For FileVault-encrypted devices, use OpenFDE
// instead.
func OpenFromBlockDevice(dev BlockRW, partIndex int) (filesystem.Filesystem, error) {
	_ = partIndex
	c, err := OpenContainerFromBackend(&blockRWBackend{rw: dev})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("apfs: open from block device: %w", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &driver{c: c, v: v}, nil
}

// blockRWBackend adapts BlockRW for OpenContainerFromBackend.
type blockRWBackend struct {
	rw BlockRW
}

func (b *blockRWBackend) ReadAt(p []byte, off int64) (int, error)  { return b.rw.ReadAt(p, off) }
func (b *blockRWBackend) WriteAt(p []byte, off int64) (int, error) { return b.rw.WriteAt(p, off) }
func (b *blockRWBackend) Close() error                             { return b.rw.Close() }
