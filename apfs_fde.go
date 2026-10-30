package filesystem_apfs

// apfs_fde.go opens FileVault (software-encrypted) APFS volumes.
//
// The keybags are unlocked with go-fde/apfs (UnlockVolumeKey), which returns
// the VEK and the UUID of the volume it belongs to. The container is then
// read raw -- its metadata is plaintext -- and only what the volume encrypts
// is decrypted, block by block, with a go-fde/apfs SectorCipher: see
// fde_crypt.go for the rules and their references.
//
// A FileVault volume opened here is read-only: the writers of this package
// write plaintext nodes and extents with crypto_id 0, which on an encrypted
// volume would store user data in clear.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	apfsfde "github.com/go-fde/apfs"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-volumes/gpt"
)

// BlockRW is the minimal interface for an arbitrary read-write block
// device accepted by OpenFromBlockDevice and OpenFDEFromBlockDevice. The
// FileVault openers only read and close it.
type BlockRW interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Close() error
}

// ErrWrongPassphrase and ErrLimit are the go-fde/apfs errors an FDE open
// wraps: no passphrase locker opened with the passphrase given, or a locker
// asked for more key-derivation work than the Limits allow. Test with
// errors.Is.
var (
	ErrWrongPassphrase = apfsfde.ErrWrongPassphrase
	ErrLimit           = apfsfde.ErrLimit
)

// OpenFDE opens the FileVault-encrypted APFS volume in the image at
// imagePath, unlocking it with passphrase, read-only.
//
// partIndex selects the partition when the image carries a partition table
// (0-based slot; -1 picks the first Apple_APFS partition). A bare container
// (NX superblock at offset 0) ignores it.
func OpenFDE(imagePath string, passphrase []byte, partIndex int) (filesystem.Filesystem, error) {
	return OpenFDELimited(imagePath, passphrase, partIndex, apfsfde.DefaultLimits)
}

// OpenFDELimited is OpenFDE with lim bounding the key derivation the
// image's keybag can ask for.
func OpenFDELimited(imagePath string, passphrase []byte, partIndex int, lim apfsfde.Limits) (filesystem.Filesystem, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("apfs: open %s: %w", imagePath, err)
	}
	size := int64(math.MaxInt64)
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		size = st.Size()
	}
	fs, err := openFDE(f, size, f.Close, passphrase, partIndex, lim)
	if err != nil {
		f.Close()
		return nil, err
	}
	return fs, nil
}

// OpenFDEFromBlockDevice opens the FileVault-encrypted APFS volume on dev,
// read-only, with go-fde/apfs's DefaultLimits. partIndex is as for OpenFDE.
// Closing the returned Filesystem closes dev; on error dev is closed too.
func OpenFDEFromBlockDevice(dev BlockRW, passphrase []byte, partIndex int) (filesystem.Filesystem, error) {
	return OpenFDEFromBlockDeviceLimited(dev, passphrase, partIndex, apfsfde.DefaultLimits)
}

// OpenFDEFromBlockDeviceLimited is OpenFDEFromBlockDevice with lim bounding
// the key derivation: the variant for an image from elsewhere (an upload, a
// dropped file). A refusal wraps ErrLimit, a wrong passphrase
// ErrWrongPassphrase.
//
// The device size, used to validate a partition table, is taken from a
// Size() int64 or Stat() method when dev has one.
func OpenFDEFromBlockDeviceLimited(dev BlockRW, passphrase []byte, partIndex int, lim apfsfde.Limits) (filesystem.Filesystem, error) {
	fs, err := openFDE(dev, deviceSize(dev), dev.Close, passphrase, partIndex, lim)
	if err != nil {
		dev.Close()
		return nil, err
	}
	return fs, nil
}

// readOnly hides any WriteAt of the backend so the Container advertises no
// write capability.
type readOnly struct{ r io.ReaderAt }

func (o readOnly) ReadAt(p []byte, off int64) (int, error) { return o.r.ReadAt(p, off) }

// openFDE: locate the container, unlock the volume key, open the container
// raw with the key installed, then the volume the key belongs to.
func openFDE(r io.ReaderAt, size int64, closer func() error, passphrase []byte, partIndex int, lim apfsfde.Limits) (filesystem.Filesystem, error) {
	off, err := containerOffset(r, size, partIndex)
	if err != nil {
		return nil, err
	}
	var cr containerReader = readOnly{r}
	if off != 0 {
		cr = &offsetReader{inner: cr, offset: off}
	}
	vk, err := apfsfde.UnlockVolumeKey(cr, passphrase, lim)
	if err != nil {
		return nil, fmt.Errorf("apfs: unlock FileVault: %w", err)
	}
	d, err := openUnlocked(cr, closer, vk)
	if err != nil {
		return nil, err // not a typed-nil *driver in the interface
	}
	return d, nil
}

// openUnlocked opens the container on cr with the volume key vk installed.
func openUnlocked(cr containerReader, closer func() error, vk apfsfde.VolumeKey) (*driver, error) {
	c, err := openContainerFrom(cr, closer)
	if err != nil {
		return nil, err
	}
	c.w = nil
	if c.fsCrypt, err = newFSCrypt(vk.VEK, c.sb.blockSize); err != nil {
		return nil, err
	}
	idx, err := c.encryptedVolumeIndex(vk.VolumeUUID)
	if err != nil {
		return nil, err
	}
	v, err := c.OpenVolume(idx)
	if err != nil {
		return nil, err
	}
	return &driver{c: c, v: v}, nil
}

// encryptedVolumeIndex returns the index of the volume whose apfs_vol_uuid is
// uuid -- the one the keybag unlocked -- or, for a keybag that names no
// volume, the first encrypted volume. Only APFS_FS_ONEKEY volumes can be
// read: per-file keys are hardware encryption (Apple File System Reference,
// "Accessing Encrypted Objects").
func (c *Container) encryptedVolumeIndex(uuid [16]byte) (int, error) {
	if c.containerOmap == nil {
		return 0, fmt.Errorf("apfs: container omap not loaded")
	}
	for i, oid := range c.sb.fsOIDs {
		paddr, err := c.omapLookup(c.containerOmap, oid, ^uint64(0))
		if err != nil {
			continue
		}
		raw, err := c.readBlock(paddr)
		if err != nil {
			continue
		}
		apsb, err := readAPSB(raw)
		if err != nil {
			continue
		}
		if uuid != ([16]byte{}) && apsb.uuid != uuid {
			continue
		}
		if apsb.fsFlags&apfsFSUnencrypted != 0 {
			if uuid != ([16]byte{}) {
				return 0, fmt.Errorf("apfs: volume %d is the keybag's but is not encrypted", i)
			}
			continue
		}
		if apsb.fsFlags&apfsFSOneKey == 0 {
			return 0, fmt.Errorf("apfs: volume %d uses per-file keys (hardware encryption), not supported", i)
		}
		return i, nil
	}
	return 0, fmt.Errorf("apfs: no encrypted volume matches the unlocked key")
}

// containerOffset returns where the APFS container starts on r: 0 for a bare
// container, else the partition partIndex selects (-1: the first
// Apple_APFS partition).
func containerOffset(r io.ReaderAt, size int64, partIndex int) (int64, error) {
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 32); err == nil && string(magic[:]) == nxMagicASCII {
		return 0, nil
	}
	var (
		p   gpt.Partition
		err error
	)
	if partIndex < 0 {
		p, err = gpt.ByType(r, size, gpt.AppleAPFSGUID)
	} else {
		p, err = gpt.ByIndex(r, size, partIndex)
	}
	if errors.Is(err, gpt.ErrNoTable) {
		return 0, fmt.Errorf("apfs: no APFS container and no partition table")
	}
	if err != nil {
		return 0, fmt.Errorf("apfs: partition %d: %w", partIndex, err)
	}
	return p.StartOffset, nil
}

// deviceSize asks dev for its size; math.MaxInt64 when it cannot say (reads
// past the real end then fail, they are not trusted to succeed).
func deviceSize(dev any) int64 {
	switch d := dev.(type) {
	case interface{ Size() int64 }:
		if s := d.Size(); s > 0 {
			return s
		}
	case interface{ Stat() (os.FileInfo, error) }:
		if st, err := d.Stat(); err == nil && st.Size() > 0 {
			return st.Size()
		}
	}
	return math.MaxInt64
}

// openEncryptedFilesystem is the FileVault branch of Open/OpenWithKeys and
// Create.
func openEncryptedFilesystem(path string, passphrase []byte) (filesystem.Filesystem, error) {
	return OpenFDE(path, passphrase, -1)
}

// OpenFromBlockDevice opens an APFS container from any read-write
// block device satisfying BlockRW. Useful for QCOW2 or memory-
// backed backends. For FileVault-encrypted devices, use
// OpenFDEFromBlockDevice instead.
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
