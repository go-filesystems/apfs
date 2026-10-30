package filesystem_apfs

// fde_crypt.go -- what a FileVault (software-encrypted) volume encrypts, and
// only that.
//
// Apple File System Reference (2020-06-22), "Encryption" / "Accessing
// Encrypted Objects": when a volume is encrypted, its file-system tree and
// the contents of its files are encrypted with the VEK as an AES-XTS key.
// "Object Map Value Flags": OMAP_VAL_ENCRYPTED (0x4) marks an encrypted
// object. j_file_extent_val_t.crypto_id: on an APFS_FS_ONEKEY volume it is the
// AES-XTS tweak of the extent.
//
// apfs-fuse (sgan81/apfs-fuse, ApfsLib) is the reference reader:
//   - ApfsVolume::ReadBlocks decrypts blkcnt blocks only when the volume is
//     encrypted and xts_tweak != 0, in 512-byte data units numbered from
//     xts_tweak * (blocksize / 512);
//   - BTree::GetNode passes omr.paddr as the tweak when the object-map value
//     has OMAP_VAL_ENCRYPTED, and 0 (no decryption) otherwise;
//   - the volume superblock, its object map, the extent-ref and snapshot
//     trees are read with tweak 0, i.e. raw;
//   - ApfsDir::ReadFile reads extent blocks with tweak crypto_id + blk_idx.
//
// The container metadata (NX superblock, checkpoints, container object map,
// spaceman) is plaintext. go-fde/apfs's Device decrypts every byte, which is
// why opening a FileVault container through it garbled the NX superblock.

import (
	"fmt"
	"io"
	"math"
	"sync"

	apfsfde "github.com/go-fde/apfs"
)

// omapValEncrypted is OMAP_VAL_ENCRYPTED.
const omapValEncrypted uint32 = 0x4

// APSB apfs_fs_flags bits.
const (
	apfsFSUnencrypted uint64 = 0x1 // APFS_FS_UNENCRYPTED
	apfsFSOneKey      uint64 = 0x8 // APFS_FS_ONEKEY
)

// fsCrypt is the unlocked key of the one encrypted volume a Container was
// opened for, plus the set of physical blocks the object maps declared
// encrypted. readBlock consults it; nothing else of the container changes.
type fsCrypt struct {
	sc            *apfsfde.SectorCipher
	unitsPerBlock uint64 // blockSize / 512

	mu  sync.Mutex
	enc map[uint64]struct{} // paddrs whose omap value carries OMAP_VAL_ENCRYPTED
}

func newFSCrypt(vek []byte, blockSize uint32) (*fsCrypt, error) {
	sc, err := apfsfde.NewSectorCipher(vek)
	if err != nil {
		return nil, err
	}
	return &fsCrypt{
		sc:            sc,
		unitsPerBlock: uint64(blockSize) / apfsfde.SectorSize,
		enc:           make(map[uint64]struct{}),
	}, nil
}

// markEncrypted records that the object at paddr is encrypted. Every
// virtual object is reached through an object-map lookup before its block is
// read, so the lookup is where the flag is learnt.
func (f *fsCrypt) markEncrypted(paddr uint64) {
	f.mu.Lock()
	f.enc[paddr] = struct{}{}
	f.mu.Unlock()
}

func (f *fsCrypt) isEncrypted(paddr uint64) bool {
	f.mu.Lock()
	_, ok := f.enc[paddr]
	f.mu.Unlock()
	return ok
}

// decryptBlocks decrypts whole blocks read from paddr in place: the tweak of
// a metadata block is its own address (BTree::GetNode).
func (f *fsCrypt) decryptBlocks(p []byte, paddr uint64) error {
	return f.sc.Decrypt(p, paddr*f.unitsPerBlock)
}

// blockByteOffset is paddr × blockSize as an int64, refusing what does not
// fit: block numbers come from the image.
func blockByteOffset(paddr, blockSize uint64) (int64, error) {
	if blockSize == 0 || paddr > uint64(math.MaxInt64)/blockSize {
		return 0, fmt.Errorf("apfs: block %d is past any device", paddr)
	}
	return int64(paddr * blockSize), nil
}

// readExtentAt fills p with the bytes at offset within of ext, decrypting
// them when the extent is encrypted (crypt != nil and crypto_id != 0, the
// apfs-fuse rule). An encrypted read is widened to whole 512-byte data units;
// an aligned one is decrypted in place without a copy.
func readExtentAt(r io.ReaderAt, crypt *fsCrypt, blockSize uint64, ext containerExtent, p []byte, within uint64) error {
	base, err := blockByteOffset(ext.physBlock, blockSize)
	if err != nil {
		return err
	}
	if within > uint64(math.MaxInt64-base) {
		return fmt.Errorf("apfs: extent offset %d past any device", within)
	}
	if crypt == nil || ext.cryptoID == 0 {
		_, err := r.ReadAt(p, base+int64(within))
		return err
	}
	const unit = apfsfde.SectorSize
	lo := within &^ (unit - 1)
	hi := (within + uint64(len(p)) + unit - 1) &^ (unit - 1)
	buf := p
	if lo != within || hi-lo != uint64(len(p)) {
		buf = make([]byte, hi-lo)
	}
	if _, err := r.ReadAt(buf, base+int64(lo)); err != nil {
		return err
	}
	// Data unit k of the extent has tweak crypto_id*(bs/512) + k
	// (ApfsDir::ReadFile + ApfsVolume::ReadBlocks); uint64 arithmetic wraps
	// as it does there.
	if err := crypt.sc.Decrypt(buf, ext.cryptoID*crypt.unitsPerBlock+lo/unit); err != nil {
		return err
	}
	if &buf[0] != &p[0] {
		copy(p, buf[within-lo:])
	}
	return nil
}
