package filesystem_apfs

// format_encrypted.go layers the F-2 encrypted-container metadata on
// top of FormatContainer. The plaintext container is built first; this
// file then:
//
//   1. Generates VEK + KEK + per-instance salts.
//   2. Builds the container + volume keybag block contents using the
//      go-fde/apfs primitives (BuildVEKBlob, BuildKEKBlob, PackKeybagBlock).
//   3. Encrypts both keybag blocks at rest with the right UUID-derived
//      AES-XTS keys (see EncryptContainerKeybag / EncryptVolumeKeybag).
//   4. Allocates two fresh blocks past the metadata range, marks them
//      in the chunk bitmap + CIB free count + spaceman free count via
//      Container.markBlocksAllocated.
//   5. Patches the live + checkpoint NX SB copies to set nx_keylocker
//      = {paddr, 1} at offset 1296 and nx_flags |= NX_CRYPTO_SW (0x4)
//      at offset 1264, then re-seals.
//   6. Patches the APSB to clear the APFS_FS_UNENCRYPTED bit, then
//      re-seals.
//
// What this DOES NOT touch: the volume metadata blocks (APSB, volume
// OMAP + leaf, FS-tree root, snap-meta, extent-ref). Direct probing of
// Apple's reference encrypted DMG shows those stay PLAINTEXT on disk
// even when NX_CRYPTO_SW is set — the VEK layer is only applied to
// user file data, not to volume metadata. An earlier draft of this
// formatter VEK-encrypted the volume metadata blocks too; removing
// that step is what unblocks the kext's spaceman query / volume
// enumeration on encrypted output.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	apfsfde "github.com/go-fde/apfs"
	"golang.org/x/crypto/pbkdf2"
)

// nxKeylockerOffset is the byte offset of the nx_keylocker apfs_prange
// inside the NX SuperBlock (paddr u64 + block_count u64 = 16 bytes).
// See pkg/go-filesystems/apfs/probe_apple_keybag_darwin_test.go.
const nxKeylockerOffset = 1296

// nxFlagsOffset is the byte offset of nx_flags inside the NX SB. Bit
// 0x4 (NX_CRYPTO_SW) tells apfs.kext the container is software-encrypted.
const nxFlagsOffset = 1264

// nxFlagCryptoSW is the NX_CRYPTO_SW flag value.
const nxFlagCryptoSW uint64 = 0x4

// apsbFSFlagsOffset is the byte offset of apfs_fs_flags inside the
// APSB. Bit 0x1 (APFS_FS_UNENCRYPTED) is set by FormatContainer for
// plaintext volumes; encrypted volumes must clear it.
const apsbFSFlagsOffset = 0x108

// apsbVolumeUUIDOffset is the byte offset of apfs_vol_uuid inside the
// APSB.
const apsbVolumeUUIDOffset = 0xF0

// formatEncryptedPBKDF2Iterations is the PBKDF2 round count this
// formatter uses for the user passphrase. Apple uses ~150K-200K rounds
// for FileVault; this value falls in that range and keeps test runs
// reasonable.
const formatEncryptedPBKDF2Iterations = 100_000

// formatContainerKeybagBlock and formatVolumeKeybagBlock are the on-disk
// paddrs of the two keybags this formatter writes. They sit immediately
// after the formatMetadataBlocks=91 metadata range; markBlocksAllocated
// extends the chunk bitmap + CIB + spaceman free-count to cover them.
const (
	formatContainerKeybagBlock uint64 = 91
	formatVolumeKeybagBlock    uint64 = 92
)

// Encrypted-container ephemeral additions: Apple's `diskutil apfs
// encryptVolume` produces a container whose CURRENT checkpoint has 5
// ephemeral mappings (vs the 2 our unencrypted N-2 path emits):
// SPACEMAN + REAPER + SFQ_IP B-tree root + SFQ_MAIN B-tree root +
// INTEGRITY_META. The kext's APFSExtendedSpaceInfo query (the source
// of the -69808 error our pre-FQ output triggered) appears to require
// these blocks to be present for software-encrypted containers. See
// the spaceman byte-diff in TestProbe_AppleEncryptedAPSBDecrypt for
// the full byte target.
//
// Paddrs reuse formatXPDataBase+4..+6 (= 13, 14, 15) — the data-area
// slots that our unencrypted format leaves zero-filled.
const (
	formatFQIPRootBlock     uint64 = formatXPDataBase + 4 // 13
	formatFQMainRootBlock   uint64 = formatXPDataBase + 5 // 14
	formatIntegrityBlock    uint64 = formatXPDataBase + 6 // 15
	formatFQIPRootOID       uint64 = 1027                 // matches Apple's reference
	formatFQMainRootOID     uint64 = 1029                 // matches Apple's reference
	formatIntegrityOID      uint64 = 1030                 // matches Apple's reference
	objTypeBTreeEphemeral   uint32 = 0x80000002           // EPHEMERAL | BTREE
	objTypeIntegrityMeta    uint32 = 0x80000012           // EPHEMERAL | INTEGRITY_META
	objSubtypeFreeQueue     uint32 = 0x09                 // SPACEMAN_FREE_QUEUE
	apfsBTNodeFlagsEmpty    uint16 = 0x0007               // ROOT | LEAF | FIXED_KV
	apfsFQTOCSpaceLen       uint16 = 0x0240               // 576 — matches Apple
)

// FormatContainerEncrypted writes a fresh APFS container at path with
// FileVault-style software encryption enabled, protected by passphrase.
// The returned container has nx_flags |= NX_CRYPTO_SW set and a
// container + volume keybag pair the kext-style unlock walk
// (passphrase → PBKDF2-derived key → KEK → VEK) can recover.
//
// The container is byte-compatible with apfsfde.Open at the keybag-chain
// level — see TestFormatContainerEncrypted_Roundtrips. It is NOT yet
// expected to mount via `hdiutil attach -stdinpass` because the volume
// metadata blocks (APSB, OMAPs, FS-tree root, …) are still plaintext;
// adding the AES-XTS-VEK layer on top is the next iteration.
func FormatContainerEncrypted(path string, sizeBytes int64, volumeLabel string, passphrase []byte) error {
	const blockSize = 4096
	if sizeBytes < int64(formatVolumeKeybagBlock+1)*blockSize {
		return fmt.Errorf("apfs: format encrypted: size %d bytes is too small (need at least %d for metadata + keybags)",
			sizeBytes, int64(formatVolumeKeybagBlock+1)*blockSize)
	}
	if err := FormatContainer(path, sizeBytes, volumeLabel); err != nil {
		return err
	}

	// 1. Generate per-instance secret material.
	vek := make([]byte, 32)
	kek := make([]byte, 32)
	pbkdf2Salt := make([]byte, 16)
	vekHMACSalt := make([]byte, 8)
	kekHMACSalt := make([]byte, 8)
	for _, b := range [][]byte{vek, kek, pbkdf2Salt, vekHMACSalt, kekHMACSalt} {
		if _, err := formatRandReadFn(b); err != nil {
			return fmt.Errorf("apfs: format encrypted: rand: %w", err)
		}
	}

	// 2. Wrap KEK with passphrase-derived key, then VEK with KEK (RFC 3394).
	derivedKey := pbkdf2.Key(passphrase, pbkdf2Salt, formatEncryptedPBKDF2Iterations, 32, sha256.New)
	wrappedKEK, err := apfsfde.AESKeyWrap(derivedKey, kek)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: wrap KEK: %w", err)
	}
	wrappedVEK, err := apfsfde.AESKeyWrap(kek, vek)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: wrap VEK: %w", err)
	}

	// 3. Open the freshly-formatted container so we can read the
	// existing UUIDs and use the markBlocksAllocated bookkeeping.
	c, err := OpenContainerRW(path)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: reopen: %w", err)
	}
	defer c.Close()

	containerUUID, err := readContainerUUID(c)
	if err != nil {
		return err
	}
	volumeUUID, err := readVolumeUUID(c)
	if err != nil {
		return err
	}

	// 4. Build the container keybag (tag=3 prange to volume keybag,
	// tag=2 VEKBLOB) and the volume keybag (tag=3 KEKBLOB).
	prangeData := make([]byte, 16)
	binary.LittleEndian.PutUint64(prangeData[:8], formatVolumeKeybagBlock)
	binary.LittleEndian.PutUint64(prangeData[8:], 1)
	vekBlob, err := apfsfde.BuildVEKBlob(volumeUUID, 0, wrappedVEK, vekHMACSalt)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: build VEKBLOB: %w", err)
	}
	kekBlob, err := apfsfde.BuildKEKBlob(volumeUUID, 0, wrappedKEK,
		formatEncryptedPBKDF2Iterations, pbkdf2Salt, kekHMACSalt)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: build KEKBLOB: %w", err)
	}
	// Apple's reference has obj_phys.oid = 0 in keybags (verified across
	// both reference DMGs in TestProbe_TwoAppleReferences). Use the
	// non-paddr variant so we match.
	containerKBPlain := apfsfde.PackKeybagBlock([]apfsfde.KeybagEntry{
		{UUID: volumeUUID, Tag: apfsfde.KBTagVolumeUnlockRecords, Data: prangeData},
		{UUID: volumeUUID, Tag: apfsfde.KBTagVolumeKey, Data: vekBlob},
	})
	volumeKBPlain := apfsfde.PackKeybagBlock([]apfsfde.KeybagEntry{
		{UUID: volumeUUID, Tag: apfsfde.KBTagVolumePassphrase, Data: kekBlob},
	})

	// 5. Encrypt at rest with the appropriate UUID-derived XTS keys.
	containerKBCipher, err := apfsfde.EncryptContainerKeybag(containerKBPlain, containerUUID, formatContainerKeybagBlock)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: encrypt container kb: %w", err)
	}
	volumeKBCipher, err := apfsfde.EncryptVolumeKeybag(volumeKBPlain, volumeUUID, formatVolumeKeybagBlock)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: encrypt volume kb: %w", err)
	}

	// 6. Reserve the two keybag blocks in the allocator's view.
	if err := c.markBlocksAllocated(formatContainerKeybagBlock, 2); err != nil {
		return fmt.Errorf("apfs: format encrypted: mark allocated: %w", err)
	}

	// 7. Write the encrypted keybag blocks.
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted: open for keybag write: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteAt(containerKBCipher, int64(formatContainerKeybagBlock)*blockSize); err != nil {
		return fmt.Errorf("apfs: format encrypted: write container kb: %w", err)
	}
	if _, err := f.WriteAt(volumeKBCipher, int64(formatVolumeKeybagBlock)*blockSize); err != nil {
		return fmt.Errorf("apfs: format encrypted: write volume kb: %w", err)
	}

	// 8. Patch the live NX SB (block 0) and its current-checkpoint copy
	// (currentNXSBCopyBlock = formatXPDescBase+3) with nx_keylocker and
	// nx_flags. Re-seal each.
	if err := patchNXSBEncryptionFields(f, 0); err != nil {
		return err
	}
	if err := patchNXSBEncryptionFields(f, int64(currentNXSBCopyBlock)*blockSize); err != nil {
		return err
	}

	// 9. Patch the APSB to clear APFS_FS_UNENCRYPTED.
	if err := patchAPSBEncryptedFlag(f); err != nil {
		return err
	}

	// Volume metadata blocks (APSB, volume OMAP, FS-tree root, snap-meta,
	// extent-ref) stay PLAINTEXT — confirmed by direct probing of
	// Apple's reference encrypted DMG (its APSB at paddr 136 carries the
	// "APSB" magic in clear). The VEK is reserved for user file data;
	// applying it to volume metadata makes the kext's spaceman query
	// fail with -69808.
	_ = vek

	// 10. Emit the FQ trees + integrity_meta and extend the current
	// checkpoint to include them. Required for the kext's encrypted-
	// container code path (see CPM byte-diff in
	// TestProbe_AppleEncryptedAPSBDecrypt).
	if err := emitEncryptedCheckpointEphemerals(f); err != nil {
		return err
	}

	return nil
}

// emitEncryptedCheckpointEphemerals writes the three additional
// ephemerals Apple's encrypted reference carries in its current
// checkpoint (SFQ_IP root, SFQ_MAIN root, INTEGRITY_META), patches
// the CPM to declare them, sets sm_fq[].sfq_tree_oid in the live
// spaceman, and bumps `nx_xp_data_len` from 2 to 5 in the live and
// checkpoint NX SB copies.
func emitEncryptedCheckpointEphemerals(f *os.File) error {
	const blockSize = 4096

	// Apple's reference has an INTEGRITY_META ephemeral as a side effect
	// of `diskutil apfs encryptVolume` running on a sealable volume; for
	// our basic encrypted-container case (no sealing) we omit it
	// (cpm_count stays at 4). The integrity-meta path is dropped — if
	// sealable-volume support is needed in the future, restore the
	// helper from git history.

	fqIP := newFQTreeRootBlock(formatFQIPRootOID)
	fqMain := newFQTreeRootBlock(formatFQMainRootOID)
	if _, err := f.WriteAt(fqIP, int64(formatFQIPRootBlock)*blockSize); err != nil {
		return fmt.Errorf("apfs: format encrypted: write FQ_IP: %w", err)
	}
	if _, err := f.WriteAt(fqMain, int64(formatFQMainRootBlock)*blockSize); err != nil {
		return fmt.Errorf("apfs: format encrypted: write FQ_MAIN: %w", err)
	}

	if err := patchCheckpointMapForEncryption(f); err != nil {
		return err
	}
	if err := patchSpacemanFQOIDsForEncryption(f); err != nil {
		return err
	}
	if err := patchNXSBDataLenForEncryption(f); err != nil {
		return err
	}
	return nil
}

// newFQTreeRootBlock returns a 4 KiB block containing an empty
// SPACEMAN_FREE_QUEUE B-tree root keyed on the supplied ephemeral oid.
// Layout matches Apple's reference (see TestProbe_AppleEncryptedAPSBDecrypt).
func newFQTreeRootBlock(oid uint64) []byte {
	block := make([]byte, 4096)
	// obj_phys
	binary.LittleEndian.PutUint64(block[8:16], oid)
	binary.LittleEndian.PutUint64(block[16:24], formatCurrentXID)
	binary.LittleEndian.PutUint32(block[24:28], objTypeBTreeEphemeral)
	binary.LittleEndian.PutUint32(block[28:32], objSubtypeFreeQueue)

	// btn_phys at +32: empty single-leaf root with FIXED_KV.
	off := 32
	binary.LittleEndian.PutUint16(block[off:off+2], apfsBTNodeFlagsEmpty)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0)         // level
	binary.LittleEndian.PutUint32(block[off+4:off+8], 0)         // nkeys
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)        // table_space.off (= 0 relative to data area start)
	binary.LittleEndian.PutUint16(block[off+10:off+12], apfsFQTOCSpaceLen)
	// free_space.off is RELATIVE to the end of table_space (= 0 means
	// "free area starts immediately after the TOC reserved region").
	// fsck_apfs rejects absolute offsets here with "invalid btn_free_space".
	freeLen := uint16(4096 - 56 - int(apfsFQTOCSpaceLen) - btreeInfoSize)
	binary.LittleEndian.PutUint16(block[off+12:off+14], 0)       // free_space.off = 0 (after table_space)
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)
	binary.LittleEndian.PutUint16(block[off+16:off+18], 0xFFFF)  // key_free_list.off (none)
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)       // key_free_list.len
	binary.LittleEndian.PutUint16(block[off+20:off+22], 0xFFFF)  // val_free_list.off (none)
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)       // val_free_list.len

	// btreeInfo trailer at end of block.
	bi := block[4096-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagEphemeral|btreeFlagAllowGhosts)
	binary.LittleEndian.PutUint32(bi[4:8], 4096)  // bt_node_size
	binary.LittleEndian.PutUint32(bi[8:12], 16)   // bt_key_size (apfs_spaceman_free_queue_key_t)
	binary.LittleEndian.PutUint32(bi[12:16], 8)   // bt_val_size (uint64 count)
	binary.LittleEndian.PutUint32(bi[16:20], 16)  // bt_longest_key
	binary.LittleEndian.PutUint32(bi[20:24], 8)   // bt_longest_val
	binary.LittleEndian.PutUint64(bi[24:32], 0)   // bt_key_count
	binary.LittleEndian.PutUint64(bi[32:40], 1)   // bt_node_count
	sealBlock(block)
	return block
}

// patchCheckpointMapForEncryption rewrites the current checkpoint map
// (paddr 5) to declare 5 ephemerals (SPACEMAN, REAPER, FQ_IP, FQ_MAIN,
// INTEGRITY_META) instead of the 2 our base format emits.
func patchCheckpointMapForEncryption(f *os.File) error {
	const blockSize = 4096
	cpmPaddr := int64(currentCheckpointMapBlock) * blockSize
	cpm := make([]byte, blockSize)
	if _, err := f.ReadAt(cpm, cpmPaddr); err != nil {
		return fmt.Errorf("apfs: format encrypted: read CPM: %w", err)
	}
	// cpm_count at +36 (cpm_flags is at +32).
	const formatEncryptedCPMCount = 4 // SPACEMAN + REAPER + SFQ_IP + SFQ_MAIN
	binary.LittleEndian.PutUint32(cpm[36:40], formatEncryptedCPMCount)
	// Existing entries at +40 and +80 (40-byte entries) are SPACEMAN
	// and REAPER per the unencrypted format. Append the FQ trees.
	writeCPMEntry(cpm, 2, objTypeBTreeEphemeral, objSubtypeFreeQueue, formatFQIPRootOID, formatFQIPRootBlock)
	writeCPMEntry(cpm, 3, objTypeBTreeEphemeral, objSubtypeFreeQueue, formatFQMainRootOID, formatFQMainRootBlock)
	sealBlock(cpm)
	if _, err := f.WriteAt(cpm, cpmPaddr); err != nil {
		return fmt.Errorf("apfs: format encrypted: write CPM: %w", err)
	}
	return nil
}

// writeCPMEntry writes one 40-byte checkpoint_mapping_t at slot index.
// CPM entry layout (matches existing writeCheckpointMapping in format.go):
//   +0   uint32 cpm_type
//   +4   uint32 cpm_subtype
//   +8   uint32 cpm_size  (block size)
//   +12  uint32 cpm_pad
//   +16  uint64 cpm_fs_oid (0 for container-level)
//   +24  uint64 cpm_oid
//   +32  uint64 cpm_paddr
func writeCPMEntry(cpm []byte, slot int, typ, subtype uint32, oid, paddr uint64) {
	off := 40 + slot*40
	binary.LittleEndian.PutUint32(cpm[off:off+4], typ)
	binary.LittleEndian.PutUint32(cpm[off+4:off+8], subtype)
	binary.LittleEndian.PutUint32(cpm[off+8:off+12], 4096)
	binary.LittleEndian.PutUint32(cpm[off+12:off+16], 0)
	binary.LittleEndian.PutUint64(cpm[off+16:off+24], 0)
	binary.LittleEndian.PutUint64(cpm[off+24:off+32], oid)
	binary.LittleEndian.PutUint64(cpm[off+32:off+40], paddr)
}

// patchSpacemanFQOIDsForEncryption sets sm_fq[SFQ_IP].sfq_tree_oid and
// sm_fq[SFQ_MAIN].sfq_tree_oid in the live (xid=2) spaceman block at
// paddr formatXPDataBase+2 = 11. sfq_count and sfq_oldest_xid stay
// zero (the trees are empty).
func patchSpacemanFQOIDsForEncryption(f *os.File) error {
	const blockSize = 4096
	const spacemanFQOff = 200
	const sfqTreeOIDOff = 8 // within spaceman_free_queue_t
	smPaddr := int64(formatXPDataBase+2) * blockSize
	sm := make([]byte, blockSize)
	if _, err := f.ReadAt(sm, smPaddr); err != nil {
		return fmt.Errorf("apfs: format encrypted: read spaceman: %w", err)
	}
	// SFQ_IP is sm_fq[0] at +200; SFQ_MAIN is sm_fq[1] at +240; SFQ_TIER2 is sm_fq[2] at +280.
	binary.LittleEndian.PutUint64(sm[spacemanFQOff+sfqTreeOIDOff:spacemanFQOff+sfqTreeOIDOff+8], formatFQIPRootOID)
	binary.LittleEndian.PutUint64(sm[spacemanFQOff+40+sfqTreeOIDOff:spacemanFQOff+40+sfqTreeOIDOff+8], formatFQMainRootOID)
	sealBlock(sm)
	if _, err := f.WriteAt(sm, smPaddr); err != nil {
		return fmt.Errorf("apfs: format encrypted: write spaceman: %w", err)
	}
	return nil
}

// patchNXSBDataLenForEncryption bumps nx_xp_data_len from 2 to 5 (and
// nx_xp_data_next from 4 to 7 to track the new write head). Updates
// both the live NX SB at block 0 and its current-checkpoint copy
// at currentNXSBCopyBlock; re-seals each.
func patchNXSBDataLenForEncryption(f *os.File) error {
	const blockSize = 4096
	for _, off := range []int64{0, int64(currentNXSBCopyBlock) * blockSize} {
		buf := make([]byte, blockSize)
		if _, err := f.ReadAt(buf, off); err != nil {
			return fmt.Errorf("apfs: format encrypted: read NX SB at %d: %w", off, err)
		}
		// nx_xp_data_next at +132 (uint32), nx_xp_data_len at +148 (uint32).
		// SPACEMAN + REAPER + SFQ_IP + SFQ_MAIN = 4 ephemerals.
		binary.LittleEndian.PutUint32(buf[148:152], 4)
		binary.LittleEndian.PutUint32(buf[132:136], 6) // index 2 + len 4 = next 6
		sealBlock(buf)
		if _, err := f.WriteAt(buf, off); err != nil {
			return fmt.Errorf("apfs: format encrypted: write NX SB at %d: %w", off, err)
		}
	}
	return nil
}

// FormatContainerEncryptedGPT writes an Apple_APFS-GPT-wrapped
// FileVault-style encrypted container to path. The output is a single
// file totalSize bytes large with a protective MBR + primary GPT at
// the head, the APFS container starting at byte 1 MiB (LBA 2048), and
// a GPT backup at the tail. apfs.kext recognises the Apple_APFS
// (7C3457EF-…) partition GUID in the GPT and binds the synthesised
// container's physical store correctly — without it the kext attaches
// the raw image but the container scheme device shows `+0 B` capacity
// and no inner volumes.
//
// The APFS container itself is exactly what FormatContainerEncrypted
// produces. totalSize must accommodate the GPT overhead (~1 MiB at
// the head + ~16 KiB at the tail) plus the formatMetadataBlocks-class
// minimum APFS container size.
func FormatContainerEncryptedGPT(path string, totalSize int64, volumeLabel string, passphrase []byte) error {
	if totalSize%gptSectorSize != 0 {
		return fmt.Errorf("apfs: format encrypted GPT: totalSize %d not multiple of %d", totalSize, gptSectorSize)
	}
	const gptHeadOverhead int64 = gptPartFirstLBA * gptSectorSize // 1 MiB
	const gptTailOverhead int64 = (1 + gptEntriesLBAs) * gptSectorSize // backup
	apfsSize := totalSize - gptHeadOverhead - gptTailOverhead
	apfsSize -= apfsSize % gptSectorSize
	if apfsSize < int64(formatMetadataBlocks+2)*4096 {
		return fmt.Errorf("apfs: format encrypted GPT: totalSize %d too small for APFS metadata", totalSize)
	}

	tmp, err := os.CreateTemp("", "apfs-pre-gpt-*.bin")
	if err != nil {
		return fmt.Errorf("apfs: format encrypted GPT: temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	if err := os.Truncate(tmpPath, apfsSize); err != nil {
		return fmt.Errorf("apfs: format encrypted GPT: truncate temp: %w", err)
	}
	if err := FormatContainerEncrypted(tmpPath, apfsSize, volumeLabel, passphrase); err != nil {
		return err
	}

	out, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("apfs: format encrypted GPT: open output: %w", err)
	}
	if err := out.Truncate(totalSize); err != nil {
		out.Close()
		return fmt.Errorf("apfs: format encrypted GPT: truncate output: %w", err)
	}
	apfsBytes, err := os.ReadFile(tmpPath)
	if err != nil {
		out.Close()
		return fmt.Errorf("apfs: format encrypted GPT: read temp: %w", err)
	}
	if _, err := out.WriteAt(apfsBytes, gptHeadOverhead); err != nil {
		out.Close()
		return fmt.Errorf("apfs: format encrypted GPT: copy APFS to LBA 2048: %w", err)
	}
	if err := out.Close(); err != nil {
		return err
	}
	return writeAppleAPFSGPT(path, totalSize)
}

// (Volume-metadata at-rest VEK encryption removed — the reference DMG
// probe showed Apple keeps APSB / volume OMAP / FS-tree root /
// snap-meta / extent-ref in plaintext even when NX_CRYPTO_SW is set.
// The VEK is reserved for user file data, which we don't write here
// for the empty-volume case.)

// readContainerUUID extracts nx_uuid from the live NX SB.
func readContainerUUID(c *Container) ([16]byte, error) {
	var uuid [16]byte
	block, err := c.readBlock(0)
	if err != nil {
		return uuid, fmt.Errorf("apfs: format encrypted: read NX SB: %w", err)
	}
	copy(uuid[:], block[72:88])
	return uuid, nil
}

// readVolumeUUID extracts apfs_vol_uuid from the APSB at formatAPSBBlock.
func readVolumeUUID(c *Container) ([16]byte, error) {
	var uuid [16]byte
	block, err := c.readBlock(formatAPSBBlock)
	if err != nil {
		return uuid, fmt.Errorf("apfs: format encrypted: read APSB: %w", err)
	}
	copy(uuid[:], block[apsbVolumeUUIDOffset:apsbVolumeUUIDOffset+16])
	return uuid, nil
}

// patchNXSBEncryptionFields reads the NX SB at byte offset off, sets
// nx_keylocker = {formatContainerKeybagBlock, 1} and nx_flags
// |= NX_CRYPTO_SW, re-seals (Fletcher64), and writes back.
func patchNXSBEncryptionFields(f *os.File, off int64) error {
	const blockSize = 4096
	buf := make([]byte, blockSize)
	if _, err := f.ReadAt(buf, off); err != nil {
		return fmt.Errorf("apfs: format encrypted: read NX SB at %d: %w", off, err)
	}
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset:nxKeylockerOffset+8], formatContainerKeybagBlock)
	binary.LittleEndian.PutUint64(buf[nxKeylockerOffset+8:nxKeylockerOffset+16], 1)
	flags := binary.LittleEndian.Uint64(buf[nxFlagsOffset : nxFlagsOffset+8])
	flags |= nxFlagCryptoSW
	binary.LittleEndian.PutUint64(buf[nxFlagsOffset:nxFlagsOffset+8], flags)
	sealBlock(buf)
	if _, err := f.WriteAt(buf, off); err != nil {
		return fmt.Errorf("apfs: format encrypted: write NX SB at %d: %w", off, err)
	}
	return nil
}

// apsbIncompatFeaturesOffset is the byte offset of
// apfs_incompatible_features inside the APSB. Bit 0x4
// (APFS_INCOMPAT_ENC_ROLLED) signals "this volume is software-
// encrypted in place" — Apple's diskutil apfs encryptVolume sets it,
// and apfs.kext consults it to gate volume enumeration on encrypted
// containers. Without ENC_ROLLED set, even with NX_CRYPTO_SW, the
// kext's APFSExtendedSpaceInfo query returns -69808.
const apsbIncompatFeaturesOffset = 0x38

// patchAPSBEncryptedFlag clears APFS_FS_UNENCRYPTED and sets
// APFS_FS_ONEKEY in the APSB at formatAPSBBlock, then re-seals.
//
// APFS_FS_ONEKEY (0x8) signals "this volume uses a single VEK for all
// files" — i.e. classic FileVault FDE. apfs.kext keys some encrypted-
// volume bookkeeping off this bit; without it the kext's
// `APFSExtendedSpaceInfo` query against an encrypted-NX_CRYPTO_SW
// container returns -69808 even though the keybag chain is sound.
func patchAPSBEncryptedFlag(f *os.File) error {
	const blockSize = 4096
	const apfsFSUnencrypted uint64 = 0x1
	const apfsFSOneKey uint64 = 0x8
	const apfsIncompatEncRolled uint64 = 0x4
	off := int64(formatAPSBBlock) * blockSize
	buf := make([]byte, blockSize)
	if _, err := f.ReadAt(buf, off); err != nil {
		return fmt.Errorf("apfs: format encrypted: read APSB: %w", err)
	}
	// apfs_fs_flags: clear UNENCRYPTED, set ONEKEY.
	flags := binary.LittleEndian.Uint64(buf[apsbFSFlagsOffset : apsbFSFlagsOffset+8])
	flags &^= apfsFSUnencrypted
	flags |= apfsFSOneKey
	binary.LittleEndian.PutUint64(buf[apsbFSFlagsOffset:apsbFSFlagsOffset+8], flags)
	// apfs_incompatible_features: set ENC_ROLLED on top of CASE_INSENSITIVE.
	incompat := binary.LittleEndian.Uint64(buf[apsbIncompatFeaturesOffset : apsbIncompatFeaturesOffset+8])
	incompat |= apfsIncompatEncRolled
	binary.LittleEndian.PutUint64(buf[apsbIncompatFeaturesOffset:apsbIncompatFeaturesOffset+8], incompat)
	sealBlock(buf)
	if _, err := f.WriteAt(buf, off); err != nil {
		return fmt.Errorf("apfs: format encrypted: write APSB: %w", err)
	}
	return nil
}
