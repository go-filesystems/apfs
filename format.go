package filesystem_apfs

// format.go writes a fresh, empty APFS container to disk in a layout
// that the read-only parser (OpenContainer, ListInodes, OpenVolume, ...) can
// open round-trip.
//
// This is iteration "D" of the read/write roadmap: no mutation of an
// existing volume, no space manager, no checkpoint cascade — just
// emitting every required structure once with sensible defaults so we
// have a reproducible starting point for the more elaborate write paths
// that follow.
//
// Block layout produced by FormatContainer (4 KiB blocks):
//
//	block 0   NX SuperBlock                    (omap_oid = 1, fs_oid = [100])
//	block 1   container OMAP header
//	block 2   container OMAP B-tree leaf       (oid 100 → block 3 APSB)
//	block 3   APSB                             (omap = 4, root_tree_oid = 200,
//	                                            snap_meta_tree_oid = 300)
//	block 4   volume OMAP header
//	block 5   volume OMAP B-tree leaf          (oid 200 → block 6,
//	                                            oid 300 → block 7)
//	block 6   FS-tree root (empty leaf)
//	block 7   snap_meta tree root (empty leaf)
//	block 8+  unused (zeroed; available for future allocators)

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// Default OIDs assigned to the metadata objects of a freshly-formatted
// container. fsck_apfs reserves the OID range < 1024 for system use
// and rejects nx_fs_oid entries below that threshold; we therefore
// pick values above 1024 for every user-visible object.
//
// Layout matches mkapfs (linux-apfs/apfsprogs):
//
//	1024  SPACEMAN_OID            (defaultSpacemanOID)
//	1025  REAPER_OID              (defaultReaperOID)
//	1026  FIRST_VOL_OID           (defaultAPSBOID)
//	1027  FIRST_VOL_CAT_ROOT_OID  (defaultFSTreeRootOID)
//	1028  IP_FREE_QUEUE_OID       (defaultFQIPTreeOID)
//	1029  MAIN_FREE_QUEUE_OID     (defaultFQMainTreeOID)
//	1030  snap-meta tree (our extension; mkapfs stores this physically)
const (
	defaultAPSBOID         uint64 = 1026
	defaultFSTreeRootOID   uint64 = 1027
	defaultSnapMetaTreeOID uint64 = 1030
	// Default object xid for the metadata that lives outside the
	// checkpoint data area (OMAP, APSB, FS-tree root, …). For APFS,
	// `o_xid` records the LAST checkpoint in which the object was
	// modified, not the most recent checkpoint that references it. We
	// set up these objects during the initial checkpoint and leave
	// them unchanged by the current checkpoint, so their o_xid stays
	// at formatInitialXID. fsck_apfs rejects o_xid > checkpoint_xid
	// (it would mean the object came from a future transaction);
	// this rule kicks in when the initial checkpoint walks the OMAP
	// and finds a block with a too-new xid.
	defaultFormatXID uint64 = formatInitialXID
)

// Block addresses of the metadata objects inside a freshly-formatted
// container.
//
// Apple's APFS reference and fsck_apfs require a checkpoint descriptor
// area of at least 8 blocks and a checkpoint data area of at least 8
// blocks. Both must be contiguous regions whose start blocks are
// recorded in the NX superblock (xp_desc_base, xp_data_base) along
// with their lengths and the index of the most recent valid
// checkpoint within them.
//
// The descriptor area holds alternating CheckpointMapPhys + NX SB
// copies. Each checkpoint contributes two slots; the freshly-formatted
// container records one checkpoint, so xp_desc_index = 0 and
// xp_desc_len = 2 (one CheckpointMap at slot 0, one NX SB copy at
// slot 1).
//
// Layout produced (each row is one 4096-byte block).
//
// Iteration D-6: dual-checkpoint init mirroring `newfs_apfs`. fsck_apfs
// rejects single-checkpoint containers with the opaque
// `checkpoint failed consistency check` message; matching Apple's
// two-step bootstrap closes that gap. Layout reverse-engineered from
// `hdiutil create -fs APFS` byte dumps.
//
//	block 0          NX SuperBlock (live; refers to checkpoint 2)
//	blocks 1..8      checkpoint descriptor area (xp_desc_base=1, blocks=8)
//	  block 1        CheckpointMap, xid=1 (initial: SPACEMAN + REAPER)
//	  block 2        NX SuperBlock copy, xid=1 (initial)
//	  block 3        CheckpointMap, xid=2 (current: SPACEMAN + REAPER + FQ_IP + FQ_MAIN)
//	  block 4        NX SuperBlock copy, xid=2 (current; byte-equal to block 0)
//	  blocks 5..8    reserved for future checkpoints (zero)
//	blocks 9..60     checkpoint data area (xp_data_base=9, blocks=52)
//	  block 9        SPACEMAN, xid=1 (initial — sm_fq[*].sfq_tree_oid = 0)
//	  block 10       REAPER, xid=1 (initial)
//	  block 11       SPACEMAN, xid=2 (current — full sm_fq with FQ tree refs)
//	  block 12       REAPER, xid=2 (current)
//	  block 13       FQ_IP free-queue B-tree root, xid=2
//	  block 14       FQ_MAIN free-queue B-tree root, xid=2
//	  blocks 15..60  unused (zero)
//	block 61         container OMAP
//	block 62         container OMAP B-tree leaf
//	block 63         APSB
//	block 64         volume OMAP
//	block 65         volume OMAP B-tree leaf
//	block 66         FS-tree root (empty leaf)
//	block 67         snap_meta tree root (empty leaf)
//	blocks 68..83    16 IP bitmap blocks (sm_ip_bm_base)
//	blocks 84..89    6 IP blocks (sm_ip_base): bitmap, CIB, scratch
const (
	formatXPDescBase             uint64 = 1
	formatXPDescBlocks           uint64 = 8
	formatXPDataBase             uint64 = 9
	formatXPDataBlocks           uint64 = 52
	formatContainerOmapBlock     uint64 = 61
	formatContainerOmapTreeBlock uint64 = 62
	formatAPSBBlock              uint64 = 63
	formatVolumeOmapBlock        uint64 = 64
	formatVolumeOmapTreeBlock    uint64 = 65
	formatFSTreeRootBlock        uint64 = 66 // VIRTUAL, in volume OMAP
	formatSnapMetaTreeRootBlock  uint64 = 67 // PHYSICAL, apfs_snap_meta_tree_oid = paddr
	formatExtentRefTreeBlock     uint64 = 68 // PHYSICAL, apfs_extentref_tree_oid = paddr
	formatIPBitmapBase           uint64 = 69 // IP_BMAP_BASE
	formatIPBitmapCount          uint64 = 16 // ip_bm_size * SPACEMAN_IP_BM_TX_MULTIPLIER
	formatIPBase                 uint64 = 85 // IP_BMAP_BASE + ip_bmap_blocks
	formatIPBlocks               uint64 = 6  // (chunk_count + cib_count + cab_count) * 3
	formatBitmapBlock            uint64 = 85 // ip_base + 0 (first chunk's allocation bitmap)
	formatCIBBlock               uint64 = 86 // ip_base + 1 (chunk-info block)
	formatMetadataBlocks                = 91 // formatIPBase + formatIPBlocks

	// Two-checkpoint xids. fsck_apfs reads the most recent (xid=2).
	formatInitialXID uint64 = 1
	formatCurrentXID uint64 = 2
)

// objTypeCheckpointMap is the obj_phys_t.o_type low-half value for a
// CheckpointMapPhys block. Apple's apfs.h defines it as 0x0C.
const objTypeCheckpointMap uint16 = 0x000C

// Ephemeral OIDs for the format checkpoint. Cross-referenced against
// apfs-fuse DiskStruct.h (object types) and against an Apple reference
// container (sm_fq[].sfq_tree_oid points at ephemeral B-tree nodes
// holding the free-queue records). fsck_apfs verifies that
// nx_spaceman_oid / nx_reaper_oid resolve to objects of the right
// type, and that every sm_fq[].sfq_tree_oid is listed in the
// checkpoint mapping.
const (
	defaultSpacemanOID   uint64 = 1024
	defaultReaperOID     uint64 = 1025
	defaultFQIPTreeOID   uint64 = 1028 // sm_fq[SFQ_IP].sfq_tree_oid
	defaultFQMainTreeOID uint64 = 1029 // sm_fq[SFQ_MAIN].sfq_tree_oid
)

// Object-type values from apfs-fuse DiskStruct.h (verified against the
// Apple-produced reference container).
const (
	objTypeReaper                 uint16 = 0x0011
	objTypeChunkInfoBlock         uint16 = 0x0007
	objTypeSpacemanBitmap         uint16 = 0x0008
	objTypeSpacemanFreeQueue      uint16 = 0x0009
	objSubtypeSpacemanFreeQueue   uint32 = uint32(objTypeSpacemanFreeQueue)
)

// Spaceman field offsets within spaceman_phys_t. Field offsets are
// derived from apfs-fuse DiskStruct.h / linux-apfs apfs_raw.h.
//
// The fixed part of spaceman_phys_t is 2520 bytes (Apple's
// sm_struct_size). It includes sm_datazone (a 2176-byte tail of
// allocation-zone history that's all-zero on a freshly-formatted
// volume). The variable-length IP arrays + cib_addr lists begin at
// sm_struct_size = 2520.
//
// We match Apple's "versioned" layout exactly:
//
//   sm_version                = 1                                 (offset 0x150)
//   sm_struct_size            = spacemanFixedSize = 2520          (offset 0x154)
//   sm_ip_bm_xid_offset       = spacemanIPBitmapXIDOffset  = 2520
//   sm_ip_bitmap_offset       = spacemanIPBitmapAddrOffset = 2528
//   sm_ip_bm_free_next_offset = spacemanIPBmFreeNextOffset= 2536
//   sm_dev[0].sm_addr_offset  = spacemanCIBAddrBaseOffset = 2568
//   sm_dev[1].sm_addr_offset  = spacemanCIBAddrBaseOffset+8       (Apple sets it even
//                                                                  with no tier-2 device)
//
// `mkapfs` overlaps the IP arrays inside sm_datazone (offsets 336/344/
// 352/384) and leaves sm_version=0 — that's a separate "non-versioned"
// dialect that the kext refuses for extended-space queries (the
// `_DMAPFSSizeStateForContainerReference` path returns -69620 against
// sm_flags=0 / sm_version=0 spacemen).
const (
	spacemanFreeQueueSize  = 40 // spaceman_free_queue_t bytes
	spacemanDeviceSize     = 48 // spaceman_device_t bytes
	spacemanFQOffset       = 200 // start of sm_fq[0]

	// Fixed-header size: the spaceman struct ends here and the variable-
	// length IP arrays + cib_addr lists begin. Apple's value is 2520.
	spacemanFixedSize             = 2520
	spacemanIPBitmapXIDOffset     = spacemanFixedSize         // = 2520
	spacemanIPBitmapAddrOffset    = spacemanFixedSize + 8     // = 2528
	spacemanIPBmFreeNextOffset    = spacemanFixedSize + 16    // = 2536
	spacemanCIBAddrBaseOffset     = spacemanFixedSize + 48    // = 2568

	// Versioned-spaceman fields.
	spacemanVersionOffset    = 0x150
	spacemanStructSizeOffset = 0x154
	spacemanVersion          = 1
	// APFS_SM_FLAG_VERSIONED — set in sm_flags at offset 0x90.
	spacemanFlagVersioned uint32 = 0x1

	spacemanIPBMIndexInvalid uint16 = 0xFFFF
)

// objTypeBitmap covers spaceman allocation-bitmap blocks. Apple's
// APFS bitmap convention: BIT SET = block is allocated. We mark bits
// 0..formatMetadataBlocks-1 = 1 (used) and the rest = 0 (free).

// FormatContainer writes a fresh, empty APFS container to the file at path.
// The file must already exist and be at least formatMetadataBlocks * 4 KiB
// in size; FormatContainer writes the metadata blocks at offsets 0 through
// (formatMetadataBlocks-1) * 4096 and leaves the remainder zeroed.
//
// The returned container is the layout described in the package-level
// comment of format.go. Open the file with OpenContainer to verify
// it is a valid APFS volume; ListInodes will return an empty slice and
// ListSnapshots a nil slice.
func FormatContainer(path string, sizeBytes int64, volumeLabel string) error {
	const block = 4096
	if sizeBytes < int64(formatMetadataBlocks)*block {
		return fmt.Errorf("apfs: format: size %d bytes is too small (need at least %d for metadata)", sizeBytes, int64(formatMetadataBlocks)*block)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("apfs: format: open %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Truncate(sizeBytes); err != nil {
		return fmt.Errorf("apfs: format: truncate: %w", err)
	}
	totalBlocks := uint64(sizeBytes / block)
	blocks := buildEmptyContainerBlocks(volumeLabel, totalBlocks)
	for i, b := range blocks {
		if _, err := f.WriteAt(b, int64(i)*block); err != nil {
			return fmt.Errorf("apfs: format: write block %d: %w", i, err)
		}
	}
	return nil
}

// buildEmptyContainerBlocks assembles the formatMetadataBlocks blocks of
// metadata an empty container needs. Returned blocks are 4096 bytes
// each with their Fletcher64 checksums populated, so they are
// byte-identical to what fsck_apfs expects on disk.
//
// Two checkpoints are emitted (matching `newfs_apfs`):
//
//   - Initial checkpoint at desc[0..1] / data[0..1], xid=1.
//     Carries SPACEMAN+REAPER only. The spaceman has empty sm_fq[*]
//     entries (no FQ trees existed yet at this point).
//   - Current checkpoint at desc[2..3] / data[2..5], xid=2.
//     Carries SPACEMAN+REAPER+FQ_IP+FQ_MAIN. Block 0 is byte-equal to
//     the desc[3] copy.
//
// fsck_apfs picks the highest-xid valid checkpoint; everything outside
// the descriptor + data areas (OMAP, APSB, FS-tree roots, IP) is shared
// between checkpoints since those blocks are physical / virtual and
// don't change between xid=1 and xid=2 in our minimal init.
func buildEmptyContainerBlocks(volumeLabel string, totalBlocks uint64) [][]byte {
	out := make([][]byte, formatMetadataBlocks)
	for i := range out {
		out[i] = make([]byte, 4096)
	}
	// Generate the shared NX UUID once. Block 0 and both desc-area NX SB
	// copies reuse it so fsck_apfs's UUID cross-checks pass.
	initFormatNXUUID()
	// Block 0: live NX SB pointing at the CURRENT checkpoint (xid=2).
	encodeNXSuperblock(out[0], totalBlocks, formatCurrentXID)
	// Initial checkpoint (xid=1).
	encodeCheckpointMapInitial(out[initialCheckpointMapBlock])
	encodeNXSuperblock(out[initialNXSBCopyBlock], totalBlocks, formatInitialXID)
	encodeSpacemanInitial(out[initialSpacemanBlock], totalBlocks)
	encodeReaper(out[initialReaperBlock], formatInitialXID)
	// Current checkpoint (xid=2).
	encodeCheckpointMapCurrent(out[currentCheckpointMapBlock])
	// desc[3] NX SB copy = byte-identical to block 0 (same xid=2).
	copy(out[currentNXSBCopyBlock], out[0])
	encodeSpacemanCurrent(out[spacemanBlock], totalBlocks)
	encodeReaper(out[reaperBlock], formatCurrentXID)
	// Apple's newfs_apfs does NOT pre-emit FQ tree roots at format time
	// (sm_fq[*].sfq_tree_oid = 0 in the spaceman; CPM lists sm + reaper
	// only). Leave fqIPBlock / fqMainBlock zeroed — they're inside the
	// data area but outside the current checkpoint window
	// (nx_xp_data_len = 2, not 4). encodeFreeQueueTree is preserved for
	// the Commit path (which DOES allocate FQ trees as transactions free
	// blocks).
	encodeChunkInfoBlock(out[formatCIBBlock], totalBlocks)
	encodeOMAPPhys(out[formatContainerOmapBlock], formatContainerOmapBlock, formatContainerOmapTreeBlock, true /* isContainer */)
	encodeOMAPLeaf(out[formatContainerOmapTreeBlock], formatContainerOmapTreeBlock, []omapEntry{
		{oid: defaultAPSBOID, xid: defaultFormatXID, paddr: formatAPSBBlock},
	})
	encodeAPSB(out[formatAPSBBlock], volumeLabel)
	encodeOMAPPhys(out[formatVolumeOmapBlock], formatVolumeOmapBlock, formatVolumeOmapTreeBlock, false /* isContainer */)
	// Volume OMAP only resolves VIRTUAL trees. The snap-meta and
	// extentref trees are PHYSICAL per Apple's apfs_*_tree_type fields,
	// so they live at fixed block addresses and are NOT in the OMAP.
	encodeOMAPLeaf(out[formatVolumeOmapTreeBlock], formatVolumeOmapTreeBlock, []omapEntry{
		{oid: defaultFSTreeRootOID, xid: defaultFormatXID, paddr: formatFSTreeRootBlock},
	})
	// Populate the FS-tree root with the four canonical special-dir
	// records (root + private-dir inodes + their parent dentries) at
	// format time. Apple's `newfs_apfs` writes these eagerly via
	// `make_cat_root` and the kext's mount path looks them up before
	// anything else. An empty FS-tree mounts as fsck-clean but
	// `mount_apfs` returns EINVAL because oid=2 (root) cannot be
	// resolved — the kext cross-checks `apfs_root_tree_oid` against the
	// records inside the tree.
	if leaf, err := emitFSTreeLeaf(upsertRootDir(nil), 4096); err == nil {
		copy(out[formatFSTreeRootBlock], leaf)
	}
	encodeEmptyPhysicalBTree(out[formatSnapMetaTreeRootBlock], formatSnapMetaTreeRootBlock, objTypeSnapMetaTree)
	encodeEmptyPhysicalBTree(out[formatExtentRefTreeBlock], formatExtentRefTreeBlock, objTypeBlockRefTree)
	// Seal every block that has an obj header BEFORE the raw bitmap
	// data is written. Bitmap blocks (chunk-allocation bitmap +
	// IP bitmaps) carry no obj header — sealBlock would clobber
	// their first 8 bytes with a Fletcher64 cksum.
	for i := range out {
		if uint64(i) == formatBitmapBlock {
			continue
		}
		if uint64(i) >= formatIPBitmapBase && uint64(i) < formatIPBitmapBase+formatIPBitmapCount {
			continue
		}
		sealBlock(out[i])
	}
	encodeAllocationBitmap(out[formatBitmapBlock], totalBlocks)
	encodeIPBitmap(out[formatIPBitmapBase])
	return out
}

// omapEntry is a single (oid, xid, paddr) triple consumed by encodeOMAPLeaf.
type omapEntry struct {
	oid   uint64
	xid   uint64
	paddr uint64
}

// Storage-class flags packed in the high 16 bits of obj_phys_t.o_type.
// Apple uses these to tell readers how an object is addressed:
//
//   - VIRTUAL  (0x0): the o_oid field is a virtual oid that must be
//     resolved through an object map (OMAP) before reading.
//   - PHYSICAL (0x4000_0000): the o_oid field IS the block address.
//   - EPHEMERAL (0x8000_0000): the object is in memory between flushes;
//     on disk its current location is recorded in the checkpoint map.
//
// fsck_apfs rejects any object whose o_type field is missing the
// expected storage class. The format encoders below pass the right
// flag through encodeObjHeader.
const (
	objStorageVirtual   uint32 = 0x00000000
	objStoragePhysical  uint32 = 0x40000000
	objStorageEphemeral uint32 = 0x80000000
)

// encodeObjHeader writes the 32-byte obj_phys_t header that prefixes every
// APFS object. The first 8 bytes (the cksum slot) are left zero here —
// callers must invoke sealBlock once the rest of the block is fully
// populated to compute Apple's Fletcher64 over the trailing 4088 bytes
// and write it into those leading 8 bytes.
func encodeObjHeader(buf []byte, oid, xid uint64, typ uint16, subtype uint32, storageClass uint32) {
	binary.LittleEndian.PutUint64(buf[0:8], 0) // cksum (sealBlock fills this)
	binary.LittleEndian.PutUint64(buf[8:16], oid)
	binary.LittleEndian.PutUint64(buf[16:24], xid)
	binary.LittleEndian.PutUint32(buf[24:28], uint32(typ)|storageClass)
	binary.LittleEndian.PutUint32(buf[28:32], subtype)
}

// fletcher64 computes Apple's APFS object checksum. The implementation
// matches the algorithm in xnu's apfs/apfs_struct.h: the input is
// processed as little-endian uint32 quantities, two running sums are
// kept modulo 0xFFFFFFFF, and the returned value is constructed so
// that adding it back to the same input yields a zero-checksum.
//
// Pass the bytes of the block AFTER the cksum slot (i.e. block[8:]).
// sealBlock takes care of the slicing.
func fletcher64(buf []byte) uint64 {
	const mod = uint64(0xFFFFFFFF)
	var s1, s2 uint64
	for i := 0; i+4 <= len(buf); i += 4 {
		v := uint64(binary.LittleEndian.Uint32(buf[i : i+4]))
		s1 = (s1 + v) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - ((s1 + s2) % mod)
	c2 := mod - ((s1 + c1) % mod)
	return (c2 << 32) | c1
}

// sealBlock computes Fletcher64 over block[8:] and writes the result
// into block[:8]. Idempotent: if called twice, the second call simply
// recomputes the same checksum (the cksum slot was zeroed before the
// hash was taken in the first invocation, but at the point of the
// second invocation it carries the cksum from the first; we therefore
// re-zero the slot before hashing).
func sealBlock(block []byte) {
	for i := 0; i < 8; i++ {
		block[i] = 0
	}
	cksum := fletcher64(block[8:])
	binary.LittleEndian.PutUint64(block[0:8], cksum)
}

// nxSuperblockOID is the well-known oid Apple assigns to the NX
// superblock at block 0. fsck_apfs validates that o_oid matches.
const nxSuperblockOID uint64 = 1

// formatNXUUID is generated once per FormatContainer call and shared
// between the live NX SB at block 0 and both NX SB copies in the
// descriptor area. fsck_apfs cross-checks UUIDs between these copies
// and rejects mismatches.
var formatNXUUID [16]byte

// formatRandReadFn is the crypto-rand entry point used by
// initFormatNXUUID and apsbRandFill below. Tests override it to
// exercise the failure-fallback branches.
var formatRandReadFn = rand.Read

// initFormatNXUUID seeds the shared NX UUID with crypto/rand. Called
// once at the start of buildEmptyContainerBlocks.
func initFormatNXUUID() {
	if _, err := formatRandReadFn(formatNXUUID[:]); err != nil {
		// crypto/rand only fails when the OS RNG is unavailable; the
		// resulting all-zero UUID will trip fsck's not-all-zero check
		// but at least Format won't panic.
		_ = err
	}
}

// encodeNXSuperblock fills an NX SuperBlock referencing the checkpoint
// at xid `forXID`. The same encoder is used for:
//
//   - block 0 (live NX SB; pass forXID = formatCurrentXID)
//   - desc[1] NX SB copy for the initial checkpoint (forXID = formatInitialXID)
//   - desc[3] NX SB copy for the current checkpoint — emitted by
//     `copy(out[currentNXSBCopyBlock], out[0])` in buildEmptyContainerBlocks
//     since it is byte-identical to block 0 except for its position.
//
// Field values that depend on which checkpoint we are describing:
//
//   - o_xid = forXID
//   - xp_desc_index, xp_data_index = start slot of THIS checkpoint
//   - xp_desc_len, xp_data_len     = blocks consumed by THIS checkpoint
//   - xp_desc_next, xp_data_next   = first slot AFTER THIS checkpoint
//   - nx_next_xid = forXID + 1
//
// The Fletcher64 cksum is filled by sealBlock, called from
// buildEmptyContainerBlocks AFTER every other field is populated.
func encodeNXSuperblock(block []byte, totalBlocks uint64, forXID uint64) {
	encodeObjHeader(block, nxSuperblockOID, forXID, objTypeNXSuperblock, 0, objStorageEphemeral)
	copy(block[32:36], nxMagicASCII) // "NXSB"
	binary.LittleEndian.PutUint32(block[36:40], 4096)
	binary.LittleEndian.PutUint64(block[40:48], totalBlocks)
	// nx_features (48..56) / nx_readonly_compatible_features (56..64):
	// stay zero — we implement none of the optional features.
	// nx_incompatible_features (64..72): mkapfs sets bit 1
	// (APFS_NX_INCOMPAT_VERSION2). Apple's apfs.kext only mounts
	// containers that advertise version 2.
	const apfsNXIncompatVersion2 uint64 = 0x2
	binary.LittleEndian.PutUint64(block[64:72], apfsNXIncompatVersion2)
	// nx_uuid (72..88): SAME UUID across block 0 and both desc-area
	// NX SB copies. fsck_apfs's "checkpoint<->X mismatch on uuid" check
	// rejects per-block randomness.
	copy(block[72:88], formatNXUUID[:])
	// nx_next_oid: must exceed every oid used by the format. mkapfs
	// uses APFS_OID_RESERVED_COUNT + 100 = 1124 — well above our
	// 1024..1030 fixed-OID block.
	binary.LittleEndian.PutUint64(block[88:96], 1124)
	// nx_next_xid = current xid + 1.
	binary.LittleEndian.PutUint64(block[96:104], forXID+1)
	// Checkpoint descriptor / data area sizes and base addresses.
	binary.LittleEndian.PutUint32(block[104:108], uint32(formatXPDescBlocks))
	binary.LittleEndian.PutUint32(block[108:112], uint32(formatXPDataBlocks))
	binary.LittleEndian.PutUint64(block[112:120], formatXPDescBase)
	binary.LittleEndian.PutUint64(block[120:128], formatXPDataBase)
	// Per Apple's apfs.h, the field order after xp_desc_base/xp_data_base
	// is: xp_desc_next, xp_data_next, xp_desc_index, xp_desc_len,
	// xp_data_index, xp_data_len.
	//
	// xid=1 (initial): index=0, len=2 (sm+reaper), next=2 in desc;
	//                  index=0, len=2, next=2 in data.
	// xid=2 (current): index=2, len=2 (sm+reaper),  next=4 in desc;
	//                  index=2, len=4 (sm+reaper+fq+fq), next=6 in data.
	var (
		descIndex, descLen, descNext uint32
		dataIndex, dataLen, dataNext uint32
	)
	switch forXID {
	case formatInitialXID:
		descIndex, descLen, descNext = 0, 2, 2
		dataIndex, dataLen, dataNext = 0, 2, 2
	case formatCurrentXID:
		// Apple's newfs_apfs writes only SPACEMAN + REAPER in the data
		// area (no FQ trees at format time) → data_len = 2.
		descIndex, descLen, descNext = 2, 2, 4
		dataIndex, dataLen, dataNext = 2, 2, 4
	default:
		// Other xids fall through to the current-checkpoint window;
		// callers should only pass formatInitialXID or formatCurrentXID.
		descIndex, descLen, descNext = 2, 2, 4
		dataIndex, dataLen, dataNext = 2, 2, 4
	}
	binary.LittleEndian.PutUint32(block[128:132], descNext)
	binary.LittleEndian.PutUint32(block[132:136], dataNext)
	binary.LittleEndian.PutUint32(block[136:140], descIndex)
	binary.LittleEndian.PutUint32(block[140:144], descLen)
	binary.LittleEndian.PutUint32(block[144:148], dataIndex)
	binary.LittleEndian.PutUint32(block[148:152], dataLen)
	// nx_spaceman_oid / nx_omap_oid / nx_reaper_oid (152..175).
	binary.LittleEndian.PutUint64(block[152:160], defaultSpacemanOID)
	binary.LittleEndian.PutUint64(block[160:168], formatContainerOmapBlock)
	binary.LittleEndian.PutUint64(block[168:176], defaultReaperOID)
	// nx_max_file_systems (180..183): up to 100 volumes (Apple's max).
	// fsck caps the fs_oid array at this value when enumerating volumes,
	// so a value of 1 here would force a single-volume layout. Setting
	// to 100 (NX_MAX_FILE_SYSTEMS) lets `Container.AddVolume` populate
	// fs_oid[1..N-1] without re-emitting the NX SB.
	binary.LittleEndian.PutUint32(block[180:184], 100)
	// fs_oid array starts at byte 184; we list one volume.
	binary.LittleEndian.PutUint64(block[184:192], defaultAPSBOID)
	// nx_ephemeral_info[0] at byte 1312: version=1, structures=4, blocks=1.
	const ephVersion uint64 = 1
	const ephStructsPerFS uint64 = 4
	const ephMinBlocks uint64 = 1
	binary.LittleEndian.PutUint64(block[1312:1320],
		ephVersion|(ephStructsPerFS<<16)|(ephMinBlocks<<32))
	// nx_counters[0] at byte 0x3D8 (uint64 LE): Apple writes a non-zero
	// baseline here on every newfs_apfs output. apfs.kext may treat an
	// all-zero counters array as "never written / never mounted" and
	// refuse to bind the synthesized container's volumes.
	binary.LittleEndian.PutUint64(block[0x3D8:0x3E0], 0x18)
	// nx_newest_mounted_version at byte 0x568 (uint64 LE): the macOS
	// version code of the newest kernel that mounted this container.
	// Apple's `hdiutil create -fs APFS` populates this with the running
	// kernel's version stamp; a zero value flags "never mounted" and
	// apfs.kext appears to skip auto-binding such containers.
	binary.LittleEndian.PutUint64(block[0x568:0x570], 0x000959DCE17AE241)
}

// encodeCheckpointMap writes a CheckpointMapPhys block. The freshly-
// formatted container records exactly one ephemeral object (the
// spaceman stub at xp_data_base); the map therefore carries one
// mapping entry and the CHECKPOINT_MAP_LAST flag identifying this
// checkpoint as the current terminator of the chain.
//
// Layout of the block (matches Apple's checkpoint_map_phys_t):
//
//	+0    obj_phys_t (32 bytes; storage class = ephemeral)
//	+32   uint32 cpm_flags    (CHECKPOINT_MAP_LAST = 1)
//	+36   uint32 cpm_count
//	+40   checkpoint_mapping[cpm_count] (40 bytes each)
//
// Each checkpoint_mapping is:
//
//	+0    uint32 cpm_type     (object type with storage class)
//	+4    uint32 cpm_subtype
//	+8    uint32 cpm_size     (block size, typically 4096)
//	+12   uint32 cpm_pad
//	+16   oid_t  cpm_fs_oid   (0 for container-level objects)
//	+24   oid_t  cpm_oid      (the ephemeral object's virtual oid)
//	+32   oid_t  cpm_paddr    (the data-area block holding the object)
// Data-area block addresses for ephemeral objects across BOTH
// checkpoints. Apple's newfs_apfs uses SPACEMAN-first ordering (mkapfs
// uses REAPER-first); we follow Apple here since fsck_apfs is the
// validator we are matching.
//
// Initial checkpoint (xid=1) data — only the bare-minimum ephemerals
// needed for a container to exist (no FQ trees yet):
//
//	formatXPDataBase + 0  → SPACEMAN (xid=1, sm_fq[*].sfq_tree_oid = 0)
//	formatXPDataBase + 1  → REAPER   (xid=1)
//
// Current checkpoint (xid=2) data — full ephemeral set:
//
//	formatXPDataBase + 2  → SPACEMAN (xid=2, full sm_fq with FQ tree refs)
//	formatXPDataBase + 3  → REAPER   (xid=2)
//	formatXPDataBase + 4  → FQ_IP B-tree root (xid=2)
//	formatXPDataBase + 5  → FQ_MAIN B-tree root (xid=2)
//
// Block 0's NX SB (and its desc[3] copy) reference the CURRENT
// checkpoint's ephemerals via cpm_paddr.
const (
	initialSpacemanBlock = formatXPDataBase     // data[0]
	initialReaperBlock   = formatXPDataBase + 1 // data[1]
	spacemanBlock        = formatXPDataBase + 2 // data[2] — current
	reaperBlock          = formatXPDataBase + 3 // data[3] — current
	fqIPBlock            = formatXPDataBase + 4 // data[4] — current
	fqMainBlock          = formatXPDataBase + 5 // data[5] — current
)

// Descriptor-area block addresses. The two checkpoints occupy desc[0..1]
// (initial) and desc[2..3] (current); block 0's NX SB points at the
// current one via xp_desc_index = 2.
const (
	initialCheckpointMapBlock = formatXPDescBase     // desc[0]
	initialNXSBCopyBlock      = formatXPDescBase + 1 // desc[1]
	currentCheckpointMapBlock = formatXPDescBase + 2 // desc[2]
	currentNXSBCopyBlock      = formatXPDescBase + 3 // desc[3]
)

// writeCheckpointMapping writes one 40-byte checkpoint_mapping_t entry.
func writeCheckpointMapping(block []byte, off int, typ uint32, subtype uint32, oid, paddr uint64) {
	binary.LittleEndian.PutUint32(block[off:off+4], typ)
	binary.LittleEndian.PutUint32(block[off+4:off+8], subtype)
	binary.LittleEndian.PutUint32(block[off+8:off+12], 4096) // cpm_size
	binary.LittleEndian.PutUint32(block[off+12:off+16], 0)   // cpm_pad
	binary.LittleEndian.PutUint64(block[off+16:off+24], 0)   // cpm_fs_oid
	binary.LittleEndian.PutUint64(block[off+24:off+32], oid)
	binary.LittleEndian.PutUint64(block[off+32:off+40], paddr)
}

// encodeCheckpointMapInitial writes the CheckpointMapPhys for the
// initial (xid=1) bootstrap checkpoint. Apple's newfs_apfs starts a
// container with only SPACEMAN and REAPER and adds the free-queue
// trees in the next checkpoint; we mirror that here.
//
// The block is at desc[0] = initialCheckpointMapBlock with o_oid =
// initialCheckpointMapBlock (CheckpointMaps are PHYSICAL).
func encodeCheckpointMapInitial(block []byte) {
	const cpmFlagLast uint32 = 0x00000001
	encodeObjHeader(block, initialCheckpointMapBlock, formatInitialXID, objTypeCheckpointMap, 0, objStoragePhysical)
	off := objPhysSize
	binary.LittleEndian.PutUint32(block[off:off+4], cpmFlagLast)
	binary.LittleEndian.PutUint32(block[off+4:off+8], 2) // cpm_count = 2
	base := off + 8
	writeCheckpointMapping(block, base+0*40,
		objStorageEphemeral|uint32(objTypeSpaceman), 0,
		defaultSpacemanOID, initialSpacemanBlock)
	writeCheckpointMapping(block, base+1*40,
		objStorageEphemeral|uint32(objTypeReaper), 0,
		defaultReaperOID, initialReaperBlock)
}

// encodeCheckpointMapCurrent writes the CheckpointMapPhys for the
// current (xid=2) checkpoint with two ephemerals: SPACEMAN and REAPER.
// Apple's newfs_apfs does NOT create the spaceman free-queue B-tree
// roots at format time — sm_fq[*].sfq_tree_oid stays 0 and the trees
// are lazily created on first allocation. fsck_apfs accepts the
// no-FQ-trees layout because it only validates trees that are actually
// referenced.
//
// The block is at desc[2] = currentCheckpointMapBlock; physical storage
// class so o_oid = its own paddr.
func encodeCheckpointMapCurrent(block []byte) {
	const cpmFlagLast uint32 = 0x00000001
	encodeObjHeader(block, currentCheckpointMapBlock, formatCurrentXID, objTypeCheckpointMap, 0, objStoragePhysical)
	off := objPhysSize
	binary.LittleEndian.PutUint32(block[off:off+4], cpmFlagLast)
	binary.LittleEndian.PutUint32(block[off+4:off+8], 2) // cpm_count = 2
	base := off + 8
	writeCheckpointMapping(block, base+0*40,
		objStorageEphemeral|uint32(objTypeSpaceman), 0,
		defaultSpacemanOID, spacemanBlock)
	writeCheckpointMapping(block, base+1*40,
		objStorageEphemeral|uint32(objTypeReaper), 0,
		defaultReaperOID, reaperBlock)
}

// encodeReaperStub writes a minimum-viable nx_reaper_phys block matching
// mkapfs's make_empty_reaper. The reaper tracks deferred deletion of
// large objects; a freshly-formatted container has nothing to reap, so
// nr_completed_id / nr_head / nr_tail / nr_*_id all stay zero. fsck_apfs
// rejects nr_flags == 0 (no APFS_NR_BHM_FLAG) and nr_next_reap_id == 0,
// so we initialize both with the values mkapfs writes.
//
// Layout (apfs_nx_reaper_phys, offsets in bytes from the obj header):
//
//	+32  nr_next_reap_id         (8)  must be ≥ 1
//	+40  nr_completed_id         (8)
//	+48  nr_head                 (8)
//	+56  nr_tail                 (8)
//	+64  nr_flags                (4)  APFS_NR_BHM_FLAG = 0x1
//	+68  nr_rlcount              (4)
//	+72  nr_type                 (4)
//	+76  nr_size                 (4)
//	+80  nr_fs_oid               (8)
//	+88  nr_oid                  (8)
//	+96  nr_xid                  (8)
//	+104 nr_nrle_flags           (4)
//	+108 nr_state_buffer_size    (4)  block_size - sizeof(reaper) = 3984
//	+112 nr_state_buffer[]       (variable)
func encodeReaper(block []byte, xid uint64) {
	encodeObjHeader(block, defaultReaperOID, xid, objTypeReaper, 0, objStorageEphemeral)
	const apfsNRBhmFlag uint32 = 0x00000001
	const reaperFixedSize = 112
	binary.LittleEndian.PutUint64(block[32:40], 1)                                     // nr_next_reap_id
	binary.LittleEndian.PutUint32(block[64:68], apfsNRBhmFlag)                         // nr_flags
	binary.LittleEndian.PutUint32(block[108:112], uint32(len(block)-reaperFixedSize)) // nr_state_buffer_size
}

// encodeSpacemanCurrent writes the current-checkpoint (xid=2) spaceman
// block. It carries full sm_fq[*].sfq_tree_oid references to the
// FQ_IP / FQ_MAIN B-tree roots emitted at fqIPBlock / fqMainBlock.
func encodeSpacemanCurrent(block []byte, totalBlocks uint64) {
	encodeSpacemanCommon(block, totalBlocks, formatCurrentXID, true)
}

// encodeSpacemanInitial writes the initial-checkpoint (xid=1) spaceman
// block. The Internal Pool layout is identical (the IP doesn't change
// between checkpoints in our minimal init), but sm_fq[*].sfq_tree_oid
// is left zero — those B-trees do not exist yet at xid=1.
func encodeSpacemanInitial(block []byte, totalBlocks uint64) {
	encodeSpacemanCommon(block, totalBlocks, formatInitialXID, false)
}

// encodeSpacemanCommon implements the shared body for both spaceman
// variants. The mkapfs/Apple-clean layout — sm_dev[0] tracking the one
// chunk that covers the volume, the spaceman Internal Pool descriptors,
// and the CIB-OID list at offset 384 — is identical between checkpoints.
//
// Only two things differ:
//
//   - the obj header's o_xid (passed in via xid)
//   - whether sm_fq[0..1] carry tree-OID references (fqRefs == true for
//     the current checkpoint, false for the bootstrap one)
//
// Layout cross-references:
//   - sm_dev[0] tracks the single chunk covering the whole volume:
//     ci_count = 1, cab_count = 0.
//   - sm_ip_* fields describe the IP: 16 bitmap blocks followed by 6 IP
//     blocks ((chunk_count + cib_count + cab_count) * 3 per mkapfs).
//   - The IP variable-length arrays (per-slot xid, current bitmap-addr,
//     free-next) live at mkapfs's offsets 336/344/352, overlapping the
//     unused sm_datazone area — both fsck_apfs and macOS accept this.
//   - The CIB-OID list lives at sm_dev[0].sm_addr_offset = 384.
func encodeSpacemanCommon(block []byte, totalBlocks uint64, xid uint64, fqRefs bool) {
	encodeObjHeader(block, defaultSpacemanOID, xid, objTypeSpaceman, 0, objStorageEphemeral)
	off := objPhysSize
	const blocksPerChunk uint32 = 32768
	const chunksPerCib uint32 = 126
	const cibsPerCab uint32 = 507
	binary.LittleEndian.PutUint32(block[off:off+4], 4096)
	binary.LittleEndian.PutUint32(block[off+4:off+8], blocksPerChunk)
	binary.LittleEndian.PutUint32(block[off+8:off+12], chunksPerCib)
	binary.LittleEndian.PutUint32(block[off+12:off+16], cibsPerCab)
	chunkCount := (totalBlocks + uint64(blocksPerChunk) - 1) / uint64(blocksPerChunk)
	cibCount := (chunkCount + uint64(chunksPerCib) - 1) / uint64(chunksPerCib)
	freeCount := totalBlocks - uint64(formatMetadataBlocks)
	dev := off + 16
	binary.LittleEndian.PutUint64(block[dev:dev+8], totalBlocks)
	binary.LittleEndian.PutUint64(block[dev+8:dev+16], chunkCount)
	binary.LittleEndian.PutUint32(block[dev+16:dev+20], uint32(cibCount))
	binary.LittleEndian.PutUint32(block[dev+20:dev+24], 0) // cab_count
	binary.LittleEndian.PutUint64(block[dev+24:dev+32], freeCount)
	binary.LittleEndian.PutUint32(block[dev+32:dev+36], spacemanCIBAddrBaseOffset)
	// sm_dev[1].sm_addr_offset is one __le64 past sm_dev[0]'s array.
	// Even though we have no tier-2 device, Apple still records the
	// offset so the kext can iterate sm_dev[] uniformly.
	binary.LittleEndian.PutUint32(block[0x60+32:0x60+36], spacemanCIBAddrBaseOffset+8)
	// sm_flags at offset 0x90: APFS_SM_FLAG_VERSIONED. Apple's
	// newfs_apfs always sets this; the kext rejects extended-space
	// queries on non-versioned spacemen.
	binary.LittleEndian.PutUint32(block[0x90:0x94], spacemanFlagVersioned)
	binary.LittleEndian.PutUint32(block[148:152], 16) // sm_ip_bm_tx_multiplier
	binary.LittleEndian.PutUint64(block[152:160], formatIPBlocks)
	binary.LittleEndian.PutUint32(block[160:164], 1)
	binary.LittleEndian.PutUint32(block[164:168], uint32(formatIPBitmapCount))
	binary.LittleEndian.PutUint64(block[168:176], formatIPBitmapBase)
	binary.LittleEndian.PutUint64(block[176:184], formatIPBase)
	// sm_fq[3] at offset 200 (40-byte entries). Apple's newfs_apfs leaves
	// every FQ tree_oid = 0 at format time (no FQ trees exist yet) but
	// sets sfq_tree_node_limit = 1 for sm_fq[0] (IP) and sm_fq[1] (MAIN).
	// fqRefs is preserved as a parameter for callers that DO want FQ
	// references (e.g. Commit after a transaction has populated trees),
	// but FormatContainer never sets it.
	_ = fqRefs
	fq0 := spacemanFQOffset + 0*spacemanFreeQueueSize
	binary.LittleEndian.PutUint16(block[fq0+24:fq0+26], 1) // sfq_tree_node_limit
	fq1 := spacemanFQOffset + 1*spacemanFreeQueueSize
	binary.LittleEndian.PutUint16(block[fq1+24:fq1+26], 1)
	// sm_ip_bm_free_head/_tail and the offset fields describe the IP
	// bitmap ring buffer; both checkpoints use the same shape.
	binary.LittleEndian.PutUint16(block[320:322], 1)
	binary.LittleEndian.PutUint16(block[322:324], uint16(formatIPBitmapCount-1))
	binary.LittleEndian.PutUint32(block[324:328], spacemanIPBitmapXIDOffset)
	binary.LittleEndian.PutUint32(block[328:332], spacemanIPBitmapAddrOffset)
	binary.LittleEndian.PutUint32(block[332:336], spacemanIPBmFreeNextOffset)
	// Versioned-spaceman header fields at offset 0x150 / 0x154. Apple's
	// kext refuses extended-space queries on non-versioned spacemen.
	binary.LittleEndian.PutUint32(block[spacemanVersionOffset:spacemanVersionOffset+4], spacemanVersion)
	binary.LittleEndian.PutUint32(block[spacemanStructSizeOffset:spacemanStructSizeOffset+4], spacemanFixedSize)
	// IP variable-length data — Apple's offsets, AFTER sm_struct_size:
	//   2520..2527 (8 bytes): xid associated with bitmap slot 0.
	binary.LittleEndian.PutUint64(block[spacemanIPBitmapXIDOffset:spacemanIPBitmapXIDOffset+8], xid)
	//   2528..2529 (2 bytes): current bitmap is at slot 0.
	binary.LittleEndian.PutUint16(block[spacemanIPBitmapAddrOffset:spacemanIPBitmapAddrOffset+2], 0)
	//   2536..2567 (32 bytes): free-list next pointers (slot 0 in use,
	//   slots 1..14 chain to next, slot 15 is tail).
	for i := 0; i < int(formatIPBitmapCount); i++ {
		var v uint16 = spacemanIPBMIndexInvalid
		if i >= 1 && i < int(formatIPBitmapCount-1) {
			v = uint16(i + 1)
		}
		offIdx := spacemanIPBmFreeNextOffset + 2*i
		binary.LittleEndian.PutUint16(block[offIdx:offIdx+2], v)
	}
	//   2568..2575 (8 bytes): main-device CIB-OID list — paddr of the chunk-info block.
	binary.LittleEndian.PutUint64(block[spacemanCIBAddrBaseOffset:spacemanCIBAddrBaseOffset+8], formatCIBBlock)
	//   2576..2583 (8 bytes): tier-2 CIB-OID list. With no tier-2 device
	//   the slot stays zero, matching Apple's output.
}

// encodeChunkInfoBlock writes a chunk_info_block describing one chunk
// that covers the whole volume. The chunk's bitmap lives at
// formatBitmapBlock; the chunk's free_count must match the bitmap's
// popcount of free bits or fsck flags an inconsistency.
//
// chunk_info_block_t layout (apfs.h):
//
//	+0    obj_phys_t (32 bytes; PHYSICAL)
//	+32   uint32 cib_index
//	+36   uint32 cib_chunk_info_count
//	+40   chunk_info_t cib_chunk_info[]
//
// chunk_info_t is 32 bytes: ci_xid (8), ci_addr (8), ci_block_count
// (4), ci_free_count (4), ci_bitmap_addr (8).
func encodeChunkInfoBlock(block []byte, totalBlocks uint64) {
	encodeObjHeader(block, formatCIBBlock, defaultFormatXID, objTypeChunkInfoBlock, 0, objStoragePhysical)
	off := objPhysSize
	binary.LittleEndian.PutUint32(block[off:off+4], 0)   // cib_index
	binary.LittleEndian.PutUint32(block[off+4:off+8], 1) // cib_chunk_info_count = 1
	ci := off + 8
	binary.LittleEndian.PutUint64(block[ci:ci+8], defaultFormatXID)        // ci_xid
	binary.LittleEndian.PutUint64(block[ci+8:ci+16], 0)                    // ci_addr (chunk starts at block 0)
	binary.LittleEndian.PutUint32(block[ci+16:ci+20], uint32(totalBlocks)) // ci_block_count
	freeCount := uint32(totalBlocks - uint64(formatMetadataBlocks))
	binary.LittleEndian.PutUint32(block[ci+20:ci+24], freeCount) // ci_free_count
	binary.LittleEndian.PutUint64(block[ci+24:ci+32], formatBitmapBlock)
}

// encodeAllocationBitmap writes the per-chunk allocation bitmap. APFS
// convention: BIT SET = block is allocated. The bitmap covers
// totalBlocks bits; we mark blocks 0..formatMetadataBlocks-1 as
// allocated and the remainder as free.
func encodeAllocationBitmap(block []byte, totalBlocks uint64) {
	for i := uint64(0); i < uint64(formatMetadataBlocks) && i < totalBlocks; i++ {
		block[i/8] |= 1 << (i % 8)
	}
}

// encodeIPBitmap writes the spaceman's Internal Pool allocation bitmap
// for slot 0 (the "current" bitmap). Per mkapfs:
//   - Block 0 of the IP holds the chunk-info bitmap (used).
//   - Block 1 of the IP holds the chunk-info-block (used).
//   - Remaining IP blocks (2..5) are free.
// Remaining bitmap slots (1..15) are zero blocks (allocated lazily as
// future transactions consume them).
func encodeIPBitmap(block []byte) {
	// Mark the first two IP blocks (bitmap + CIB) as allocated.
	// formatBitmapBlock - formatIPBase = 0, formatCIBBlock - formatIPBase = 1.
	block[0] = 0x03 // bits 0 and 1 set
}

// encodeOMAPPhys writes an omap_phys_t block whose B-tree root sits at
// treeBlock. ownPaddr is the physical block address of the OMAP block
// itself; for physical objects fsck verifies o_oid == own paddr.
// isContainer signals "this is the NX-level OMAP" so we set
// APFS_OMAP_MANUALLY_MANAGED in om_flags — mkapfs's `make_omap_btree`
// does the same (`if (!is_vol) omap->om_flags = ...`). The volume-level
// OMAP leaves om_flags = 0.
//
// om_tree_type and om_snap_tree_type are full obj_type words —
// `(storage class) | (object type)` — not bare object type IDs. mkapfs
// writes APFS_OBJ_PHYSICAL | APFS_OBJECT_TYPE_BTREE = 0x40000002 here.
// fsck_apfs's "Object map is invalid" error fires when the storage
// class bits are missing.
func encodeOMAPPhys(block []byte, ownPaddr, treeBlock uint64, isContainer bool) {
	encodeObjHeader(block, ownPaddr, defaultFormatXID, objTypeOMAP, 0, objStoragePhysical)
	off := objPhysSize
	const omapTreeType uint32 = objStoragePhysical | uint32(objTypeBTree) // 0x40000002
	const omapManuallyManaged uint32 = 0x1                                // APFS_OMAP_MANUALLY_MANAGED
	var omFlags uint32
	if isContainer {
		omFlags = omapManuallyManaged
	}
	binary.LittleEndian.PutUint32(block[off:off+4], omFlags)              // om_flags
	binary.LittleEndian.PutUint32(block[off+4:off+8], 0)                  // om_snap_count
	binary.LittleEndian.PutUint32(block[off+8:off+12], omapTreeType)      // om_tree_type
	binary.LittleEndian.PutUint32(block[off+12:off+16], omapTreeType)     // om_snap_tree_type
	binary.LittleEndian.PutUint64(block[off+16:off+24], treeBlock) // om_tree_oid
	binary.LittleEndian.PutUint64(block[off+24:off+32], 0)         // om_snapshot_tree_oid
	// om_most_recent_snap = largest snapshot xid in this OMAP. With no
	// snapshots, fsck_apfs requires this to be 0; "om_most_recent_snap
	// (X) is not equal to the largest snapshot xid (0)" otherwise.
	binary.LittleEndian.PutUint64(block[off+32:off+40], 0)
}

// encodeOMAPLeaf writes a fixed-shape root-AND-leaf B-tree node holding the
// supplied (oid, xid, paddr) entries — the same encoding the parser
// expects from a container or volume OMAP. Entries should already be
// sorted by (oid, xid); FormatContainer passes them in canonical order.
//
// Layout matches mkapfs's make_omap_root: btn_table_space.len is
// preallocated to min_table_size(OMAP) = 448 bytes (capacity 112
// records of {16-byte key, 16-byte val, 4-byte kvoff}). free_space
// starts immediately after the keys area; key/val free lists are
// marked APFS_BTOFF_INVALID to denote no fragmentation.
func encodeOMAPLeaf(block []byte, ownPaddr uint64, entries []omapEntry) {
	// OMAP B-tree nodes are physical: their oid is the block address.
	encodeObjHeader(block, ownPaddr, defaultFormatXID, objTypeBTree, uint32(objTypeOMAP), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0) // btn_level = 0
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	const omapTOCLen uint16 = 448 // mkapfs min_table_size(OMAP) = 112 * 4
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)         // table_space.off
	binary.LittleEndian.PutUint16(block[off+10:off+12], omapTOCLen) // table_space.len
	keyLen := uint16(len(entries) * 16)
	valLen := uint16(len(entries) * 16)
	const headLen = 56
	freeLen := uint16(len(block)-headLen-int(omapTOCLen)-int(keyLen)-int(valLen)-btreeInfoSize)
	binary.LittleEndian.PutUint16(block[off+12:off+14], keyLen)        // free_space.off
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)       // free_space.len
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)  // key_free_list.off
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)             // key_free_list.len
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)  // val_free_list.off
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)             // val_free_list.len
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(omapTOCLen)
	valBaseEnd := len(block) - btreeInfoSize
	for i, e := range entries {
		// kvoff.k = byte offset of the key from the start of the keys
		// area (grows forward). kvoff.v = byte offset of the value
		// from the END of the values area (grows backward). For the
		// first record (i=0): k=0 (first key), v=16 (sizeof(omap_val) —
		// the value's END offset, since values grow backward toward 0).
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], uint16(i*16))
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], uint16((i+1)*16))
		// omap_key {oid, xid}
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], e.xid)
		// omap_val {flags(0), size(4096), paddr}
		v := block[valBaseEnd-(i+1)*16 : valBaseEnd-i*16]
		binary.LittleEndian.PutUint32(v[0:4], 0)
		binary.LittleEndian.PutUint32(v[4:8], 4096)
		binary.LittleEndian.PutUint64(v[8:16], e.paddr)
	}
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical)
	binary.LittleEndian.PutUint32(bi[4:8], 4096)
	binary.LittleEndian.PutUint32(bi[8:12], 16)
	binary.LittleEndian.PutUint32(bi[12:16], 16)
	binary.LittleEndian.PutUint32(bi[16:20], 16)
	binary.LittleEndian.PutUint32(bi[20:24], 16)
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1) // node_count
}

// encodeAPSB writes a volume superblock referencing the volume OMAP at
// formatVolumeOmapBlock and the empty FS-tree / snap-meta tree roots
// through their virtual oids (default FSTreeRoot / SnapMetaTree).
//
// Layout matches Apple's apfs_superblock (linux-apfs_raw.h):
//
//	+0x00  obj_phys (32)
//	+0x20  apfs_magic   "APSB"
//	+0x24  apfs_fs_index
//	+0x28  apfs_features                       (8) — must be 0
//	+0x30  apfs_readonly_compatible_features   (8) — 0
//	+0x38  apfs_incompatible_features          (8) — see below
//	+0x40  apfs_unmount_time                   (8)
//	+0x48  apfs_fs_reserve_block_count         (8)
//	+0x50  apfs_fs_quota_block_count           (8)
//	+0x58  apfs_fs_alloc_count                 (8)
//	+0x60  apfs_meta_crypto                    (20)
//	+0x74  apfs_root_tree_type                 (4) — VIRTUAL|BTREE
//	+0x78  apfs_extentref_tree_type            (4) — PHYSICAL|BTREE
//	+0x7C  apfs_snap_meta_tree_type            (4) — PHYSICAL|BTREE
//	+0x80  apfs_omap_oid                       (8)
//	+0x88  apfs_root_tree_oid                  (8)
//	+0x90  apfs_extentref_tree_oid             (8)
//	+0x98  apfs_snap_meta_tree_oid             (8)
//	+0xF0  apfs_vol_uuid                       (16)
//	+0x2C0 apfs_volname                        (256)
//
// fsck_apfs's "apfs_root_tree_type is invalid: 0x0" fires when the
// type words at +0x74 are zero; our previous encoder put oids at the
// wrong offsets, leaking values into apfs_features / type fields.
func encodeAPSB(block []byte, label string) {
	// APSB has a virtual oid (resolved through the container OMAP).
	encodeObjHeader(block, defaultAPSBOID, defaultFormatXID, objTypeAPFSVolume, 0, objStorageVirtual)
	copy(block[0x20:0x24], apsbMagicASCII) // apfs_magic = "APSB"
	binary.LittleEndian.PutUint32(block[0x24:0x28], 0) // apfs_fs_index = 0
	// apfs_features (offset 0x28) = APFS_FEATURE_HARDLINK_MAP_RECORDS
	// (bit 1 — Apple's apfs.kext sets this on every newfs_apfs output).
	binary.LittleEndian.PutUint64(block[0x28:0x30], 0x2)
	// apfs_readonly_compatible_features (0x30): zero.
	// apfs_incompatible_features (0x38) = APFS_INCOMPAT_CASE_INSENSITIVE
	// (0x1). Apple's default volume policy; required for apfs.kext to
	// auto-mount the inner volume into /Volumes via diskutil mountDisk.
	// `encodeDrecKey` emits the matching `apfs_drec_hashed_key_t` shape
	// (CRC-32C name hash in the upper 22 bits of `name_len_and_hash`).
	binary.LittleEndian.PutUint64(block[0x38:0x40], 0x1)
	// apfs_unmount_time / reserve_block / quota: zero.
	// apfs_fs_alloc_count (offset 0x58): mkapfs sets 5 — the four tree
	// root nodes (fs-tree, snap-meta, extentref, doc-id) plus the OMAP
	// structure. fsck_apfs's "apfs_fs_alloc_count is not valid (expected
	// 5, actual 0)" fires when we leave it zero.
	binary.LittleEndian.PutUint64(block[0x58:0x60], 5)
	// apfs_meta_crypto (offset 0x60..0x74) — wrapped_meta_crypto_state.
	// fsck_apfs warns "crypto major version (0) is not CP_CURRENT (5)"
	// when this is left zero. mkapfs's set_meta_crypto:
	//   +0x60  major_version    = APFS_WMCS_MAJOR_VERSION (5)
	//   +0x62  minor_version    = 0
	//   +0x64  cpflags          = 0
	//   +0x68  persistent_class = APFS_PROTECTION_CLASS_F (0xF)
	//   +0x6C  key_os_version   = 0
	//   +0x70  key_revision     = 1
	//   +0x72  padding          (2 bytes)
	const (
		wmcsMajorVersion     uint16 = 5
		// APFS_PROTECTION_CLASS_F = 6 (no protection, non-persistent key).
		// fsck_apfs rejects values outside the documented enum (e.g. 15
		// triggers "invalid default_protection_class (15)").
		wmcsProtectionClassF uint32 = 6
		wmcsKeyRevision      uint16 = 1
	)
	binary.LittleEndian.PutUint16(block[0x60:0x62], wmcsMajorVersion)
	binary.LittleEndian.PutUint32(block[0x68:0x6C], wmcsProtectionClassF)
	// key_os_version (offset 0x6C): Apple sets a non-zero version
	// stamp (e.g. 0x19440850 on macOS 15.x). mkapfs leaves this at 0
	// and fsck accepts both, but Apple's apfs.kext may reject 0 when
	// deciding whether to auto-mount.
	binary.LittleEndian.PutUint32(block[0x6C:0x70], 0x19440850)
	binary.LittleEndian.PutUint16(block[0x70:0x72], wmcsKeyRevision)
	// Tree-type triple at +0x74:
	const rootTreeType uint32 = objStorageVirtual | uint32(objTypeBTree)  // 0x00000002
	const extRefTreeType uint32 = objStoragePhysical | uint32(objTypeBTree) // 0x40000002
	const snapMetaTreeType uint32 = objStoragePhysical | uint32(objTypeBTree)
	binary.LittleEndian.PutUint32(block[0x74:0x78], rootTreeType)
	binary.LittleEndian.PutUint32(block[0x78:0x7C], extRefTreeType)
	binary.LittleEndian.PutUint32(block[0x7C:0x80], snapMetaTreeType)
	binary.LittleEndian.PutUint64(block[0x80:0x88], formatVolumeOmapBlock)    // apfs_omap_oid (PHYSICAL → paddr)
	binary.LittleEndian.PutUint64(block[0x88:0x90], defaultFSTreeRootOID)    // apfs_root_tree_oid (VIRTUAL → oid)
	binary.LittleEndian.PutUint64(block[0x90:0x98], formatExtentRefTreeBlock) // apfs_extentref_tree_oid (PHYSICAL → paddr)
	binary.LittleEndian.PutUint64(block[0x98:0xA0], formatSnapMetaTreeRootBlock) // apfs_snap_meta_tree_oid (PHYSICAL → paddr)
	// apfs_revert_to_xid / apfs_revert_to_sblock_oid (0xA0..0xB0): zero.
	// apfs_next_obj_id (0xB0..0xB8): start fresh inode numbering above
	// APFS_MIN_USER_INO_NUM (16). Use 0x10 (16) so callers can allocate
	// 0x10, 0x11, … without colliding with the reserved 0..15.
	binary.LittleEndian.PutUint64(block[0xB0:0xB8], 0x10)
	// apfs_num_* counters (0xB8..0xE0) and totals_alloced/freed (0xE0..0xF0)
	// stay zero for an empty volume.
	// apfs_vol_uuid (0xF0..0x100): random, distinct from container UUID.
	if _, err := formatRandReadFn(block[0xF0:0x100]); err != nil {
		_ = err
	}
	// apfs_last_mod_time (0x100..0x108): nanoseconds since the Unix
	// epoch. Apple's mount path treats an all-zero value as "uninitialized
	// volume" and refuses to bind it (the diskarbitrationd `disenter`
	// daemon returns status 0x42 with last_mod_time == 0). Use the
	// current wall clock; a non-zero value is what matters, the exact
	// value doesn't.
	formatNow := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(block[0x100:0x108], formatNow)
	// apfs_fs_flags (0x108..0x110) = APFS_FS_UNENCRYPTED. Without this
	// fsck warns "Volume is encrypted and crypto I/O failed/was skipped";
	// macOS then refuses to mount the volume (it sees a protection class
	// other than NONE in apfs_meta_crypto and looks for a key bag).
	const apfsFSUnencrypted uint64 = 0x1
	binary.LittleEndian.PutUint64(block[0x108:0x110], apfsFSUnencrypted)
	// apfs_formatted_by (0x110..0x140): 48 bytes — id (32) + timestamp
	// (8) + last_xid (8). Apple writes "newfs_apfs (<version>)" here;
	// apfs.kext may treat an all-zero formatted_by as suspicious and
	// refuse to auto-mount.
	const formatterID = "go-filesystems/apfs (D-7)"
	copy(block[0x110:0x110+32], []byte(formatterID))
	// timestamp at 0x130: must be non-zero (same reason as last_mod_time).
	binary.LittleEndian.PutUint64(block[0x130:0x138], formatNow)
	// last_xid at 0x138: matches the volume's current xid.
	binary.LittleEndian.PutUint64(block[0x138:0x140], defaultFormatXID)
	// Per byte-diff with Apple's `hdiutil create -fs APFS` reference,
	// these high APSB fields are non-zero on Apple's output.
	//
	// Tree-type field convention (verified against Apple):
	//   - apfs_extentref_tree_type / apfs_snap_meta_tree_type / apfs_fext_tree_type
	//     carry a FULL obj-type word (PHYSICAL|BTREE = 0x40000002), because
	//     they describe trees whose root oid is interpreted as a paddr.
	//   - apfs_doc_id_tree_type / apfs_sec_root_tree_type / the unnamed
	//     reserved-tree-type at 0x460 carry JUST APFS_OBJECT_TYPE_BTREE
	//     (= 0x02, no storage-class flags). Apple's mount path appears to
	//     reject the storage-class flag in these slots ("Invalid argument"
	//     when set to 0x40000002 instead of 0x02).
	const physicalBTree uint32 = objStoragePhysical | uint32(objTypeBTree) // 0x40000002
	const bareBTree uint32 = uint32(objTypeBTree)                          // 0x00000002
	binary.LittleEndian.PutUint32(block[0x410:0x414], physicalBTree)        // apfs_fext_tree_type
	binary.LittleEndian.PutUint32(block[0x414:0x418], physicalBTree)        // reserved_type
	binary.LittleEndian.PutUint64(block[0x420:0x428], defaultFormatXID)     // apfs_doc_id_index_xid
	binary.LittleEndian.PutUint32(block[0x428:0x42C], 0x10)                 // apfs_doc_id_index_flags
	binary.LittleEndian.PutUint32(block[0x42C:0x430], bareBTree)            // apfs_doc_id_tree_type
	binary.LittleEndian.PutUint32(block[0x450:0x454], bareBTree)            // apfs_sec_root_tree_type
	binary.LittleEndian.PutUint32(block[0x460:0x464], bareBTree)            // (reserved-tree-type 1)
	binary.LittleEndian.PutUint32(block[0x468:0x46C], 0xC)                  // (reserved-tree-type 2 / flags)
	// apfs_volname (0x2C0..0x3C0): 256 bytes, NUL-padded.
	if label != "" {
		const volNameOff = 0x2C0
		const volNameLen = 256
		raw := []byte(label)
		if len(raw) >= volNameLen {
			raw = raw[:volNameLen-1]
		}
		copy(block[volNameOff:volNameOff+len(raw)], raw)
	}
	// apfs_next_doc_id (offset 0x3C0, uint32). fsck_apfs rejects values
	// less than APFS_MIN_DOC_ID (3); mkapfs writes exactly 3.
	const apfsMinDocID uint32 = 3
	binary.LittleEndian.PutUint32(block[0x3C0:0x3C4], apfsMinDocID)
}

// encodeEmptyFSTreeLeaf writes a variable-shape root-AND-leaf B-tree node
// with zero entries. Used for both the FS-tree root and the snap_meta
// tree root in a freshly-formatted container.
//
// `oid` is the virtual oid by which the volume OMAP resolves this tree
// (defaultFSTreeRootOID for the catalog, defaultSnapMetaTreeOID for
// the snap-meta tree). For a VIRTUAL object, fsck_apfs requires
// o_oid == that virtual oid (NOT zero).
//
// encodeEmptyPhysicalBTree writes an empty PHYSICAL B-tree root for the
// volume-level extent-ref tree (subtype = APFS_OBJECT_TYPE_BLOCKREFTREE
// = 0x0F) or snap-meta tree (subtype = APFS_OBJECT_TYPE_SNAPMETATREE =
// 0x10). mkapfs's `make_empty_btree_root` is the reference; layout:
//
//   - flags = ROOT | LEAF (no FIXED_KV_SIZE — both trees are variable)
//   - btn_table_space pre-allocated to BTREE_TOC_ENTRY_MAX_UNUSED *
//     sizeof(kvloc) = 64 bytes (mkapfs default for variable trees)
//   - btn_free_space starts at offset 0 with the rest of the block
//   - btn_key_free_list / btn_val_free_list = APFS_BTOFF_INVALID
//   - bt_flags = APFS_BTREE_PHYSICAL | APFS_BTREE_KV_NONALIGNED (matches
//     the "default" branch of mkapfs's set_empty_btree_info)
//
// PHYSICAL storage class means the block address IS the oid; fsck_apfs
// requires o_oid == ownPaddr.
func encodeEmptyPhysicalBTree(block []byte, ownPaddr uint64, subtype uint16) {
	encodeObjHeader(block, ownPaddr, defaultFormatXID, objTypeBTree, uint32(subtype), objStoragePhysical)
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0) // btn_level = 0
	binary.LittleEndian.PutUint32(block[off+4:off+8], 0) // btn_nkeys = 0
	const physTreeTOCLen uint16 = 8 * 8 // BTREE_TOC_ENTRY_MAX_UNUSED * sizeof(kvloc)
	const headLen = 56
	freeLen := uint16(len(block) - headLen - int(physTreeTOCLen) - btreeInfoSize)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0)               // table_space.off
	binary.LittleEndian.PutUint16(block[off+10:off+12], physTreeTOCLen) // table_space.len
	binary.LittleEndian.PutUint16(block[off+12:off+14], 0)              // free_space.off
	binary.LittleEndian.PutUint16(block[off+14:off+16], freeLen)        // free_space.len
	binary.LittleEndian.PutUint16(block[off+16:off+18], btoffInvalid)   // key_free_list.off
	binary.LittleEndian.PutUint16(block[off+18:off+20], 0)              // key_free_list.len
	binary.LittleEndian.PutUint16(block[off+20:off+22], btoffInvalid)   // val_free_list.off
	binary.LittleEndian.PutUint16(block[off+22:off+24], 0)              // val_free_list.len
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], btreeFlagPhysical|btreeFlagKVNonAligned)
	binary.LittleEndian.PutUint32(bi[4:8], 4096) // bt_node_size
	binary.LittleEndian.PutUint64(bi[24:32], 0)  // bt_key_count
	binary.LittleEndian.PutUint64(bi[32:40], 1)  // bt_node_count = 1
}
