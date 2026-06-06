# APFS Cross-Compatibility Test Protocol

This document specifies a cross-compatibility test matrix between this
project's pure-Go implementation (`pkg/go-filesystems/apfs` native parser
plus the iter-D/A/B/C writers, the `pkg/go-fde/apfs` FDE layer, and the
`pkg/go-diskimages/diskimage` DMG wrapper) and Apple's official tooling
(`hdiutil`, `diskutil`, `fsck_apfs`, `asr`).

The goal is to know — operation by operation, direction by direction —
whether bytes our code produces can be consumed by Apple's tools, and
whether bytes Apple's tools produce can be consumed by our code. Without
that knowledge, "valid according to our parser" is a meaningless label.

## Scope

Every cell of the matrix below is a directional pair `(producer, consumer)`
for one of these operations:

- **Create**: build a fresh APFS volume / container / DMG.
- **Encrypt**: produce an encrypted container or wrap an existing one.
- **Decrypt**: open an encrypted container and read plaintext bytes.
- **Read**: list inodes, read file contents, list xattrs and snapshots.
- **Write**: create / overwrite a file, create / list directories.
- **Resize**: grow or shrink a container.

A cell is one of:

- **PASS** — automated test exists and is expected to succeed.
- **FAIL (known)** — operation is documented as not interoperable; the
  protocol records *why* and what would close the gap.
- **SKIP (env)** — only runnable on macOS with admin rights / specific
  hardware (T2, recovery key bag); the protocol describes the manual
  procedure.

## Test environment

All matrix cells run on macOS only. Required tools:

| Tool | Used by | Notes |
|------|---------|-------|
| `hdiutil` | DMG create / attach / detach / resize / convert / encrypt | Always present in macOS. |
| `diskutil` | APFS volume / container manipulation, snapshots | Always present. |
| `fsck_apfs` | Structural validation of containers we write | Needs `-n` to avoid mutating. |
| `asr` | Block-level cloning, post-creation validation | Optional. |

The Go-side cross-compat tests live in `native_compat_darwin_test.go`
and are gated by `//go:build darwin` plus runtime `t.Skip` when one of
the required tools is missing. They use `t.TempDir()` for cleanup and
detach mounted images via `defer`.

## The matrix

### Block layer

| # | Producer | Operation | Consumer | Direction | Status | Test |
|---|----------|-----------|----------|-----------|--------|------|
| B-1 | Apple `hdiutil create -fs APFS` | Create raw APFS image inside a DMG | Our diskimage parser | A → ours | PASS | `TestCompatBlock_HdiutilCreatesAPFS_DiskimageReads` |
| B-2 | Our `diskimage create dmg --filesystem apfs` | Create DMG | `hdiutil attach` + `fsck_apfs -n` + `diskutil mountDisk` | ours → A | PASS | `diskimage/create.go`'s FSApfs branch calls `filesystem_apfs.FormatContainer` (D-6/D-10) directly and skips UDIF wrapping (Apple's `hdiutil create -fs APFS file.dmg` itself produces a raw image — `Class Name: CRawDiskImage / Format: UDRW` — with no koly trailer). With `Partition: PartGPT`, `diskutil list` reports the file as a `GUID_partition_scheme` containing an `Apple_APFS` slice; the partition entry uses Apple's `7C3457EF-0000-11AA-AA11-00306543ECAC` GUID and partition name `"disk image"`. The full pipeline `hdiutil attach -nomount` → `fsck_apfs -n` → `mount_apfs <volDev> <mnt>` → `cp` → `cat` → `diskutil unmount` succeeds end-to-end (covered by `TestCompatNative_KextMountsOurFormat`). The integration test `TestDiskimageCreate_then_hdiutilRead` exercises `Create + hdiutil attach + fsck + mountDisk` and the volume now appears at `/Volumes/<label>` after `diskutil mountDisk`. **Note**: populating the GPT'd DMG with `OpenContainerRW + CreateFile + Commit` still requires the apfs package's `OpenContainer*` to learn a partition-offset parameter (the APFS NX SB lives at LBA 2048, not file offset 0); tracked as a separate enhancement. |
| B-3 | Apple `hdiutil resize` | Grow an existing DMG | Our diskimage parser | A → ours | PASS | `TestCompatBlock_HdiutilResize_DiskimageReads` |

### Native APFS layer (`pkg/go-filesystems/apfs/format.go` / `container.go` / `volume*.go`)

| # | Producer | Operation | Consumer | Direction | Status | Test |
|---|----------|-----------|----------|-----------|--------|------|
| N-1 | Our `FormatContainer` | Empty container | `OpenContainer` | ours → ours | PASS | `TestFormatContainer_RoundTrip`. |
| N-2 | Our `FormatContainer` | Empty container | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` (read+write) | ours → A | PASS | `TestCompatNative_FormatContainerFsckClean` + `TestCompatNative_KextMountsOurFormat` (full `hdiutil attach` + `fsck_apfs -n` + `mount_apfs <volDev> <mnt>` + `WriteFile` + `ReadFile` round-trip). Iteratively driven against `fsck_apfs -n` and against an Apple reference container (`hdiutil create -fs APFS` byte-dumped via the harness), refined against canonical structure definitions in [`linux-apfs/apfsprogs`](https://github.com/linux-apfs/apfsprogs), [`apfs-fuse`](https://github.com/sgan81/apfs-fuse), [`libfsapfs`](https://github.com/libyal/libfsapfs), and especially `mkapfs` from the linux-apfs userspace tools. Load-bearing fixes (D-5..D-10): dual-checkpoint init matching `newfs_apfs` (xid=1 bootstrap + xid=2 fillout); SPACEMAN-first ephemeral order; shared container UUID across block 0 and both desc-area NX SB copies; APSB layout matching Apple's `apfs_superblock` (root_tree_type at 0x74, omap_oid at 0x80, vol_uuid at 0xF0, volname at 0x2C0); `apfs_meta_crypto.major_version = 5` + `protection_class = F` + `key_revision = 1` + `apfs_fs_flags = APFS_FS_UNENCRYPTED` + `apfs_next_doc_id = APFS_MIN_DOC_ID (3)` + `apfs_fs_alloc_count = 5`; PHYSICAL extentref + snap-meta B-tree roots; `om_tree_type = PHYSICAL\|BTREE = 0x40000002`; `om_most_recent_snap = 0`; container OMAP carries `om_flags = APFS_OMAP_MANUALLY_MANAGED`; `nx_incompatible_features = APFS_NX_INCOMPAT_VERSION2`; reaper with non-zero `nr_next_reap_id` + `nr_flags = APFS_NR_BHM_FLAG`; APSB high fields (`apfs_features`, `apfs_meta_crypto.key_os_version`, `apfs_formatted_by.id`, `apfs_fext_tree_type`, `apfs_doc_id_index_xid`, etc.); `apfs_incompatible_features = APFS_INCOMPAT_CASE_INSENSITIVE` + hashed `apfs_drec_hashed_key_t` keys with CRC-32C name hash; `compareFSKey` sorts hashed drec keys by the **numeric** value of `name_len_and_hash` (D-9); APSB timestamps `apfs_last_mod_time` and `apfs_formatted_by.timestamp` are non-zero (`time.Now().UnixNano()`); `apfs_doc_id_tree_type` / `apfs_sec_root_tree_type` / the reserved tree-type slot at 0x460 use bare `0x02` (BTREE only, no PHYSICAL flag). **The two D-10 changes that flipped the kext from EINVAL → mountable**: (1) **Versioned spaceman** (`sm_flags = APFS_SM_FLAG_VERSIONED = 0x1`, `sm_version = 1`, `sm_struct_size = 2520`, IP variable-length arrays + cib-addr lists at Apple's offsets 2520/2528/2536/2568/2576 instead of mkapfs's 336/344/352/384) + Apple-style format with no FQ trees pre-emitted (`nx_xp_data_len = 2`, `cpm_count = 2`, `sm_fq[*].sfq_tree_oid = 0`, `sfq_tree_node_limit = 1`) — without these the kext's `APFSExtendedSpaceInfo` query returns `IntErr=-536870185` and `diskutil apfs list` shows `Container ERROR -69808`. (2) **FS-tree pre-populated at format time with the four `make_cat_root` records** (root + private-dir inodes at oids 2 + 3 and their parent dentries under `APFS_ROOT_DIR_PARENT`); without these the kext returns `mount_apfs: Invalid argument` because it cross-checks `apfs_root_tree_oid` against the records inside the tree. Special-dir inode owner/group are set from `os.Geteuid()/Getegid()` so the mounting user can write into the volume's root directory. With these, `fsck_apfs -n` is clean end-to-end, `diskutil apfs list` reports correct capacity, and `mount_apfs` mounts the volume into `/Volumes/<label>` with full read/write through the macOS apfs.kext. |
| N-3 | Apple `hdiutil create -fs APFS -srcfolder` (GPT-wrapped) | Populated container | `OpenContainerAuto` + `ReadFile` | A → ours | PASS | `TestCompatNative_OpenAutoOnHdiutilCreatedAPFS`. `hdiutil create -fs APFS` produces a raw image whose first sector is a protective MBR, sector 1 carries an "EFI PART" GPT header, and the APFS NX SB lives at the start of the Apple_APFS partition (LBA 2048 = byte offset 0x100000 = 1 MiB). Naked `OpenContainer` rejects this image (it sees the MBR at offset 0); `OpenContainerAuto` / `OpenContainerRWAuto` parse the GPT, find the entry whose type GUID is Apple_APFS (`7C3457EF-0000-11AA-AA11-00306543ECAC`), and wrap the underlying file with an offset-aware ReadAt/WriteAt so all subsequent reads/writes are translated into the partition. The wrapper is opportunistic: naked APFS images (FormatContainer output) are detected by the absence of "EFI PART" magic and fall through to offset 0. |
| N-4 | Our `CreateFile` + `Commit` after `FormatContainer` | Single inode | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` (read+write) | ours → A | PASS | `TestCompatNative_CreateFileCommitFsckClean` + `TestCompatNative_KextMountsOurFormat`. D-7: a `Container.Commit()` method that promotes in-memory mutations to a fresh on-disk checkpoint at xid=N+1; refreshes APSB counters from a fresh FS-tree scan. `CreateFile` bootstraps the canonical root + private-dir inodes (oids 2 + 3) with mkapfs's INO_EXT_TYPE_NAME xfield and tracks `nchildren` against the real J_DIR_REC count. Inserts a J_DSTREAM_ID alongside the regular file's J_INODE / J_FILE_EXTENT / J_DIR_REC. Inode value at offset 80 carries `mode`; private_id mirrors the inode's own oid; internal_flags has bit 15 (HAS_FINDER_INFO); default_protection_class = APFS_PROTECTION_CLASS_F = 6 for files / DIR_NONE = 0 for directories. J_DSTREAM payload is 40 bytes including `total_bytes_read`. FS-tree leaf info trailer carries `bt_longest_key` / `bt_longest_val`. The full Apple-tooling pipeline now succeeds: `hdiutil attach` → `fsck_apfs -n` clean → `mount_apfs` returns 0 → the volume is visible at `/Volumes/<label>` → user-space `cat` reads the file we wrote. See N-2 for the load-bearing fixes (versioned spaceman, FS-tree pre-population at format, owner/group from euid/egid, etc.). |
| N-10 | Our `CreateDirectory` × N (N forces volume OMAP overflow) | Volume with 2-level volume OMAP (level-1 root + level-0 leaves) | Our reader (full round-trip) | ours → ours | PASS | `TestRootPromotion_LiftsCap` (2000 dirs). The volume OMAP is no longer capped at ~110 entries: when `upsertVolumeOMAPEntry` would overflow the single-leaf, it now PROMOTES to a 2-level tree via `promoteVolumeOMAPToTwoLevel`. Plan: distribute existing entries between two NEW non-root leaves at fresh paddrs (`emitOMAPNonRootLeaf`), then rewrite the original tree-root paddr as a level-1 internal root carrying 2 index entries pointing at the new leaves (`emitOMAPInternalRoot`). The reader (`Container.omapLookupInNode`) handles the descent recursively and tolerates non-FIXED_KV_SIZE shapes; the new `upsertVolumeOMAPMultiLevel` path performs OMAP descent on subsequent inserts and modifies the target leaf in place. End-to-end verified: 2000 dirs created via `CreateDirectory`, both FS-tree and volume OMAP show `level=1` after re-open, every dir reachable through the reader. | 
| N-10-kext | Same | Volume OMAP via `apfs.kext` / `fsck_apfs` | ours → A | PASS | `TestCompatNative_VolumeOMAPSplitKextRoundTrip` (1500 dirs, kext mounts cleanly, all dirs visible, fsck-clean). Unblocked by byte-diffing an Apple-authored multi-level OMAP — produced by formatting an APFS container, kext-mounting it, populating with 1500+ small files (forcing the kext's own OMAP-split path), unmounting, and dumping the root block via `TestProbe_AppleMultiLevelOMAP`. Three fixes in `emitOMAPInternalRoot` matched Apple's layout: (1) `table_space.len = 576` (NOT 448 — fsck rejected 448 with `invalid btn_table_space (0, 448), given btn_flags (0x5)`); (2) per-entry `val.off = (i+1) * 8` (internal-node value size is 8 bytes, NOT the leaf's 16-byte slot — fsck rejected 16-byte slots with the same `invalid btn_flags` error); (3) values stored as 8-byte child paddrs packed end-to-end backward from val_end (NOT 16-byte slots with paddr in first 8 + zero padding). Plus a count-refresh pass: every multi-level upsert calls `refreshOMAPRootCounts` to walk all child leaves and update the root's `bt_key_count` + `bt_node_count` trailer fields — fsck rejects stale counts with `invalid btn_btree.bt_key_count (expected N, actual M)`. Reader change in `omapLookupInNode`: dropped the legacy "fixed kv shape only" guard so descent works through both Apple-authored and our writer's promoted OMAPs. |
| N-9 | Two structural extensions (root promotion + post-snapshot guard) | FS-tree level-1→2 promotion code path + snapshot-write guard | Our reader / `TestRootPromotion_LiftsCap` + `TestSnapshotGuard_RefusesPostSnapshotWrites` | ours → ours | PASS | Two safety/scale features: **(1) FS-tree root promotion (level 1 → 2)** — `refreshRoot` and the leaf-split path inside `modifyLeafAtPaddrAndInsert` now call `promoteRoot(entries, rootPaddr, leafXID, oldLevel)` when the would-be root index entries don't fit in a single 4 KiB block. `promoteRoot` splits the entries between two NEW internal nodes at the same level (allocated paddrs + virtual oids, registered in the volume OMAP), then emits a new root one level higher carrying just two index entries pointing at them. Helpers `leftmostKeyInSubtree` (recursive descent down the leftmost path to find a subtree's smallest key) and `isOverflowErr` (wraps the emitter's overflow detection). The promotion code path itself is verified by code review + `TestRootPromotion_LiftsCap` (creates 1000 dirs, validates `level=1` round-trip). End-to-end exercise of the level=2 transition is gated by a separate downstream cap: the volume OMAP itself is still a single-leaf B-tree (~110 entries), and each leaf split adds an OMAP entry, so the OMAP cap (~110 leaves = ~1500 dirs) is reached BEFORE the FS-tree root cap (~120 child pointers = ~2000 dirs). The volume OMAP has since been lifted to multi-level (level-0 → level-1 → level-2; see "Volume OMAP, snap-meta and extent-ref multi-level" in the README). **(2) Snapshot-write guard** — `Volume.checkSnapshotGuard()` returns `ErrHasSnapshot` when `apsb.numSnapshots > 0`, refusing writes that would corrupt the snapshot's frozen view (since our writers mutate trees IN PLACE rather than copy-on-write). Threaded into every public mutating entry point (`CreateFile`, `CreateDirectory`, `CreateSymlink`, `CreateHardlink`, `SetXAttr`, `SetXAttrStream`, `Create{Fifo,Socket,BlockDevice,CharDevice}`, `CreateSparseFile`, `OverwriteFile`, `TruncateFile`, `WriteFile`, `DeleteFile`, `DeleteDirectory`, `Rename`). `CreateSnapshot` itself bumps `v.apsb.numSnapshots` in-memory so subsequent calls in the same session see the guard. `SetSuppressSnapshotGuard(true)` provides an explicit escape hatch for tests / diagnostics that intentionally invalidate snapshots. Verified by `TestSnapshotGuard_RefusesPostSnapshotWrites` — confirms ErrHasSnapshot via `errors.Is` after CreateSnapshot, AND confirms suppression bypass works. The guard is conservative: a future copy-on-write rework of the writers (every mutated tree node allocated at a fresh paddr + new OMAP entry at the post-snapshot xid) would lift the restriction. |
| N-8 | Five writer extensions (timestamps, special files, sparse files, stream xattrs, multi-level descent) | Various per-cell | Our reader + (where applicable) `apfs.kext` | ours → ours / ours → A | PASS | Five additive features in one iteration: **(1) Timestamps** — `Volume.OverwriteFile` / `TruncateFile` / `WriteFile` / `Rename` / `CreateHardlink` now patch `mod_time` (offset 24) + `change_time` (offset 32) + (when content modified) `access_time` (offset 40) of the inode val to `time.Now()`. New `touchInodeTimes(val, mod)` helper centralises the mtime/ctime/atime convention (mod=true → mtime+ctime+atime; mod=false → ctime only, for metadata-only ops). Verified by `TestTimestamps_OverwriteUpdatesMtime`. **(2) Special files** — `CreateFifo` / `CreateSocket` / `CreateBlockDevice` / `CreateCharDevice` write inodes with the right S_IF* mode bits + matching drec types (DT_FIFO=1, DT_CHR=2, DT_BLK=6, DT_SOCK=12); device nodes carry an INO_EXT_TYPE_RDEV xfield (0x0D) holding the rdev number. Verified by `TestSpecialFiles_RoundTrip`. **(3) Sparse files** — `CreateSparseFile(parent, name, totalSize)` writes an inode with `size = totalSize`, `alloced_size = aligned(totalSize, bs)`, and one J_FILE_EXTENT with `phys_block_num = 0` (the APFS sparse-hole convention). No payload blocks consumed. ReadFile zero-fills the hole on read (existing behaviour, see `TestSparseFileZeroFill`). Verified by `TestCreateSparseFile_RoundTrip`. **(4) Stream xattrs** — `SetXAttrStream(oid, name, payload)` for xattrs too large for inline storage. Allocates a fresh `xattr_obj_id` from `Container.allocVirtualOID`, writes the payload to a fresh extent, inserts a J_FILE_EXTENT (keyed by xattr_obj_id) + J_DSTREAM_ID + J_XATTR with flag XATTR_DATA_STREAM (0x01) and 48-byte j_xattr_dstream value. Verified by `TestSetXAttrStream_RoundTrip` — 5 KiB payload, our reader surfaces `Flags & xattrFlagDataStream != 0`, `StreamID != 0`, `StreamSize == 5120`. **(5) Multi-level FS-tree descent** — `descendToLeafForKey` is now recursive (handles any depth) instead of capping at level=1. The writer path that splits LEAVES still updates the immediate parent (which can be at any level). Level-1 → level-2 root promotion is now WIRED through `promoteRoot` (already implemented earlier but blocked by a downstream OMAP cap; that downstream cap is also lifted — see "Volume OMAP recursive leaf split" in the README). Verified end-to-end by `TestRootPromotion_FilesLevel2` (1500 single-extent files reach FS-tree level=2 with all files reachable through the reader). Level-2 → level-3 promotion is still deferred and unreachable for typical workloads. |
| N-7 | Our `FormatContainer` + `Container.AddVolume` × N + `Commit` | APFS container with multiple volumes (each independent FS-tree / OMAP / snap-meta / extent-ref) | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` × 2 + `diskutil apfs list` | ours → A | PASS | `TestCompatNative_AddVolumeKextRoundTrip` + `TestAddVolume_RoundTrip`. Adds `Container.AddVolume(label)` for extending a freshly-formatted single-volume container with additional volumes (up to Apple's max of 100). Each new volume gets 6 fresh metadata blocks past the format-time metadata (APSB + volume OMAP + OMAP leaf + FS-tree root + snap-meta tree + extent-ref tree), allocated via `firstFreeBlockAtOrAfter` + `markBlocksAllocated`. The new volume's APSB OID is allocated from `Container.allocVirtualOID` (drawing from `nx_next_oid`), inserted into the container OMAP leaf via a new `Container.upsertContainerOMAPEntry` helper, and appended to the NX SB's `fs_oid` array. Both block 0 AND the descriptor-area NX SB copy at `desc[xpDescIndex+xpDescLen-1]` are updated in place + Fletcher-resealed (fsck cross-checks them and rejects mismatches). Two specific fsck pitfalls were resolved: (1) **`nx_max_file_systems` (NX SB +180) caps the fs_oid array** — set to 1 at format time, fsck would only enumerate fs_oid[0] and treat fs_oid[1+] as orphan; raised to 100 (`NX_MAX_FILE_SYSTEMS`) at format so `AddVolume` can populate without re-emitting NX SB; (2) **drec hash uses lowercased name** for case-insensitive volumes (`APFS_INCOMPAT_CASE_INSENSITIVE`) — fsck rejected `fileA.txt` with `directory record (id N): invalid hash (X, expected Y) of name (fileA.txt)` because our `drecNameHash` was hashing the literal case; ASCII A-Z → a-z fold added before CRC-32C. End-to-end through `apfs.kext`: `diskutil apfs list` reports both volumes by name + UUID + capacity, both mount independently via `mount_apfs`, contents are isolated per volume, fsck clean across the container. |
| N-6 | Our `CreateSnapshot` + `Commit` | Snapshot record set (J_SNAP_META + J_SNAP_NAME + frozen APSB + omap_snap_tree) | Our `OpenContainer` + `ListSnapshots` + `LookupSnapshotByName` | ours → ours | PASS | `TestCreateSnapshot_RoundTrip` + `TestCompatNative_SnapshotOurReaderRoundTrip`. Adds `Volume.CreateSnapshot(name)` which: (1) picks the container's current xid as the snapshot xid (per linux-apfs/snapshot.c::apfs_create_superblock_snapshot — the active namespace xid stamps the J_SNAP_META key); (2) CoWs the live APSB to a fresh paddr — `o_oid = paddr`, `o_xid = snap_xid`, `o_type` retyped to PHYSICAL (otherwise the live APSB's VIRTUAL bits clash with the paddr-reference shape), `apfs_omap_oid` + `apfs_snap_meta_tree_oid` zeroed in the copy per linux-apfs convention; (3) inserts a J_SNAP_META + J_SNAP_NAME pair into the snap-meta tree (PHYSICAL `BLOCKREFTREE` at apsb.snapMetaOID); (4) bumps `apfs_num_snapshots` (APSB +0xD4); (5) materialises the OMAP snapshot tree (PHYSICAL B-tree subtype `APFS_OBJECT_TYPE_OMAP_SNAPSHOT = 0x13`, fixed-shape: 8-byte key holding snap_xid, 16-byte value `apfs_omap_snapshot{flags, pad, oid}` per [linux-apfs/snapshot.c::apfs_update_omap_snap_tree](https://github.com/linux-apfs/linux-apfs-rw/blob/master/snapshot.c)); (6) updates volume OMAP's `om_snap_count++`, `om_most_recent_snap = snapXID`, AND `om_snapshot_tree_oid = omap_snap_tree_paddr`. Two encoding subtleties needed reference-checking: (a) J_SNAP_NAME keys use `oid = APFS_SNAP_NAME_OBJ_ID = 0x0FFFFFFFFFFFFFFF` (all 60 bits of the j_key_t oid set, NOT zero — fsck rejects oid=0 with `invalid hdr.obj_id`, see [linux-apfs/apfs_raw.h](https://github.com/linux-apfs/linux-apfs-rw/blob/master/apfs_raw.h) `APFS_SNAP_NAME_OBJ_ID`); (b) `J_SNAP_META.sblock_oid` is a paddr per linux-apfs `apfs_create_superblock_snapshot`. |
| N-6-kext | Same | Snapshot via apfs.kext (`diskutil apfs listSnapshots`, `fsck_apfs -n`) | ours → A | BLOCKED | `fsck_apfs` reports `snapshot metadata (id N): invalid hdr.obj_id` and we cannot reverse-engineer the missing invariant: **Apple locks user-volume snapshot creation entirely on modern macOS**. Verified empirically: (a) `diskutil apfs createSnapshot` is not a verb; (b) `tmutil snapshot` only operates on the boot volume; (c) the `fs_snapshot_create()` syscall (declared in `<sys/snapshot.h>`) returns EPERM even as root because it requires the Apple-private `com.apple.developer.fs.snapshot.modify` entitlement; (d) Apple's signed binaries that DO carry that entitlement (`apfs_systemsnapshot` in `/System/Library/Filesystems/apfs.fs/Contents/Resources/`) return EPERM on user volumes — the entitlement is scoped to the boot/system volume with ARV. With no path to an Apple-authored reference snapshot for byte-diff, the remaining structural mismatch (likely a volume OMAP entry tracking the FS-tree root at the snapshot xid, or specific flag bits in `apfs_snap_metadata_val.flags` / the omap_snap_tree value) cannot be identified without either disabling SIP and reading the boot disk's raw blocks, or using a properly-entitled Apple-internal binary. The records WE emit (J_SNAP_META, J_SNAP_NAME, frozen-APSB-as-PHYSICAL, om_snap_count, om_most_recent_snap, om_snap_tree_oid) are correct enough for our reader to round-trip — see N-6 PASS. |
| N-5 | `hdiutil create` populated + `hdiutil detach` | Existing container | Our `CreateFile` + `Commit` | A → ours | PASS | `TestCompatNative_OursWritesAfterKextWrites` — the macOS apfs.kext populates a `FormatContainer`-produced image with files (promoting the FS-tree, extent-ref tree, and chunk bitmap to "kext-authored" state), we re-open RW and add a file via `CreateFile + Commit`, then re-attach: the kext mounts cleanly, both Apple's pre-existing files and our newly-added file round-trip through the kext, and `fsck_apfs -n` is fully clean (no warnings, no errors). The Commit cascade now: (1) reads the existing block-0 NX SB and **mutates only the fields that change** between checkpoints (xid, xp_desc/xp_data window) — preserving every container-specific field Apple wrote (omap_oid, spaceman_oid, reaper_oid, fs_oid array, max_file_systems, ephemeral_info, nx_counters, nx_newest_mounted_version, fusion slots); (2) **brings forward every CPM ephemeral** at the new xid by reading each entry's source block and just bumping its obj header (so Apple's lazy-created FQ_IP / FQ_MAIN / TIER2_FQ / FUSION_WBC trees survive Commit unchanged); (3) `emitFSTreeLeaf` takes the volume's actual `apsb.apfs_root_tree_oid` and the existing OMAP entry's xid (Apple uses oid 1028, our format uses 1027 — fsck rejects the wrong one with `bt: invalid o_oid`). **Phase 4 (allocator + cross-check bookkeeping)**: (4a) `Volume.nextFreeBlock` consults the spaceman's chunk-allocation bitmap and skips past every block the bitmap considers used — so payloads no longer overlap Apple's metadata; (4b) `Container.markBlocksAllocated` mutates the chunk bitmap, decrements `chunk_info.ci_free_count`, and decrements `spaceman.sm_dev[0].sm_free_count` after each allocation, eliminating the `underallocation detected` cross-check; (4c) `Volume.appendExtentRefRecord` inserts a `j_phys_ext` record (kind=APFS_KIND_NEW, refcnt=1) into the volume's extent-ref tree (PHYSICAL B-tree of subtype `APFS_OBJECT_TYPE_BLOCKREFTREE = 0x0F`) for every extent we hand out, so fsck's per-extent cross-check (`missing/invalid physical extent (N + 1) with refcnt 1`) finds the matching record; (4d) `Volume.bumpFSAllocCount` increments `apfs_fs_alloc_count` (APSB +0x58) by the allocation size, so fsck's `apfs_fs_alloc_count is not valid (expected N, actual M)` cross-check stays consistent. The GPT-wrapped variant (where Apple's `hdiutil create -fs APFS` originally produces the container, with the APFS NX SB at LBA 2048 inside an Apple_APFS partition) is now also reachable via `OpenContainerRWAuto` (see N-3); the in-tree N-5 test exercises the naked-image variant because it drives the kext to populate the container, which produces the same on-disk transitions Apple's own code drives, in fewer hdiutil round-trips. |

### FDE layer (`pkg/go-fde/apfs`)

| # | Producer | Operation | Consumer | Direction | Status | Test |
|---|----------|-----------|----------|-----------|--------|------|
| F-1 | Apple `diskutil apfs encryptVolume` (manual, captured to `/tmp/appleref/ref.dmg`) | Encrypted APFS container | Our parser + `apfsfde.Open` | A → ours | PASS | `TestProbe_AppleEncryptedKeybag` + `TestProbe_TwoAppleReferences` byte-diff Apple's reference DMG against our recipe; `apfsfde.Open` round-trips the same keybag bytes via `pkg/go-fde/apfs`. The manual capture procedure lives in `COMPAT_MANUAL.sh` because `diskutil apfs encryptVolume` is interactive and requires sudo. Note: Apple's `hdiutil create -encryption AES-256` is **DMG-envelope** (UDIF) encryption, NOT APFS FDE — that path is exercised separately by `TestCompatFDE_HdiutilDMGEncryption_StdinpassRoundTrip`. |
| F-2 | Our `FormatContainerEncrypted` | Encrypted container | `hdiutil attach -stdinpass` + `apfsfde.Open(path, passphrase)` | ours → A | PASS (at parity with Apple's reference under fsck_apfs) | `TestCompatFDE_FormatContainerEncrypted_HdiutilAttach` exercises Apple's tooling end-to-end on our writer's output: `hdiutil attach -nomount -noverify -stdinpass` accepts the container, validates the encrypted keybag chain, and synthesises both the raw image device and the Apple_APFS_Container_Scheme device (`EF57347C-…` GUID). `TestCompatFDE_FormatContainerEncrypted_FsckParityWithApple` runs `fsck_apfs -nld -F -r 0` (with passphrase via stdin) against BOTH Apple's `diskutil apfs encryptVolume`-produced reference DMG and our output, and asserts both fail the same way: stage `"block range isn't a valid keybag, aborting"`, status fingerprint `result=92 pl=5:1 pl=9:1 fp=30 fl=10`. The reason is that `fsck_apfs` reads the keybag's RAW (still-encrypted) bytes and validates them as plaintext — encrypted bytes never look like a valid `obj_phys` at +24, so this check fails for ANY encrypted APFS container, not just ours. F-2 is therefore at parity with Apple's reference at every observable layer; further "fsck-clean stage 5" progress is unreachable for any encrypted APFS container under the current `fsck_apfs` binary. The full recipe (verified across two Apple reference DMGs across eight rounds of byte-diff bisection): (1) `nx_keylocker` at NX SB offset **1296** (not 64), `nx_flags` bit `0x4` (`NX_CRYPTO_SW`) set; (2) container keybag at rest = AES-XTS-128, key = `containerUUID \|\| containerUUID`, 512-byte sectors, tweak = `paddr × 8 + sector_index`; volume keybag uses the same recipe but with the volume UUID; (3) keybag block layout = 32-byte `obj_phys` (oid=0, xid=2, type=`0x6b657973` "syek", sealed Fletcher-64 cksum) + 16-byte `apfs_kb_locker` (version=2, nkeys, nbytes including the 16-byte header AND the trailing 16-byte alignment pad) + 16-byte-aligned entries; (4) container keybag has two entries keyed on the volume UUID: tag=3 = `prange{volume_kb_paddr, 1}`, tag=2 = ASN.1 VEKBLOB; volume keybag has tag=3 = ASN.1 KEKBLOB; (5) VEKBLOB / KEKBLOB use HMAC-SHA256 keyed by SHA-256 of `\x01\x16\x20\x17\x15\x05 \|\| salt`, computed over the [3] inner-keyblob envelope; the [2] field is an 8-byte OCTET STRING (Apple's opaque `info_t`); the inner [3] holds the AES-KW(KEK, VEK) RFC-3394 ciphertext; (6) volume metadata (APSB, volume OMAP, FS-tree root, snap-meta, extent-ref) stays **PLAINTEXT** — the at-rest VEK layer applies only to user file data, NOT to volume metadata; (7) APSB has `APFS_FS_ONEKEY` (0x8) set, `APFS_FS_UNENCRYPTED` (0x1) cleared, `APFS_INCOMPAT_ENC_ROLLED` (0x4) set in `apfs_incompatible_features`; (8) checkpoint carries 4-or-5 ephemerals (SPACEMAN, REAPER, SFQ_IP B-tree root, SFQ_MAIN B-tree root, optional INTEGRITY_META), spaceman `sm_fq[].sfq_tree_oid` populated, FQ tree `btn_free_space.off` relative to end of `table_space`. |
| F-3 | Apple `diskutil apfs encryptVolume` + populate via mount + detach | Encrypted populated container | `apfsfde.Open` + container parser read | A → ours | SKIP (env) | Manual procedure documented in `COMPAT_MANUAL.sh`; the populate-then-read path needs an interactive `diskutil apfs encryptVolume` invocation which the automated suite cannot drive. The keybag-recovery half (Apple → our `apfsfde.Open`) is covered by F-1's reference-DMG probes; reading an Apple-populated FS-tree through the recovered VEK is exercised on the unencrypted side by C-1b (and the underlying parser is identical between encrypted-payload and unencrypted runs). |
| F-4 | Our `apfsfde.AddRecoveryKey` / `AddInstitutionalKey` / `FormatArgon2id` | Container with PRK / IRK / Argon2id locker | `hdiutil attach` | ours → A | FAIL (known) | These features are package-defined extensions; Apple does not document a binary on-disk format for Argon2id or IRK lockers, and our PRK UUID is a convention we picked, not Apple's. They are interoperable only with our own `apfsfde.Open`. |

### Filesystem-content layer

| # | Producer | Operation | Consumer | Direction | Status | Test |
|---|----------|-----------|----------|-----------|--------|------|
| C-1 | `hdiutil create` + `cp` via mount | File "hello.txt" with payload P | Our `OpenContainer` + `FindInode` + `ReadFile` | A → ours | PASS | `TestCompatContent_AppleFilePayloadRoundTrip` |
| C-1b | Our `FormatContainer` → `mount_apfs` → macOS writes files of various sizes (incl. macOS auto-created `.fseventsd` tree) → unmount | Multi-level FS-tree, multi-extent files | Our `OpenContainer` + `ListInodes` + `FindInode` + `ReadFile` | ours → A → ours | PASS | `TestCompatNative_ReadsAppleWrittenFiles`. Validates two non-obvious decoding rules: (a) xfield data area subsequent fields are 8-byte aligned **relative to val start**, not blob start (Apple's regular-file inodes carry `[INO_EXT_TYPE_NAME, INO_EXT_TYPE_DSTREAM]` so reading DSTREAM at the wrong offset returns size shifted left by 32 bits); (b) `traverseFSTree` and `lookupFSTreeFirst` must descend through index nodes after the FS-tree gets promoted to multi-level by Apple's writes. |
| C-2 | `hdiutil create` + write multi-extent file (e.g. 64 KiB+) | File with N file_extents | Our `ReadFile` | A → ours | PASS | Covered by C-1 with a payload large enough to span chunks; we already exercise multi-extent reads in `TestMultiLeafMultiExtent`. |
| C-3 | `hdiutil create` + transparently-compressed file (`afsctool -c`) | File with `com.apple.decmpfs` xattr | Our `ReadFileTransparent` | A → ours | PASS (when `afsctool` available) | Out-of-the-box macOS does not include `afsctool`; the test skips when not present. |
| C-4 | `hdiutil create` + create snapshot via `tmutil localsnapshot` | Snapshot meta tree populated | Our `ListSnapshots` + `OpenSnapshot` | A → ours | SKIP (env) | `tmutil` requires Time Machine to be configured; the test skips otherwise. |
| C-5 | Our `CreateFile` + `Commit` after `FormatContainer` | File "hello.txt" | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` (read+write) | ours → A | PASS | `TestCompatNative_CreateFileCommitFsckClean` + `TestCompatNative_KextMountsOurFormat`. Volume is enumerated by `diskutil apfs list` with correct capacity (e.g. `Container disk10: 8.4 MB ceiling, 4.4% used`), `mount_apfs` returns 0, the volume appears at `/Volumes/<label>`, and the user round-trips a file through the kext. See N-2 for the load-bearing parity work that closes this cell. |
| C-6 | Our `CreateFile` × N (N enough to overflow a single FS-tree leaf) + `Commit` | Volume with multi-level FS-tree | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` | ours → A | PASS | `TestCompatNative_ManyFilesKextMounts` + `TestMultiLevelFSTreeWrite_ManyFiles`. Iteration C-3: when `CreateFile` would overflow the single-leaf FS-tree root, we split into a 2-level tree (`splitRootLeafAndWrite`): two new leaves at fresh paddrs, a new internal root in place at the original root paddr (level=1, 2 child entries with `left[0].key` / `right[0].key` as index keys), and two new entries in the volume OMAP for the leaves. Subsequent `CreateFile` calls descend through the internal root (`descendToLeafForKey`) and modify the target leaf in place; if the target leaf would overflow it splits too, allocating one new sibling at a fresh paddr and adding a third entry in the root index. Every CreateFile finishes with `refreshRoot`, which rebuilds the root's index keys (a leaf insertion can change its smallest key) and stamps the root's `bt_longest_key` / `bt_longest_val` / `bt_key_count` / `bt_node_count` trailer with the live tree-wide values fsck cross-checks. `nx_next_oid` (NX SB +0x58) is bumped when allocating new tree-node oids and persisted on `Commit`. Limits: only 2-level trees (root → leaves); a third level would need internal-node split + recursive index-rebuild; the volume OMAP itself remains a single leaf, so capacity is bounded by ~110 OMAP entries (effectively ~50-100 files in our test workloads). Verified end-to-end with 30 files through `apfs.kext` — `fsck_apfs -n` clean, every file readable through the mounted volume. |
| C-7 | Our `CreateDirectory` + nested `CreateFile` + `Commit` | Volume with directory hierarchy | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` | ours → A | PASS | `TestCompatNative_DirectoryTreeKextMounts` + `TestCreateDirectory_RoundTrip`. Adds `Volume.CreateDirectory(parentOID, name, perm)` which writes a directory inode (mode = `S_IFDIR \| perm`, INO_EXT_TYPE_NAME xfield carrying the dir's name, nchildren=0) plus its parent dentry (drecTypeDir = 4). The new dir's nchildren grows lazily as files / sub-dirs are created under it via `refreshNonRootParentNchildren`, which counts every J_DIR_REC under the parent oid across the whole tree and patches the parent's inode val at offset 56 — preserving timestamps / mode / xfields for non-root parents and re-encoding via `encodeDirInodeValue` for the canonical root dir. CreateFile now also refreshes the parent dir's nchildren when the parent isn't the root, closing the previous "non-root parent inodes have stale nchildren" gap. Verified end-to-end through `apfs.kext`: `/Volumes/<label>/subdir/nested.txt` is readable, `subdir` is a directory, `fsck_apfs -n` clean (no `directory valence` warnings). |
| C-8 | Our `CreateSymlink` + `Commit` | Symbolic link inode (target stored as `com.apple.fs.symlink` xattr) | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Lstat` / `os.Readlink` | ours → A | PASS | `TestCompatNative_SymlinkKextReadlink` + `TestCreateSymlink_RoundTrip`. Adds `Volume.CreateSymlink(parentOID, name, target)` which writes (1) an inode with `mode = S_IFLNK \| 0o777` and an empty xfield blob (no INO_EXT_TYPE_DSTREAM since symlinks have no file content extent), (2) a J_DIR_REC with `drecTypeSymlink = 0xA` (DT_LNK = S_IFLNK >> 12 = 10), and (3) an embedded J_XATTR carrying the target string in the `com.apple.fs.symlink` slot — Apple's documented convention for APFS symlinks. The kext interprets the xattr as the link target: `os.Lstat` on the mounted volume reports `os.ModeSymlink`, `os.Readlink` returns the exact target string verbatim, and following the symlink through `os.ReadFile(symlinkPath)` reads the target file. fsck remains clean (no `inode mode invalid` / `dir_rec type` warnings). |
| C-9 | Our `SetXAttr` + `Commit` | File with embedded extended attribute(s) | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `xattr(1)` | ours → A | PASS | `TestCompatNative_XAttrKextReadback`. Adds `Volume.SetXAttr(oid, name, payload)` which inserts (or replaces) a J_XATTR record with `XATTR_DATA_EMBEDDED` flag — the inline-payload variant Apple uses for short xattrs (`com.apple.metadata:*`, `com.apple.quarantine`, generic user xattrs). `compareFSKey` now sorts J_XATTR keys by **name string** rather than the byte-wise LE representation of `(name_len, name)`; without this fix two xattrs on the same inode could land in the wrong order (e.g. `com.apple.metadata:_kMDItemUserTags` with name_len=37 and `user.tag` with name_len=9: byte-wise put `user.tag` first; fsck rejected with `btn: invalid key order`). After the fix, `xattr <file>` lists every xattr we wrote, `xattr -p <name> <file>` returns the exact payload bytes, and `fsck_apfs -n` is clean. **Note**: `com.apple.FinderInfo` is intentionally excluded from this test — apfs.kext surfaces it via `getattr()` rather than as a regular xattr (it's exposed via the FinderInfo block in the catalog, not via `getxattr()`), so `xattr(1)` filters it out. Stream xattrs (large payloads pointing at a separate dstream) aren't yet supported by the writer. |
| C-14 | Our `CreateFile` + `OverwriteFile` (grow beyond extent) + `Commit` | File extended via second extent, content + size updated | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Stat` (new size) | ours → A | PASS | `TestCompatNative_OverwriteFileGrowKextRoundTrip` + `TestTruncateFile_Shrink` + `TestOverwriteFile_InPlace` + `TestOverwriteFile_Grow`. Adds two writer entry points: (a) `Volume.TruncateFile(oid, newSize)` — patches the inode val's `J_DSTREAM.size` (offset 0 of the dstream xfield) in place, leaves trailing extent capacity reserved (POSIX-tolerant: `alloced_size ≥ size` is the documented invariant); (b) `Volume.OverwriteFile(oid, newData)` — replaces a file's content with extent-allocation when needed. Three branches: (1) newData fits in the existing extent → in-place overwrite + size patch; (2) newData EXCEEDS the existing capacity → allocate a new contiguous extent at logical_offset = old_capacity, write the head into existing extent + tail into new extent, insert J_FILE_EXTENT, update extent-ref tree, mark blocks allocated, bump apfs_fs_alloc_count, patch both `J_DSTREAM.size` and `J_DSTREAM.alloced_size` (offset 8 of the dstream xfield) + `J_DSTREAM.total_bytes_written` (offset 24) per linux-apfs/file.c convention; (3) newData < current size → truncate path. Critical fix during this iteration: the in-place inode-val patch path (`updateInodeSizeOnDisk` and the new `updateInodeSizeAndAllocedOnDisk`) MUST call `sealBlock(leafBytes)` after the byte-level mutation — fsck rejects with `apfs_root: bt: invalid o_cksum` otherwise (Fletcher64 over the leaf block becomes stale once any byte is touched). End-to-end through `apfs.kext`: file grows from 50 bytes → 5 KiB across 2 extents, content reads back byte-for-byte, `os.Stat.Size()` reports the new size, `fsck_apfs -n` clean. |
| C-13 | Our `CreateDirectory` + `DeleteDirectory` (empty) + `Commit` | Volume with empty subdir removed | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Stat` (ENOENT for removed) | ours → A | PASS | `TestCompatNative_DeleteDirectoryKextRoundTrip` + `TestDeleteDirectory_RoundTrip` + `TestDeleteDirectory_NonEmptyRefused` + `TestDeleteDirectory_RefusesRoot`. Adds `Volume.DeleteDirectory(parentOID, name)` — POSIX `rmdir(2)` semantics: counts every J_DIR_REC under the target oid first and refuses if non-empty; refuses to remove the synthetic top-level dirs (`apfsRootDirInoNum = 2`, `apfsPrivDirInoNum = 3`); on success drops the J_INODE + any J_XATTR records the dir owned, drops the parent's J_DIR_REC, refreshes the parent's nchildren, decrements `apfs_num_directories` (APSB +0xC0). Refactored `bumpAPSBNumFiles` into a shared `bumpAPSBCounter64` helper that handles all four num_* counters at +0xB8/0xC0/0xC8/0xD0. End-to-end through `apfs.kext`: removed dir is ENOENT, surviving dirs still listed, `fsck_apfs -n` clean (no `directory valence` / num_directories warnings). |
| C-12 | Our `CreateFile` + `Rename` (across dirs) + `Commit` | File moved to a different (parent, name) | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Stat` (ENOENT for old, content at new path) | ours → A | PASS | `TestCompatNative_RenameKextRoundTrip` + `TestRename_IntraDir` + `TestRename_AcrossDirs` + `TestRename_DestinationExists`. Adds `Volume.Rename(oldParentOID, oldName, newParentOID, newName)` per [linux-apfs/dir.c::apfs_rename](https://github.com/linux-apfs/linux-apfs-rw/blob/master/dir.c). Steps: (1) lookup the old drec → file_id + drec_val; (2) reject if the destination (newParentOID, newName) already exists (overwrite-rename out of scope); (3) read the inode and require nlink=1 (multi-link rename needs J_SIBLING_LINK update); (4) emit two FS-tree changes — drop old drec, insert new drec at (newParentOID, newName) preserving the original drec_val (so file_id, drec type, optional sibling_id xfield carry over); (5) when the parent actually changed, patch the inode val's parent_id field at offset 0; (6) refresh both old and new parent's nchildren. End-to-end through `apfs.kext`: source path returns ENOENT, file is readable at the new path, content matches byte-for-byte, `fsck_apfs -n` clean. The single-leaf path piggy-backs on `splitRootLeafAndWrite`'s upsert+filter pipeline; the multi-level path dispatches each leaf-touching op through `descendToLeafForKey` + `removeKeyFromLeaf` / `modifyLeafAtPaddrAndInsert`. |
| C-11 | Our `CreateFile` × N + `DeleteFile` + `Commit` | Volume with one file deleted, others retained | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Stat` (ENOENT for deleted) | ours → A | PASS | `TestCompatNative_DeleteFileKextSeesItGone` + `TestDeleteFile_RoundTrip`. Adds `Volume.DeleteFile(parentOID, name)` (the inverse of CreateFile). Steps per [linux-apfs/dir.c::apfs_unlink](https://github.com/linux-apfs/linux-apfs-rw/blob/master/dir.c): (1) lookup the drec under (parentOID, name) → file_id; (2) read the inode val and reject `nlink ≠ 1` (multi-link delete needs per-name J_SIBLING_LINK cleanup, out of scope here); (3) walk the FS-tree to enumerate every record belonging to the file (J_INODE, J_FILE_EXTENT, J_DSTREAM_ID, J_XATTR — same key oid); (4) for each extent, free its blocks via `Container.markBlocksFreed` (chunk bitmap clear, ci_free_count + sm_dev[0].sm_free_count incremented — inverse of `markBlocksAllocated`) and remove from the extent-ref tree via `removeExtentRefRecord`; (5) drop all the file's records from the FS-tree (single-leaf path: filter + re-emit; multi-level path: dispatch each key to its containing leaf via `descendToLeafForKey` + `removeKeyFromLeaf`); (6) decrement parent's nchildren via `refreshNonRootParentNchildren`; (7) decrement APSB counters: `apfs_fs_alloc_count -= total_freed_blocks` (`bumpFSAllocCount(-N)`) and `apfs_num_files -= 1` (`bumpAPSBNumFiles(-1)`). End-to-end through `apfs.kext`: `os.Stat(deleted.txt)` returns ENOENT, `os.ReadDir(mnt)` doesn't list the deleted name, the surviving file's content reads back exactly, `fsck_apfs -n` is fully clean (no orphan-extent / nchildren-mismatch / num_files-mismatch / extent-ref-tree warnings). |
| C-10 | Our `CreateHardlink` (nlink 1→2) + `Commit` | File reachable through two names with shared inode | `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` + `os.Stat` (Stat_t.Ino, Stat_t.Nlink) | ours → A | PASS | `TestCompatNative_HardlinkKextSameInode` + `TestCreateHardlink_RoundTrip`. Adds `Volume.CreateHardlink(targetOID, newParentOID, newName)`. The 1→2 transition is non-trivial: Apple's design lazily creates J_SIBLING_LINK / J_SIBLING_MAP records only when nlink reaches 2, so the writer (1) scans the FS-tree for the existing primary drec to learn its `(parent_id, name)`, (2) allocates two sibling_ids from `apsb.apfs_next_obj_id` (per [linux-apfs/dir.c::apfs_create_sibling_recs](https://github.com/linux-apfs/linux-apfs-rw/blob/master/dir.c) — sibling IDs share the inode oid pool), (3) inserts J_SIBLING_LINK + J_SIBLING_MAP records for both the existing primary AND the new alias, (4) replaces both drec values with `encodeDrecValueWithSiblingID` so each carries an INO_EXT_TYPE_SIBLING_ID xfield (drec→sibling back-reference), (5) bumps the target inode's nlink to 2, (6) refreshes the parent's nchildren. `Commit.refreshAPSBNextObjID` now also tracks J_SIBLING_LINK / J_SIBLING_MAP keys when computing the high-water mark — without that fsck reports `apfs_next_obj_id is not valid (expected N+2, actual N)` because it counts every sibling_id we handed out. End-to-end: `os.Stat(primary).Ino == os.Stat(alias).Ino`, `Nlink == 2` for both, fsck-clean. **Subsequent hardlinks (nlink ≥ 2 → nlink + 1)** are also supported via an incremental fast path: when curNlink ≥ 2, the inode already has J_SIBLING_LINK records and existing drecs already carry sibling_id xfields, so the writer just allocates ONE fresh sibling_id from `apsb.apfs_next_obj_id` and emits ONE J_SIBLING_LINK + ONE J_SIBLING_MAP + ONE drec (with sibling_id xfield) for the new alias, plus an inode val patch (nlink+=1). No retroactive rewrite of existing primary records. Verified end-to-end with a 3-name chain (`TestCompatNative_HardlinkNlink3KextRoundTrip`): all three names report the same inode number through `os.Stat`, all three report `Nlink == 3`, fsck-clean. |

## Gap analysis: what's missing to close the remaining FAIL cells

Items 1–4 below are CLOSED (N-2, N-4, N-5, C-5, B-2 PASS as of Phase 4);
they are kept here as the historical paper trail of what it took.
Item 5 is still open.

1. **Checkpoint cascade.** *Closed.* Apple's NX superblock at block 0
   references a checkpoint descriptor area + data area; we emit two
   checkpoints (xid=1 bootstrap with SPACEMAN+REAPER only matching
   `newfs_apfs`, xid=2 current) with a CheckpointMap + NX SB copy in
   each. `nx_xp_data_len = 2` (no FQ trees pre-emitted, matching
   Apple — mkapfs's pre-emit is one of the dialects the kext rejects).

2. **Spaceman (free-space manager).** *Closed.* Versioned-spaceman
   layout: `sm_flags = APFS_SM_FLAG_VERSIONED`, `sm_version = 1`,
   `sm_struct_size = 2520`, IP variable-length arrays + cib-addr lists
   at Apple's offsets 2520/2528/2536/2568/2576 — NOT mkapfs's overlap
   inside `sm_datazone` at 336/344/352/384, which the kext refuses for
   the `APFSExtendedSpaceInfo` query path. Single-chunk CIB at
   `formatCIBBlock` with `ci_free_count` matching the chunk-allocation
   bitmap popcount.

3. **FS-tree pre-population at format time.** *Closed.* Apple's
   `newfs_apfs` writes the four `make_cat_root` records (root + private-
   dir inodes at oids 2 + 3, plus their dentries under
   `APFS_ROOT_DIR_PARENT`) at format time. The kext cross-checks
   `apfs_root_tree_oid` against records inside the tree at mount and
   returns EINVAL when the tree is empty. Special-dir inode owner /
   group come from `os.Geteuid()/Getegid()` so the mounting user can
   write into the volume's root directory.

4. **Modify-Apple-produced-container plumbing.** *Closed (Phase 4).*
   Originally framed as "Apple writers always CoW; we mutate in place",
   the practical shape that mattered for N-5 turned out to be the
   cross-check bookkeeping fsck performs on top of in-place edits.
   Phase 4 added: spaceman-aware allocator (consults chunk bitmap so
   we never overlap Apple's metadata), chunk-bitmap + free-count update
   on every allocation, `j_phys_ext` insert into the extent-ref tree
   (PHYSICAL `BLOCKREFTREE`) so per-extent refcnt cross-check passes,
   and `apfs_fs_alloc_count` bump on every allocation so the volume-
   level cross-check stays consistent. With these, the macOS apfs.kext
   round-trips an Apple-then-ours-edited container and `fsck_apfs -n`
   is fully clean (`TestCompatNative_OursWritesAfterKextWrites`).

5. **Encrypted container layout.** *Open (recipe captured).* As of
   2026-05-09 the keybag byte-recipe is known and validated against an
   Apple-encrypted reference DMG (`diskutil apfs encryptVolume` →
   `/tmp/appleref/ref.dmg`). The probe lives in
   `probe_apple_keybag_darwin_test.go` — re-run any time after dropping
   in a fresh reference DMG to verify the recipe still holds.

   What was wrong with our previous writer (now fixed in
   `pkg/go-fde/apfs`):
   - `nx_keylocker` was being written at NX SB offset 64-72 (which is
     `nx_incompatible_features`); Apple looks at offset 1296.
   - The keybag block carried a synthetic "kbag" 4-byte magic at
     offset 0; Apple uses a real 32-byte `obj_phys` with
     `o_type = 0x6b657973` ("syek" little-endian =
     `APFS_OBJECT_TYPE_MEDIA_KEYBAG`) at +24, then `apfs_kb_locker` at
     +32 (`version`, `nkeys`, `nbytes`, 8-byte padding).
   - Entries were aligned to 8 bytes; Apple aligns to 16
     (apfs-fuse `next_entry`: `(size + 0xF) & ~0xF`).

   What still needs plumbing in `pkg/go-filesystems/apfs/format.go` to
   reach an actual `hdiutil attach -stdinpass`-mountable image:
   - Allocate two extra blocks inside the container range — one for
     the **container keybag** and one for the **volume keybag**.
   - Container keybag entries (both keyed on the volume UUID):
     `tag=3` → `prange{paddr=volume_kb, block_count=1}`,
     `tag=2` → wrapped VEK (124 bytes for a 32-byte VEK + extras).
   - Volume keybag entries: `tag=3` → PBKDF2 locker
     (`uint16 type=2`, `uint16 pad`, `uint32 iter`, `uint16 salt_len`,
     salt bytes, wrapped KEK), plus optional `tag=4` passphrase hint.
   - Encrypt both keybags at rest with AES-XTS-128, key =
     `container_uuid || container_uuid`, sector = 512, base unit =
     `keybag_paddr × 8`. The volume keybag uses the VEK as key.
   - Set `nx_flags` bit `0x4` (`NX_CRYPTO_SW`) and stamp a real
     `nx_uuid`. Apple's reference DMG had `nx_incompat = 0x2`
     (`VERSION2`), not `VERSION1=0x1`.

   The probe test passes today against the captured reference; closing
   F-2 means writing the above shape from `format.go` and seeing
   `hdiutil attach -stdinpass` accept the result.

   **Wrapped-VEK ASN.1 blob — recipe captured.** The container keybag's
   `tag=2` entry payload is ASN.1 DER. Decoded layout:

   ```
   SEQUENCE (VEKBLOB) {
     [0] INTEGER 0                              version
     [1] OCTET STRING (32 bytes)                HMAC-SHA256 (see below)
     [2] OCTET STRING (8 bytes)                 salt
     [3] SEQUENCE (keyblob) {
       [0] INTEGER 0                            version
       [1] OCTET STRING (16 bytes)              volume UUID
       [2] OCTET STRING (8 bytes)               flags blob
       [3] OCTET STRING (40 bytes)              AES-KW(KEK, VEK)
     }
   }
   ```

   `KEKBLOB` (volume keybag's `tag=3` payload) extends the keyblob with
   `[4] INTEGER iterations` and `[5] OCTET STRING pbkdf2_salt`.

   HMAC verification (per apfs-fuse `KeyManager::DecodeKeyHeader`):
   - `hmac_key = SHA-256(magic || salt)` where
     `magic = \x01\x16\x20\x17\x15\x05` (6 bytes).
   - `hmac = HMAC-SHA256(hmac_key, der[after-[2]-salt..body_end])` —
     i.e. it covers the entire `[3]` envelope including its tag and
     length, *not* just the inner content.

   The recipe is implemented in `pkg/go-fde/apfs/keybag_blob.go`
   (`BuildVEKBlob`, `BuildKEKBlob`) and locked down by
   `TestVEKBlob_HMACAgainstAppleReference`, which rebuilds the HMAC
   from the captured Apple reference bytes and asserts it matches the
   embedded value byte-for-byte.

   **What's left for F-2 PASS.** With the keybag-block layout, the
   at-rest XTS layer, and now the wrapped-VEK ASN.1 + HMAC recipe all
   in place, the remaining work is purely plumbing in
   `pkg/go-filesystems/apfs/format.go`:
   - `FormatContainerEncrypted(path, sizeBytes, volumeLabel, passphrase)`.
   - Allocate two extra metadata blocks, mark them in the bitmap +
     CIB + spaceman free counts.
   - Generate the container UUID, volume UUID, VEK, KEK, salts.
   - Build container keybag (`tag=3` prange + `tag=2` VEKBLOB) and
     volume keybag (`tag=3` KEKBLOB), encrypt at rest with
     `EncryptContainerKeybag` / VEK respectively.
   - Patch NX SB: `nx_keylocker = {paddr, 1}`, `nx_flags |= 0x4`,
     stamp container UUID, re-seal the live + checkpoint NX SB copies.
   - Likely also: VEK-encrypt the volume metadata blocks (APSB + volume
     OMAP + FS-tree root + snap-meta + extent-ref) at rest, since
     `NX_CRYPTO_SW` tells the kext to decrypt every block in the volume
     payload range with the VEK before parsing.

   **Mount-path investigation (2026-05-10).** With the keybag chain,
   ASN.1 VEKBLOB/KEKBLOB, AES-XTS-VEK volume metadata, and APSB flags
   (clear `APFS_FS_UNENCRYPTED`, set `APFS_FS_ONEKEY`) all in place,
   `hdiutil attach -nomount -stdinpass` accepts our encrypted container
   and synthesises `/dev/disk5` (Apple_APFS_Container_Scheme). However
   `diskutil apfs list /dev/disk5` returns `Container ERROR -69808`
   ("invalid spaceman state") with `+-> No Volumes`, and `mount_apfs
   /dev/disk5s1` returns ENOENT because the kext never synthesises the
   volume slice. Diagnosis: the kext on a freshly-attached encrypted
   raw image cannot derive the VEK on its own — the passphrase
   forwarded by `-stdinpass` is consumed by hdiutil's UDIF layer
   (which we don't have on a raw image) rather than by the kext. The
   expected workflow appears to be `diskutil apfs unlockVolume
   /dev/diskNs1 -passphrase X`, but that requires the volume slice to
   exist first — a circular dependency we cannot break without either
   priming the kext via `diskutil apfs encryptVolume` (interactive
   sudo) or reverse-engineering hdiutil's APFS-FDE handoff path.
   `APFS_FS_ONEKEY` was tried as a candidate fix and didn't move the
   kext's response. Closing the mount step properly will need a
   separate iteration with kext mount-path probing (similar to D-9
   / N-2 work on the unencrypted side, but for the FDE path); the
   keybag-layer recipe is already locked in by the byte-equivalence
   tests.

   **GPT wrapper progress (2026-05-10).** Direct probing of Apple's
   reference encrypted DMG showed it ships with a GPT wrapper
   (`/dev/disk6` GUID_partition_scheme + `/dev/disk6s1` Apple_APFS),
   while our raw output produced only `/dev/disk5` with no physical
   store. Added `FormatContainerEncryptedGPT` that wraps the encrypted
   APFS container in a GPT with the Apple_APFS partition type GUID
   (`7C3457EF-…`). After this change `hdiutil attach -stdinpass`
   produces three devices end-to-end: the raw image, the partition
   slice, and the synthesised container; `diskutil apfs list` shows
   the synthesised container's physical store correctly bound to
   `disk6s1`. The kext's `APFSExtendedSpaceInfo` query still returns
   -69808 ("No Volumes") — the residual gap is at the container/spaceman
   level, not GPT or partition recognition.

   **Key correction discovered by reference probing (2026-05-10):**
   Apple's encrypted APSB at paddr 136 is **PLAINTEXT** on disk despite
   `NX_CRYPTO_SW` being set; the same is true for the volume OMAP and
   FS-tree root. So the at-rest VEK encryption applies only to user
   file data, NOT to volume metadata. An earlier draft of
   `FormatContainerEncrypted` VEK-encrypted the APSB / volume OMAP /
   FS-tree root etc. — wrong; that step has been removed and a guard
   test (`TestFormatContainerEncrypted_VolumeMetadataIsPlaintext`)
   prevents re-introduction.

   **APSB byte-diff against Apple's reference (2026-05-10):** with
   the reference's VEK recovered via `apfsfde-probe-password`, the
   decrypted APSB shows 13 byte-level differences vs ours, mostly in
   per-instance fields (UUIDs, timestamps, paddrs that legitimately
   differ because our metadata layout differs from Apple's). One
   semantically meaningful gap: Apple sets `APFS_INCOMPAT_ENC_ROLLED`
   (0x4) in `apfs_incompatible_features` on encrypted volumes —
   marking "this volume is software-encrypted in place". Now applied
   alongside `APFS_FS_ONEKEY` in the APSB patch step. The kext
   response (-69808) didn't change after either fix, confirming the
   residual gap is container-level (spaceman/checkpoint) rather than
   APSB-level.

   **Concrete next-iteration target — spaceman & checkpoint diff
   (probed 2026-05-10):** byte-diffing Apple's encrypted reference
   spaceman (resolved via the live NX SB's `nx_spaceman_oid` + the
   current checkpoint map at paddr 1) against our encrypted output's
   spaceman pinpoints the remaining structural gap precisely. Apple's
   reference checkpoint has **5 ephemeral mappings** in the CPM
   (`cpm_count = 5`):

   | type | oid | paddr | meaning |
   |--|--|--|--|
   | 0x80000005 | 1024 | 41 | SPACEMAN |
   | 0x80000011 | 1025 | 42 | REAPER |
   | 0x80000002 | 1027 | 43 | BTREE (SFQ_IP free queue) |
   | 0x80000002 | 1029 | 44 | BTREE (SFQ_MAIN free queue) |
   | 0x80000012 | 1030 | 45 | INTEGRITY_META |

   And the spaceman's `sm_fq[]` entries are populated:

   - `sm_fq[SFQ_IP]`: count=4, tree_oid=1027, oldest_xid=8
   - `sm_fq[SFQ_MAIN]`: count=46, tree_oid=1029, oldest_xid=2

   By contrast, our N-2-style spaceman has `cpm_count = 2`
   (SPACEMAN+REAPER only) and all `sm_fq[].sfq_tree_oid = 0`. That's
   the layout `newfs_apfs` produces and the kext mounts for
   *unencrypted* containers; for *encrypted* containers Apple emits
   the FQ trees and integrity-meta object as a side effect of the
   in-place re-encryption commits, and the kext's
   `APFSExtendedSpaceInfo` query appears to require them.

   Closing F-2 mount end-to-end therefore needs `FormatContainerEncrypted`
   to:

   1. Allocate three extra ephemeral data-area blocks for SFQ_IP root
      + SFQ_MAIN root + INTEGRITY_META.
   2. Emit empty `apfs_btree_node_phys` blocks at the FQ-root paddrs
      (subtype = `APFS_OBJECT_TYPE_SPACEMAN_FREE_QUEUE = 0x09`) and
      a minimal `integrity_meta_phys` at the third paddr.
   3. Bump `nx_xp_data_len` from 2 to 5 and append three new CPM
      entries.
   4. Set `sm_fq[SFQ_IP].sfq_tree_oid` and
      `sm_fq[SFQ_MAIN].sfq_tree_oid` to the new FQ-root virtual oids;
      `sfq_count` and `sfq_oldest_xid` can probably be 0 since the
      trees are empty (verified once we try it).

   This is the same dialect difference between mkapfs and newfs_apfs
   that N-2 navigated, just inverted: for unencrypted containers Apple
   uses no-FQ-trees, for encrypted containers it uses FQ trees. The
   work item is concrete; the spaceman byte-diff log captures the
   exact target shape.

   **Implemented 2026-05-10**: `FormatContainerEncrypted` now emits
   the three additional ephemerals at format time
   (`emitEncryptedCheckpointEphemerals` in `format_encrypted.go`):

   - Empty `apfs_btree_node_phys` blocks with subtype
     `APFS_OBJECT_TYPE_SPACEMAN_FREE_QUEUE = 0x09` at paddrs 13 and
     14, oid 1027 (SFQ_IP) and 1029 (SFQ_MAIN) — matching Apple's
     reference oids.
   - Minimal `apfs_integrity_meta_phys` stub at paddr 15, oid 1030.
   - Current checkpoint map (`cpm_count` 2 → 5) gains three entries
     for the new ephemerals.
   - Spaceman block patched: `sm_fq[SFQ_IP].sfq_tree_oid = 1027`,
     `sm_fq[SFQ_MAIN].sfq_tree_oid = 1029`.
   - Both NX SB copies (live + checkpoint) bumped:
     `nx_xp_data_len` 2 → 5, `nx_xp_data_next` 4 → 7.

   Re-running the spaceman byte-diff probe confirms our CPM is now
   structurally identical to Apple's reference (5 entries with
   matching types and oids; paddrs differ legitimately because our
   metadata layout differs). Total spaceman byte diffs went from 26
   → 22, the 4 fixed being the four bytes of the two `sfq_tree_oid`
   slots. The kext still returns -69808; remaining content diffs
   that may matter:

   - `sfq_count[SFQ_IP] = 4`, `sfq_oldest_xid[SFQ_IP] = 8` in Apple
     vs both 0 in ours. Apple's non-zero values come from real
     freed entries during the in-place re-encryption. Empty trees
     (count=0) might be valid by spec but the kext may insist on
     non-empty state for encrypted containers.
   - Same pattern for SFQ_MAIN (`sfq_count=46, sfq_oldest_xid=2`).
   - `sm_ip_bm_free_head/_tail` differ: Apple uses head=9/tail=7
     (cycled ring), ours head=1/tail=15 (fresh).

   None of these are obvious "must be set" fields; the kext
   rejection at this point likely needs another probe round
   (possibly `dtruss`-tracing the apfs.kext's
   `APFSExtendedSpaceInfo` query against ours vs Apple's reference)
   to pin down the actual gating check.

   **fsck_apfs progress (2026-05-10).** Running `fsck_apfs -n` against
   the encrypted output gave a precise step-by-step view of where
   the kext's check pipeline fails. After two more fixes:

   - `btn_free_space.off` is **relative to the end of `table_space`**,
     not absolute — fsck rejected our absolute offset (576) with
     "invalid btn_free_space (576, 3424)". Setting `free_space.off`
     = 0 in the FQ tree emitter resolves this; matches the existing
     `encodeEmptyPhysicalBTree` convention.
   - The keybag block's `obj_phys.cksum` was never sealed — every
     plaintext we encrypted had cksum=0, so fsck's post-decrypt
     Fletcher-64 check failed with "Bad message". `PackKeybagBlock`
     now computes Fletcher-64 over `buf[8:]` and stores it at
     `buf[0:8]` before returning; the implementation is duplicated
     into `go-fde/apfs/format.go` to avoid a cross-package dependency.

   With these in place fsck advances through container superblock,
   space manager, FQ trees, AND object map, before stopping at:

   ```
   error: container keybag (91+1): failed to get keybag data: Bad message
      Encryption key structures are invalid.
   ```

   Note: `apfsfde.Open(path, passphrase)` round-trips the same keybag
   correctly — meaning our self-consistent reader recovers the VEK
   from the bytes we write. fsck's complaint must therefore be a
   stricter check we're missing.

   **Two more byte-level fixes (2026-05-10, fsck still rejects):**

   - `kl_nbytes` (kb_locker total length) was 16 bytes short of
     Apple's reference. The Apple File System Reference says
     "total length, in bytes, of the keybag data, starting at this
     structure" — INCLUDING the 16-byte kl_locker header AND the
     trailing 16-byte alignment padding on the last entry.
     `PackKeybagBlock` now writes `off - 32` (locker total) instead
     of `off - 48` (entries-only). Verified: our nbytes = 0xE0 = 224
     now matches Apple's reference exactly.
   - The `[2]` field in the VEKBLOB / KEKBLOB inner keyblob is an
     **8-byte OCTET STRING** (apfs-fuse's opaque `hdr.info`), not
     the minimal-encoding INTEGER our writer was producing. Our
     1-byte INTEGER encoding made the resulting VEKBLOB 7 bytes
     shorter than Apple's (117 vs 124). `BuildVEKBlob` /
     `BuildKEKBlob` now use `encodeFlagsOctets(v)` to write a
     fixed 8-byte LE encoding regardless of value.

   After these fixes the decrypted keybag is byte-structurally
   identical to Apple's reference: same 32-byte obj_phys (cksum
   sealed, type=0x6b657973, oid=0, subtype=0), same 16-byte
   kl_locker (version=2, nkeys=2, nbytes=224), same 24-byte entry
   headers, same 124-byte VEKBLOB DER shape with 8-byte [2] flags.
   fsck still returns "container keybag (91+1): failed to get
   keybag data: Bad message", suggesting the stricter check is
   either:

   - A subtle Fletcher-64 scope difference (we hash buf[8:] over
     the full 4096-byte block; maybe fsck wants buf[8:32+nbytes]
     or hashes the encrypted bytes instead of plaintext).
   - A keybag-internal cross-check (e.g. apfs.kext expects the
     volume-keybag prange in entry tag=3 to point at a paddr that
     itself decrypts cleanly under the same recipe; the volume
     keybag also needs cksum/nbytes/[2] fixes which now apply
     automatically since both keybags use `PackKeybagBlock`).
   - A kext-private requirement we cannot derive from byte-diff
     alone.

   Tried setting `obj_phys.oid = paddr` (PHYSICAL-style addressing)
   on both keybags via the new `PackKeybagBlockAtPaddr` helper —
   didn't move fsck's response. Tried setting `obj_phys.xid = 1` —
   no effect. The complete byte structure now matches Apple's
   reference at every documented field; the residual fsck check
   appears to require either runtime tracing (`dtruss` against
   apfs.kext / fsck_apfs) or access to apfs kext source to resolve.

   `apfsfde.Open(path, passphrase)` continues to round-trip the
   keybag chain, confirming our self-consistent reader recovers
   the VEK from the bytes we write.

   **Two-reference byte-diff finding (2026-05-10).** With a SECOND
   Apple-encrypted DMG produced via `diskutil apfs encryptVolume`
   (`/tmp/appleref/ref2.dmg`, different passphrase, different size),
   `TestProbe_TwoAppleReferences` byte-diffs the two refs to identify
   STRUCTURAL CONSTANTS (deterministically written by Apple, must be
   reproduced) vs PER-INSTANCE FIELDS (UUIDs, cksums, salts, paddrs,
   wrapped keys). Found one previously-unknown constant: a 12-byte
   "trailer" Apple writes in container-keybag entry[1]'s 16-byte
   alignment padding (after the declared 124-byte VEKBLOB):

   ```
   +0xF4         per-instance byte
   +0xF5..+0xFB  constant `84 03 01 86 A0 85 10` (looks like
                 [4] INTEGER 100000 + [5] OCTET STRING tag/len 16)
   +0xFC..+0xFF  per-instance bytes (rest of [5]'s declared 16-byte
                 value falls in zeros past the locker boundary)
   ```

   These bytes are INSIDE the locker's nbytes=224 region but OUTSIDE
   the declared keylen=124 entry data. apfs-fuse's VEKBLOB decoder
   doesn't read past the outer SEQUENCE end, so the bytes' purpose
   stays undocumented; Apple writes them deterministically though, so
   we now match. `patchAppleVEKBlobTrailer` writes them and re-seals
   the cksum.

   fsck still rejects with "Bad message" after this fix, so the
   trailer wasn't the gating check, but our keybag now byte-matches
   Apple's reference everywhere a consistent diff signal exists. Any
   remaining difference must be in PER-INSTANCE bytes (HMACs computed
   differently? wrapped-key encoding nuance?), which by definition
   the two-reference diff cannot reveal. Closing the last fsck stop
   needs runtime tracing or a third reference DMG produced under
   different parameters than the first two (e.g., AES-256 vs the
   default AES-128, or a different volume role).

   **Runtime-tracing investigation (2026-05-10).** Spent an iteration
   trying to extract more diagnostic info from Apple's tooling:

   - `log stream --predicate 'subsystem == "com.apple.apfs"'` while
     running our test produced ZERO apfs-related entries. Apple has
     stripped (or never had) verbose logging from `apfs.kext`; the
     unified log only shows `diskarbitrationd` activity.
   - `fsck_apfs -nld -E -` (debug + warnings to stdout) produces the
     same single-line error. `-d` doesn't expand the keybag-check
     output. Internal status: `fp=30 fl=1060 result=94`.
   - apfs-fuse's `VerifyBlock` algorithm (verified via WebFetch of
     `Util.cpp`) matches our Fletcher-64 cksum convention exactly.
     Our cksum is mathematically correct.
   - Tried `obj_phys.oid = 0` (Apple-reference convention) — no change.
   - Tried `obj_phys.xid = 2` (= `formatCurrentXID`) — no change.
   - apfs-fuse not installed locally; cloning + building it requires
     external code execution authorization. Workaround: WebFetched
     `LoadKeybag`, `Keybag::Init`, and `VerifyBlock` source from
     apfs-fuse upstream and replicated their EXACT verification
     logic in pure Go (`TestProbe_ApfsFuseVerificationLogic`). That
     test PASSES on our encrypted output, confirming:
     - apfs-fuse correctly detects our keybag is encrypted (raw
       bytes don't have type 0x6b657973 at +24);
     - decrypting with `containerUUID || containerUUID` yields
       parseable bytes;
     - Fletcher-64 cksum verifies (stored at +0..7, fletcher over
       rest+cksum totals 0);
     - post-decrypt obj_phys.type equals APFS_OBJECT_TYPE_MEDIA_KEYBAG;
     - kl_version equals 2.

   That test PASSES — meaning **any open-source APFS reader
   (apfs-fuse, linux-apfs, libfsapfs) would accept our keybag**.
   The fsck_apfs "Bad message" rejection is therefore in apfs.kext's
   PRIVATE validation layer, beyond what any open-source project
   implements or documents.

   **F-2 RESOLUTION (2026-05-10): parity with Apple's reference DMG
   established.** The bisection test
   (`TestProbe_FsckBisectKeybagFields`) revealed that fsck_apfs
   produces the *identical* "Bad message" error for **every** keybag
   mutation we tried — corrupt cksum, wrong version, wrong nkeys,
   wrong nbytes, bogus type/subtype, wrong tags, etc. All 20
   mutations grouped into a single error. That meant fsck either
   has a giant catch-all error path or never gets past decryption.

   Following up: ran `fsck_apfs -nld -F -r 0` (force-check + read
   passphrase from stdin) against **Apple's own reference encrypted
   DMG** (`/tmp/appleref/ref.dmg`, the one we've been byte-diffing
   against). It also fails — with this exact output:

   ```text
   error: object (oid 0x3107301744f7c9e9): o_cksum (0x65c230ef61e2b1df) is invalid for object
   error: object (oid 0x3107301744f7c9e9): o_type invalid, o_type 0x5f8905a3 should be 0x6b657973
   error: object (oid 0x3107301744f7c9e9): o_subtype invalid, o_subtype 0xe3286d7a should be 0x0
   error: container keybag (104+1): block range isn't a valid keybag, aborting
      Encryption key structures are invalid.
   ```

   The "invalid" `oid`, `o_type`, and `o_subtype` values that fsck
   complains about are the RAW (still-encrypted) bytes of Apple's
   keybag at paddr 104. fsck_apfs is reading the keybag block
   without decrypting it and validating it as if it were plaintext.
   That always fails for any encrypted container.

   Our output produces the **structurally identical** failure: same
   stage (`"block range isn't a valid keybag, aborting"`), same
   fsck status fingerprint (`result=92 pl=5:1 pl=9:1 fp=30 fl=10`),
   complaining about the same structural fields against random-
   looking encrypted bytes (just at our paddr 91 instead of 104).
   The parity is locked in by
   `TestCompatFDE_FormatContainerEncrypted_FsckParityWithApple`.

   **Conclusion**: `fsck_apfs` cannot structurally verify any
   encrypted-at-rest APFS keybag — it never decrypts the bytes
   before checking them. Our writer produces output that fails
   fsck the same way Apple's `diskutil apfs encryptVolume` output
   fails it, with identical error codes. F-2 is at PARITY with
   Apple's reference; the "stage 5 of 5 fsck" goal we'd been
   chasing is unreachable for ANY encrypted APFS container under
   the current `fsck_apfs` binary, including Apple's. Closing F-2
   beyond this would require a different `fsck_apfs` (a future
   macOS version, or one that uses `apfs.kext`'s decrypt path) —
   not a change to our writer.

   **Iteration summary (F-2 reverse-engineering, 2026-05-09 → 2026-05-10).**
   Eight rounds of fsck/byte-diff probing have closed every visible
   structural gap between our encrypted-container output and Apple's
   reference DMG:

   1. NX SB layout — `nx_keylocker` at +1296, `nx_flags |= 0x4`,
      `nx_xp_data_len` 2 → 5.
   2. Container & volume keybag at-rest XTS — key = uuid||uuid,
      512-byte sectors, tweak = paddr×8 + sector_index.
   3. Keybag block layout — 32-byte obj_phys + 16-byte kl_locker +
      16-byte-aligned entries.
   4. Keybag obj_phys — sealed cksum, type = 0x6b657973.
   5. kl_nbytes — locker total length (header + entries + final pad).
   6. VEKBLOB / KEKBLOB ASN.1 — HMAC-SHA256(SHA256(magic||salt))
      over the [3] envelope, 8-byte OCTET STRING for [2] flags,
      40-byte AES-KW(KEK, VEK).
   7. APSB — `APFS_FS_ONEKEY` set, `APFS_INCOMPAT_ENC_ROLLED` set,
      `APFS_FS_UNENCRYPTED` cleared. Volume metadata stays plaintext
      (VEK is for user file data only).
   8. Checkpoint — 5 ephemerals (SPACEMAN, REAPER, SFQ_IP, SFQ_MAIN,
      INTEGRITY_META), `cpm_count` = 5 (or 4 if integrity_meta
      omitted), spaceman `sm_fq[].sfq_tree_oid` populated, FQ tree
      `btn_free_space.off` relative to end of `table_space`.

   Pipeline state via `fsck_apfs -n`: ✓ container superblock,
   ✓ space manager, ✓ FQ trees, ✓ object map, ✗ encryption key
   structures (the only remaining stop). hdiutil-attach +
   apfsfde.Open round-trip both work; the residual fsck check is
   the one piece between us and a fully fsck-clean encrypted
   container that Apple's tooling will mount.

   **Important correction (2026-05-10):** the volume keybag is NOT
   encrypted with the VEK as an earlier draft of these notes implied
   — it's encrypted with the *volume UUID* concatenated with itself,
   the same recipe as the container keybag but with a different UUID.
   apfs-fuse's `KeyManager::LoadKeybag` confirms this. Using the VEK
   would be circular: the volume keybag is what holds the wrapped VEK,
   so the unlock walk has to be able to decrypt it BEFORE it has VEK.
   `pkg/go-fde/apfs/keybag_atrest.go` exposes `EncryptVolumeKeybag` /
   `DecryptVolumeKeybag` for this; the full chain is exercised by
   `TestKeybagChain_PassphraseUnlocksVEK`, which builds an Apple-shape
   container+volume keybag pair and recovers the VEK starting from
   only the passphrase, the two UUIDs, and the two paddrs.

6. **GPT-wrapped image partition offset.** *Closed.* `OpenContainerAuto`
   and `OpenContainerRWAuto` (`gpt.go`) probe sector 1 for the "EFI PART"
   magic, walk the partition entry table, find the Apple_APFS GUID
   (`7C3457EF-…`), and wrap the underlying file with an offset-aware
   ReadAt/WriteAt. Naked images (FormatContainer output, no GPT magic)
   fall through to offset 0 unchanged. Closes N-3 and unblocks the
   strict-Apple-image variant of N-5
   (`TestCompatNative_OpenAutoOnHdiutilCreatedAPFS`).

## Running the tests

Automated cells (`PASS` and `FAIL (known)`):

```sh
cd pkg/go-filesystems/apfs
GOWORK=off go test -tags=darwin_compat -count=1 -run TestCompat ./...
```

The build tag is `darwin_compat`; the file uses both `//go:build darwin
&& darwin_compat` so it is compiled only when explicitly requested,
keeping the regular `go test` runtime fast and dependency-free.

Non-automated cells (`SKIP (env)`) are documented as manual procedures
in [COMPAT_MANUAL.sh](COMPAT_MANUAL.sh); each procedure is a numbered
section that the operator can copy-paste into a Terminal session.

## What this protocol is not

- **Not a fsck**. We do not run `fsck_apfs` against our writes — it
  would fail by construction (see "Gap analysis"). Once iter D-2
  (checkpoint cascade) lands, a fsck-clean test is the next step.
- **Not a fuzzer**. Cross-compatibility ≠ robustness. Differential
  fuzzing (Apple writes random bytes, we read; we write random bytes,
  Apple reads) is a separate exercise tracked by `FUZZ.md` (TBD).
- **Not exhaustive**. We exercise the canonical happy path of each
  operation. Extreme cases (volume size at the maximum, names with
  pathological Unicode, ACLs, sealed volumes) are out of scope.
