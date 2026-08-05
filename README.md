<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems-apfs.png" alt="go-filesystems/apfs" width="720"></p>

# APFS

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/apfs.svg)](https://pkg.go.dev/github.com/go-filesystems/apfs)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/apfs/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/apfs/actions/workflows/ci.yml)

Pure-Go reader/writer for **real APFS** — the on-disk format Apple's
`apfs.kext` mounts. Containers written by this package are byte-mountable
through `apfs.kext` (`hdiutil attach` → `fsck_apfs -n` clean →
`mount_apfs`); encrypted containers written by `FormatContainerEncrypted`
reach parity with `diskutil apfs encryptVolume`.

The cross-compatibility test matrix and the per-cell rationale live in
[`COMPAT.md`](./COMPAT.md). The current matrix has every cell PASS except a
handful of cells blocked on Apple-private code paths (snapshot creation
gated on a private entitlement, fsck-clean-stage-5 on encrypted containers
which `fsck_apfs` cannot structurally verify even on Apple's own output —
see F-2).

## Container API (`OpenContainer*` / `FormatContainer*`)

| Entry point | Purpose |
| --- | --- |
| `OpenContainer(path)` | Read-only open; resolves NX SB → container OMAP. |
| `OpenContainerRW(path)` | Same plus mutating APIs (commit, write, create, …). |
| `OpenContainerFromBackend(r)` | Open from any `containerReader`; if `r` also satisfies `containerWriter`, write APIs are enabled. |
| `OpenContainerAuto(path)` | GPT-aware open: detects `EFI PART` magic at LBA 1 and offsets into the Apple_APFS partition. Falls through to `OpenContainer` for raw images. |
| `OpenContainerRWAuto(path)` | Read-write GPT-aware open. |
| `FormatContainer(path, sizeBytes, label)` | Write a fresh, kext-mountable APFS container. |
| `FormatContainerEncrypted(path, sizeBytes, label, passphrase)` | Write a FileVault-style software-encrypted APFS container (raw image). |
| `FormatContainerEncryptedGPT(path, totalSize, label, passphrase)` | Same wrapped in a GPT with the Apple_APFS partition GUID. |
| `FormatAppleDmg(path, sizeBytes, cfg)` | Write an Apple-compatible DMG (no UDIF wrapper). |

`Container` carries `Volumes()`, `OpenVolume(index)`, `OpenSnapshot(snap)`,
`AddVolume(label)`, `Commit()`, `Close()`, `SetVerifyHashes(on)`, and the
single-chunk container resize trio `Grow(newSizeBytes)`,
`Shrink(newSizeBytes)`, `Resize(newSizeBytes)` (the last dispatches to
Grow or Shrink based on the current size; see "Container resize" below).

`Volume` exposes the read paths (`Name`, `ListInodes`, `ListSnapshots`,
`LookupSnapshotByName`, `ListXAttrs`, `ReadXAttrStream`,
`XAttrStreamReaderAt`, `ListSiblings`, `LookupInodeRecord`,
`LookupInodeRawValue`, `FindInode`, `ReadFile`, `FileReaderAt`,
`ReadFileTransparent`) and the mutating paths (`WriteFile`,
`WriteFileInPlace`, `OverwriteFile`, `TruncateFile`, `CreateFile`,
`CreateFileCompressed`, `CreateFileCompressedCodec`,
`CreateDirectory`, `CreateSymlink`, `CreateHardlink`, `CreateSparseFile`,
`CreateFifo`, `CreateSocket`, `CreateBlockDevice`, `CreateCharDevice`,
`DeleteFile`, `DeleteDirectory`, `Rename`, `SetXAttr`, `SetXAttrStream`,
`CreateSnapshot`, `DeleteSnapshot`, `SetSuppressSnapshotGuard`).

### `filesystem.Filesystem` entry points

These wrap a `*Container` + first `*Volume` in a path-based `driver`
satisfying `pkg/go-filesystems/interface.Filesystem`. They are what
`pkg/go-diskimages/diskimage` and other callers consume.

| Entry point | Purpose |
| --- | --- |
| `Open(imagePath, partIndex)` | Open a real APFS container. On macOS, falls back to `hdiutil attach` if the path isn't a parseable container. |
| `OpenWithKeys(imagePath, partIndex, keys…)` | Same, trying each key as a FileVault passphrase before falling back. |
| `Format(path, sizeBytes, cfg)` | Create a new real APFS container. `cfg.Encryption = &FDEConfig{Passphrase: …}` produces a FileVault-encrypted container. |
| `OpenFDE(imagePath, passphrase, partIndex)` | Open a FileVault-encrypted real APFS container directly. |
| `OpenFromBlockDevice(dev, partIndex)` | Open a `BlockRW` backend (already decrypted, e.g. behind QCOW2). |

The driver additionally satisfies `filesystem.LabelReader` (`Label()`,
read-only — see below), `filesystem.Symlinker`, `filesystem.HardLinker`,
`filesystem.Truncater`, `filesystem.Grower` (`GrowTo(newSizeBytes)`), and
`filesystem.Resizer` (`Resize(newSize)`, the uniform grow-or-shrink entry
point from `pkg/go-filesystems/interface`).

The implementation type (`driver`) is unexported; callers get
`filesystem.Filesystem`. The compile-time assertion
`var _ filesystem.Filesystem = (*driver)(nil)` in `driver.go` guards
against drift.

## Real APFS — supported features

### Read paths

- NX superblock decode (block size, fs_oid array, container OMAP oid,
  `nx_keylocker`, `nx_flags`).
- Object map B-tree lookup (single-level and multi-level descend along
  the matching key path).
- Per-volume APSB decode (volume name, root tree oid, volume OMAP).
- **Full FS-tree traversal** at any B-tree height, with hashed-internal-
  node support (sealed volumes — values larger than 8 bytes are accepted;
  only the leading uint64 child OID is read for descent).
- FS-tree leaf decoding for `J_INODE_VAL`, `J_DIR_REC`, `J_FILE_EXTENT`,
  `J_XATTR`, `J_SIBLING_LINK`, `J_SNAP_META`, `J_SNAP_NAME`,
  `J_DSTREAM_ID`.
- **File reading across multiple contiguous extents** (extents sorted by
  logical offset; sparse holes zero-filled; trailing zero region honoured).
- `FindInode(oid)` — `O(log n + k)` lookup returning a fully populated
  `Inode` (Name + dataExtents). Implemented via two `seekAndIterate`
  passes (one over the inode's own records, one over the parent's drec
  range).
- `LookupInodeRecord(oid)` — `O(log n)` lookup returning just the
  `J_INODE_VAL` (Mode, Size, IsDir, ParentID).
- `seekAndIterate(target, visit)` — B-tree forward iterator: binary-
  search descent positions the cursor at the first key ≥ `target`, then
  the visit callback walks every subsequent record in ascending order
  with early termination via `(stop bool, err error)`.
- `ListSnapshots()` enumerates every `J_SNAP_META` record in the
  volume's snapshot metadata tree.
- `LookupSnapshotByName(name)` — fast path `O(log n)` binary search on
  `J_SNAP_NAME` records, then a second `O(log n)` seek on `J_SNAP_META`.
  Falls back to a linear scan when an image has `J_SNAP_META` records
  without matching `J_SNAP_NAME` side records.
- `OpenSnapshot(snap)` returns a read-only `*Volume` exposing the volume
  as it was at `snap.XID`. Internally every virtual-oid resolution
  through the volume OMAP is clamped to the snapshot's XID.
- `ListXAttrs(inode)` returns every embedded xattr; stream xattrs
  surface their stream id and size. `ReadXAttrStream(xattr)` fetches
  the payload of stream xattrs (concatenates `J_FILE_EXTENT` records
  keyed by `xattr_obj_id`).
- `ListSiblings(inode)` returns every hard-link record (alternate
  parent + name) for the inode.
- **Optional hash verification for sealed volumes** via
  `Container.SetVerifyHashes(true)`. When enabled, every B-tree descent
  through a hashed internal node validates the child block's SHA-256
  against the 32-byte digest stored after the child OID in
  `btn_index_node_val`. Disabled by default for performance.
- **Streaming reads** via `FileReaderAt(inode)` and
  `XAttrStreamReaderAt(xattr)`: both return an `io.ReaderAt` over the
  decoded bytes without buffering the whole payload. Bounded by the
  inode size / xattr stream size (reads past EOF return `io.EOF`);
  sparse holes return zeros without consuming I/O. Use these instead
  of `ReadFile` / `ReadXAttrStream` for large files (boot images,
  archives, kernel binaries) where the all-at-once allocation would
  waste memory.
- **Transparent file decompression** via `ReadFileTransparent(inode)`
  covers the **full** decmpfs matrix:
  - Type 1  — uncompressed inline
  - Type 3  — zlib inline (with `0xFF` raw passthrough)
  - Type 4  — zlib resource fork (HFS+ rsrc header + chunked block table)
  - Type 5  — raw resource fork (chunked, verbatim)
  - Type 7  — LZVN inline (raw payload wrapped in synthetic `bvxn`)
  - Type 8  — LZVN resource fork (offset-table layout)
  - Type 11 — LZFSE inline (block stream)
  - Type 12 — LZFSE resource fork (offset-table layout)

  Resource-fork variants automatically fetch the file's
  `com.apple.ResourceFork` xattr (embedded or stream). LZVN/LZFSE
  decoding is delegated to `pkg/go-compressions/lzfse`.

  The resource-fork offset-table decoder (types 8/12) accepts **both**
  the real Apple layout that `ditto --hfsCompression` / the diskimages
  framework emit (no 256-byte HFS header; `(N+1)` little-endian uint32
  offsets from byte 0, `offset[0] == 4*(N+1)`) **and** the legacy
  0x100-header layout. The Apple layout is validated against a real
  `ditto` image captured in `testdata/golden_big_rsrc.bin`.

### Write paths

- `FormatContainer(path, sizeBytes, label)` writes a kext-mountable
  unencrypted APFS container (cell N-2 in COMPAT.md): full Apple-shape
  NX SB / spaceman / OMAP / APSB / FS-tree pre-population, including
  the four `make_cat_root` records the kext requires. Verified
  end-to-end via `hdiutil attach` + `fsck_apfs -n` + `mount_apfs` +
  read+write round-trip in `TestCompatNative_KextMountsOurFormat`.
- `FormatContainerEncrypted(path, sizeBytes, label, passphrase)` and
  `FormatContainerEncryptedGPT(path, totalSize, label, passphrase)`
  write FileVault-style software-encrypted containers (cell F-2 in
  COMPAT.md). Output is structurally byte-identical to what
  `diskutil apfs encryptVolume` emits:

  - container + volume keybags encrypted at rest with AES-XTS-128
    keyed on `containerUUID || containerUUID` (resp.
    `volumeUUID || volumeUUID`), 512-byte XTS sectors, tweak =
    `paddr × 8 + sector_index`;
  - ASN.1 DER VEKBLOB / KEKBLOB with HMAC-SHA256 keyed by SHA-256 of
    `\x01\x16\x20\x17\x15\x05 || salt`, computed over the [3]
    inner-keyblob envelope;
  - PBKDF2-SHA256 (100,000 iterations) protecting the KEK, AES-KW
    (RFC 3394) wrapping the VEK with the KEK;
  - five-ephemeral checkpoint (SPACEMAN, REAPER, SFQ_IP, SFQ_MAIN,
    and the optional INTEGRITY_META) matching what Apple writes;
  - APSB with `APFS_FS_ONEKEY` set, `APFS_FS_UNENCRYPTED` cleared, and
    `APFS_INCOMPAT_ENC_ROLLED` set;
  - GPT-wrapped variant emits an Apple_APFS partition entry
    (`7C3457EF-…`) so apfs.kext binds the synthesised container's
    physical store correctly.

  The recipe was reverse-engineered byte-by-byte against two
  independently-encrypted Apple reference DMGs across eight rounds of
  `fsck_apfs` / byte-diff bisection. `fsck_apfs` stops at the same
  stage and with the same status code (`result=92 pl=5:1 pl=9:1 fp=30
  fl=10`) for both Apple's reference and our output — fsck reads the
  encrypted keybag's RAW bytes without decrypting and validates them
  as plaintext, which always fails for any encrypted APFS container,
  including Apple's own. Parity locked in by
  `TestCompatFDE_FormatContainerEncrypted_FsckParityWithApple`.

  `apfsfde.Open(path, passphrase)` round-trips the keybag chain and
  recovers the VEK end-to-end through the public API
  (`TestFormatContainerEncrypted_ApfsfdeOpenRoundtrip`).
- `WriteFileInPlace(inode, data)` overwrites a file's already-
  allocated extents in place. No metadata cascade, no allocator: the
  file's extents must be contiguous from logical offset 0 and
  `len(data)` must fit within them; the inode's declared size is
  **not** updated.
- `WriteFile(inode, data)` is the metadata-aware variant: in-place
  overwrite plus a patch of the inode's `J_DSTREAM.size` inside its
  FS-tree leaf, so subsequent reads see `len(data)` as the file's
  logical size.
- `OverwriteFile(oid, newData)` is the size-changing variant. Three
  branches: (1) newData fits in the file's total existing capacity →
  in-place overwrite across the existing extents in logical order +
  size patch; (2) newData exceeds capacity → fill the existing
  extents head-to-tail then allocate one fresh contiguous extent at
  logical offset = old_total_capacity for the rest, insert
  `J_FILE_EXTENT`, update extent-ref tree, mark blocks allocated,
  bump `apfs_fs_alloc_count`, patch `J_DSTREAM.{size,alloced_size,
  total_bytes_written}`; (3) newData < current size → size patch
  only (use `TruncateFile` afterwards to free the trailing blocks).
  Multi-extent files are supported on both grow and in-place paths.
- `TruncateFile(oid, newSize)` resizes the file. When `newSize` ≥
  current size: only the inode's `J_DSTREAM.size` is patched (the
  file becomes sparse past the existing extents). When `newSize` <
  current size: extents that fall entirely past `newSize` are freed
  (chunk bitmap, ci_free_count, sm_free_count, extent-ref tree, and
  `apfs_fs_alloc_count` all updated); when `newSize` lands inside an
  extent, that extent is shrunk to its smallest block-aligned size
  that still holds `newSize` and only the trailing blocks within it
  are freed. POSIX-tolerant: `alloced_size ≥ size` invariant
  preserved when `newSize` is mid-block.
- `CreateFile(parentOID, name, data)` allocates a fresh inode oid
  (from `apsb.apfs_next_obj_id`), allocates blocks for the payload,
  writes the file content, and inserts the four records `J_INODE_VAL`,
  `J_FILE_EXTENT`, `J_DIR_REC`, `J_DSTREAM_ID`, with multi-leaf
  FS-tree splits when the root would overflow.
- `CreateDirectory`, `CreateSymlink`, `CreateHardlink`,
  `CreateSparseFile`, `CreateFifo`, `CreateSocket`,
  `CreateBlockDevice`, `CreateCharDevice` — full POSIX special-file
  set with the right inode mode + content (symlink target as inline
  data; device files with `rdev`).
- `DeleteFile(parentOID, name)`, `DeleteDirectory(parentOID, name)`
  — POSIX-style delete: drop records, free extents through
  `markBlocksFreed`, refresh parent `nchildren`, decrement APSB
  counters. Hardlinked files (`nlink > 1`) take a separate path:
  only the named alias's drec + matching J_SIBLING_LINK +
  J_SIBLING_MAP records are removed and the inode's nlink is
  decremented in place; the inode, its extents, xattrs and
  extent-ref records stay alive because the other names still
  reference them.
- `Rename(oldParentOID, oldName, newParentOID, newName)` — drop old
  drec, insert new drec preserving `file_id` + drec val (incl.
  optional `sibling_id` xfield), patch inode `parent_id`, refresh
  both parents' `nchildren`. If the destination already exists AND
  refers to a regular file with `nlink == 1`, that file is deleted
  first (records dropped, extents freed, APSB counters updated) so
  the rename can complete — matching POSIX `rename(2)` semantics
  for the regular-file → regular-file case. Overwriting a directory
  or a hardlinked target is rejected.
- `SetXAttr(oid, name, payload)` — embedded xattr (`XATTR_DATA_EMBEDDED`)
  for short payloads; `SetXAttrStream(oid, name, payload)` — stream
  xattr (separate dstream) for large payloads.
- **Compress-on-write** via `CreateFileCompressed(parentOID, name, data)`
  (and `CreateFileCompressedCodec(..., codec)`): stores a regular file's
  content transparently compressed exactly as `AppleFSCompression` /
  `ditto --hfsCompression` does — the inode carries the `UF_COMPRESSED`
  bsd flag, `INODE_HAS_UNCOMPRESSED_SIZE` + the logical size in
  `j_inode_val.uncompressed_size`, and no main data fork; a
  `com.apple.decmpfs` xattr carries the header (and, inline, the payload).
  Small files use inline compression (zlib type 3 or LZVN type 7); files
  larger than one 64 KiB chunk use a chunked LZVN resource fork (type 8)
  in Apple's byte-0 offset-table layout, stored embedded or as a stream
  `com.apple.ResourceFork` xattr (whose `xattr_obj_id` is drawn from the
  `apfs_next_obj_id` space, matching Apple). Only apfs.kext-interoperable
  formats are emitted (LZVN, not LZFSE bvx2). Chunks that don't shrink
  fall back to Apple's 0xFF raw passthrough. Verified end-to-end:
  `fsck_apfs -n` clean (no warnings) + apfs.kext mount + transparent
  read-back byte-exact + `UF_COMPRESSED` reported by the kernel
  (`TestCompatNative_KextReadsOurCompressedFiles`). LZVN block interop is
  itself guarded in `go-compressions/lzfse` against Apple's
  `libcompression` (`COMPRESSION_LZVN`) in both directions.
- `CreateSnapshot(name)` — pick the container's current xid, CoW the
  live APSB to a fresh paddr (with `o_oid = paddr`, retyped to
  PHYSICAL), insert J_SNAP_META + J_SNAP_NAME records, materialise
  the OMAP snapshot tree (subtype `APFS_OBJECT_TYPE_OMAP_SNAPSHOT`),
  bump `apfs_num_snapshots`.
- `DeleteSnapshot(name)` removes the named snapshot: frees its frozen
  APSB block, drops the `J_SNAP_NAME` + `J_SNAP_META` records from the
  snap-meta tree, decrements `apsb.apfs_num_snapshots`, and — when
  `name` was the most-recent snapshot — rolls the volume OMAP's
  `om_most_recent_snap` back to the new maximum xid (or 0 when none
  remain). Returns `os.ErrNotExist` when no snapshot of that name
  exists.
- **Container resize** — `Container.Grow(newSizeBytes)`,
  `Container.Shrink(newSizeBytes)`, and the dispatching
  `Container.Resize(newSizeBytes)` reshape a live container within the
  single-chunk regime (≤ 32768 blocks, 128 MiB at the default 4 KiB
  block size — Apple's `blocks-per-chunk` constant): both update the NX superblock, the
  spaceman, and the chunk_info_block, and truncate the backing storage
  when the backend supports it. Grow requires the new size to be
  strictly larger; Shrink requires it to be strictly smaller, at or
  above the format-time metadata floor, and rejects (`ErrShrinkUnsupported`)
  when any block at or above the new boundary is still allocated.
  Crossing the single-chunk boundary in either direction returns
  `ErrResizeUnsupported` (allocating a fresh chunk_info_block /
  bitmap is out of scope for this iteration). The `filesystem.Filesystem`
  driver exposes the same capability uniformly via `GrowTo` (
  `filesystem.Grower`) and `Resize` (`filesystem.Resizer`). Verified by
  `TestResize_GrowShrinkRoundTrip`, `TestResize_ErrShrinkUnsupported`,
  `TestResize_RejectsCrossChunk`, `TestStress_ResizeCycle`,
  `TestStress_ResizeConcurrentReaders`, and — on macOS —
  `TestGrowShrinkThenFsckApfs` (fsck-clean after a native resize).
- `Container.AddVolume(label)` extends a freshly-formatted
  single-volume container with additional volumes (up to Apple's
  max of 100). Each new volume gets 6 fresh metadata blocks past the
  format-time metadata (APSB + volume OMAP + leaf + FS-tree + snap-
  meta + extent-ref).
- `Container.Commit()` promotes in-memory mutations to a fresh
  on-disk checkpoint at xid=N+1; refreshes APSB counters from a fresh
  FS-tree scan.
- **Concurrent stress testing**: two heavy-load tests exercise the
  thread-safety contract under sustained pressure:
  - `TestConcurrentStress_MixedOps` — 16 creator + 16 reader + 4
    mutator (create+grow+truncate+rename+delete) goroutines, ~1000
    operations end-to-end. Validates leaf-rewrites don't crash
    concurrent readers and the rename-overwrite cross-call path
    holds the lock correctly through `Rename → deleteFileLocked`.
  - `TestConcurrentStress_ReaderHeavy` — 32 readers + 2 writers
    against a 100-file volume, ~16k+ parallel reads. Verifies the
    RWMutex actually lets readers run in parallel rather than
    serialising on the write lock.

  Both pass clean under `go test -race`.
- **Thread-safe `Container` / `Volume` API**: every public method
  on `Container` and `Volume` is wrapped with `sync.RWMutex`
  (`Container.mu`). Mutating ops (`CreateFile`, `Commit`, `Rename`,
  `DeleteFile`, `OverwriteFile`, `WriteFile`, `CreateSnapshot`, …)
  take a write lock; read ops (`ListInodes`, `FindInode`, `ReadFile`,
  `ListSnapshots`, …) take a read lock so many readers run in
  parallel. Cross-method calls that previously chained two public
  methods (`Rename → DeleteFile`, `WriteFile → WriteFileInPlace`,
  `LookupSnapshotByName → ListSnapshots`) now go through unexported
  `*Locked` helpers to avoid recursive re-locking. The streaming
  readers (`FileReaderAt`, `XAttrStreamReaderAt`) take a snapshot of
  the inode's extent list under the lock at construction time;
  subsequent `ReadAt` calls do NOT re-lock — concurrent mutation
  after construction may serve stale (but valid) bytes. Verified
  by `TestConcurrent_CreateAndRead` (4 writer + 4 reader goroutines,
  100 files end-to-end) and `TestConcurrent_RenameAndDelete`, both
  clean under `go test -race`.
- **`TruncateFile` shrink on multi-level FS-trees**: the shrink path
  used to reject any volume whose FS-tree had been promoted to
  level≥1 (~30+ files). It now dispatches per dropped/shrunk
  J_FILE_EXTENT key through `descendToLeafForKey` +
  `removeKeyFromLeaf` / `modifyLeafAtPaddrAndInsert`, then refreshes
  the root index. Verified by `TestTruncateFile_MultiLevelTree`
  (50 files force level-1 FS-tree, target file shrunk to 100 bytes,
  unrelated files unaffected).
- **Commit ring-buffer wrap**: `Container.Commit()` now wraps the
  checkpoint descriptor + data ring buffers when the next checkpoint
  wouldn't fit linearly past `xp_desc_next` / `xp_data_next`. Apple's
  apfs.kext / fsck pick the latest checkpoint by xid rather than
  position, so wrapping is transparent: the oldest checkpoint's
  slots are silently overwritten. Previously the writer errored out
  with "descriptor area exhausted" after ~3 commits; an arbitrary
  number of commits is now supported. Verified by
  `TestCommit_RingBufferWrap` (20 round-trip commits, last file
  readable after re-open).
- **Volume OMAP, snap-meta and extent-ref multi-level**: each of the
  three PHYSICAL trees (`apsb.apfs_omap_oid`,
  `apsb.apfs_snap_meta_tree_oid`, `apsb.apfs_extentref_tree_oid`)
  starts as a single leaf, promotes to level-1 (split into two
  non-root leaves under an internal root) when the leaf would
  overflow, and promotes to level-2 in place at the APSB-pointed root
  paddr when the level-1 index would overflow. Promotion splits the
  level-1 children into two halves written as level-1 non-root
  internals at fresh paddrs, then rewrites the original root as a
  level-2 internal with two children. Subsequent inserts use a
  recursive descent (level-2 → level-1 → level-0) with leaf-split →
  L1-internal-split → L2-root index-add propagation. Reads route
  through `traverseBTreeWithOmap` which detects `btreeFlagPhysical`
  and descends child paddrs directly at any level. The extent-ref
  modify path also collapses an empty leaf back out of the index
  (free + drop) when its level-1 parent still has another sibling.
  Tree-wide totals on the root trailer (`bt_key_count` / `bt_node_count`)
  are recomputed on every rewrite by scanning the live leaves, so
  fsck-strict cross-checks stay clean. Level-3 is the next
  unimplemented jump (capacity at level-2: ≈ 122² × 108 ≈ 1.6M entries
  — far past typical disk-image scale). Verified by:
  - `TestRootPromotion_FilesLevel2` (FS-tree + volume OMAP, 1500
    single-extent files).
  - `TestSnapMetaMultiLevel_PromotesAtThreshold` (level-1, 200 records).
  - `TestExtentRefMultiLevel_PromotesAtThreshold` +
    `TestExtentRefMultiLevel_DeleteAfterPromote` (level-1, 130 files).
  - `TestOMAP_PromotesToLevel2` (3000 files force OMAP level-2 via
    `omapInternalRootCap=4`).
  - `TestSnapMeta_PromotesToLevel2` (800 J_SNAP_META records via
    `snapMetaInternalCapEntries=4`).
  - `TestExtentRef_PromotesToLevel2` (700 files via
    `extentRefInternalCapEntries=4`).
  Test-only cap vars (`omapInternalRootCap`, `snapMetaInternalCapEntries`,
  `extentRefInternalCapEntries`) lower the natural per-block byte cap so
  the level-2 path fires under workloads tolerable in CI.

## Limitations

- Mount-backed `Open` mode is only used on macOS (proxies to
  `hdiutil attach`) and only when the file isn't a parseable real
  APFS container — i.e. for Apple-produced DMGs that the pure-Go
  reader can't (yet) consume directly.
- `LookupSnapshotByName` falls back to a linear scan when an image
  carries `J_SNAP_META` records without matching `J_SNAP_NAME` side
  records (Apple's `tmutil snapshot` always emits both, so the fast
  path covers the common case).
- T2 / Secure Enclave mediated keys are not supported (hardware
  access required).
- `fsck_apfs` cannot structurally verify any encrypted APFS keybag
  — by design (fsck reads the encrypted bytes without decrypting and
  validates them as plaintext). Our `FormatContainerEncrypted` output
  is at parity with Apple's reference DMG under fsck. See F-2 in
  `COMPAT.md`.

## Testing

`extra_coverage_test.go` carries smoke tests for the public entry
points that aren't exercised through the larger end-to-end suites
(`OpenWithKeys` unencrypted-hit and bogus-input miss).
`decmpfsDecodeRsrcChunk` is covered across every branch (raw type
with truncation, zlib empty / 0xFF passthrough / decode error /
unsupported codec). `OpenWithKeys` is exercised on its per-key
fall-through loop.

The mountpoint-dispatch branch at the top of every path-based
driver method (the d.mountpoint != "" check that routes to the
darwin hdiutil-attached mountpoint) is covered by constructing a
driver{mountpoint: tempdir} synthetically.

Container/volume open entry points are exercised on their
early-error branches: OpenContainer / OpenContainerRW on missing
file + garbage content, OpenVolume with out-of-range index,
OpenSnapshot with zero APSBOID and nonexistent (xid, oid).
ReadFileTransparent is covered on a directory and on a plain
file (no decmpfs xattr). Rename and DeleteDirectory carry tests
for the apfsRootDirParent (parent_id=1) → apfsRootDirInoNum
rebind branch.

Multi-level FS-tree paths are covered by bulk-creating ~150 files (no
cap-injection var exists for the FS-tree the way it does for
extent-ref / snap-meta) so subsequent writers descend through the
non-leaf code path. Variants drive: every writer on the root dir,
every writer on a non-root parent (refreshNonRootParentNchildren
isRootDir=false branch), and DeleteFile on a hardlink alias under a
multi-level tree (deleteHardlinkAlias multi-level descend).

Each public Volume writer (CreateFile / CreateDirectory / CreateSymlink
/ CreateSparseFile / SetXAttr / SetXAttrStream / TruncateFile /
Create{Fifo,Socket,BlockDevice,CharDevice}) is also covered against
its shared early-error preconditions: read-only container,
snapshot-view (xidLimit != ∞), snapshot-guard not suppressed, empty
name / empty target / empty payload. DeleteFile, DeleteDirectory,
and Rename carry additional error-path tests (missing source, wrong
type, non-empty directory, identical src+dst, multi-link source,
directory destination, overwrite-regular-file success).

`driver_filesystem_test.go` exercises the path-based
`filesystem.Filesystem` driver: `Format` (plain + encrypted +
default-label + preexisting file), `Open` (success + non-APFS),
the full `MkDir / WriteFile / ReadFile / Stat / ListDir / Rename /
DeleteFile / DeleteDir / ReadLink` lifecycle, the read-only-fallback
in `openContainerAsFilesystem`, plus targeted unit tests for
`drecTypeToDT`, `mountModeDeleteDir` wipe-root,
`decmpfs{Zlib,LZFSE,LZVN}Inline` edge cases, `bytesReaderAt.ReadAt`,
`OpenFromBlockDevice` success, the `fdeContainerBackend` WriteAt/Close
passthrough, partial-extent shrink via `TruncateFile`, snapshot delete
that rewinds `om_most_recent_snap`, and the multi-level B-tree
manipulation paths (`snapMetaRemoveOneRecordMultiLevel`,
`extentRefModifyLeafLevel2`, `rewriteExtentRefRootAtLevel`,
`rewriteSnapMetaRootAtLevel`) driven via cap-injected fixtures.
