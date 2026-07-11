package filesystem_apfs

// commit.go is iteration "D-7" of the read/write roadmap. It promotes
// in-progress mutations made by CreateFile / WriteFile (which write
// directly to existing physical blocks) into a new on-disk checkpoint
// that fsck_apfs and Apple's apfs.kext will accept as the "current"
// state of the container.
//
// FormatContainer (D-6) emits a dual-checkpoint init:
//
//	desc[0..1] xid=1 — bootstrap (SPACEMAN+REAPER only)
//	desc[2..3] xid=2 — current (SPACEMAN+REAPER+FQ_IP+FQ_MAIN)
//	data[0..5] holds the corresponding ephemerals
//
// Commit() advances by one checkpoint. With xpDescNext=4 / xpDataNext=6
// after FormatContainer, the next commit lands at:
//
//	desc[4..5] xid=3 — Commit's CheckpointMap + NX SB copy
//	data[6..9]      — fresh SPACEMAN, REAPER, FQ_IP, FQ_MAIN at xid=3
//
// Block 0's NX SB is rewritten to point at the new checkpoint.
//
// Subsequent Commits keep advancing through the desc/data ring buffers
// (8 desc slots, 52 data slots are reserved by FormatContainer). When
// the next checkpoint wouldn't fit linearly past `xp_desc_next`, the
// ring buffer wraps to slot 0 and starts overwriting the oldest
// checkpoint. fsck / apfs.kext find the latest checkpoint via the
// xid stamped in the obj header (highest xid wins), so wrapping is
// transparent.
//
// What Commit DOES NOT do in this iteration:
//   - Mutate the OMAP. Callers that change FS-tree contents must update
//     the OMAP entry's xid themselves before Commit; this version only
//     promotes pre-positioned blocks.
//   - Crash safety. If the host process dies mid-Commit, the container
//     may end up referencing partially-written ephemerals.

import (
	"encoding/binary"
	"fmt"
)

// Commit promotes the in-memory state to a new on-disk checkpoint.
// Callers that have run CreateFile / WriteFile / etc. must Commit
// before macOS will mount the result; without a Commit the mutations
// live only at the FS-tree level and the (older) checkpoint that fsck
// uses to validate the container does not see them.
//
// The Commit cascade:
//
//  1. Compute the next checkpoint's xid (= current xid + 1).
//  2. Compute the next slots in the desc + data ring buffers.
//  3. Write a fresh SPACEMAN, REAPER, FQ_IP and FQ_MAIN at the new
//     data slots, all carrying the new xid.
//  4. Write a CheckpointMap at the next desc slot mapping each
//     ephemeral OID to its new paddr.
//  5. Write a new block-0 NX SB pointing at the new checkpoint, then
//     replicate it at the desc slot AFTER the CheckpointMap.
//
// All writes are sealed (Fletcher64) before WriteAt; the underlying
// backend's WriteAt is called sequentially in cascade order so a crash
// before block 0 is updated leaves the previous checkpoint intact.
func (c *Container) Commit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return ErrReadOnly
	}
	if c.sb == nil {
		return fmt.Errorf("apfs: Commit: container superblock not loaded")
	}
	bs := uint64(c.sb.blockSize)
	if bs == 0 {
		return fmt.Errorf("apfs: Commit: zero block size")
	}

	// Step 1: pick the next xid. fsck_apfs requires nx_next_xid to
	// strictly exceed every used xid; we therefore use the on-disk
	// nextXID and bump it by one for the post-Commit nx_next_xid.
	newXID := c.sb.nextXID
	if newXID <= c.sb.xid {
		// Defensive: nextXID should already exceed the current xid.
		newXID = c.sb.xid + 1
	}

	// Step 2: read the current CheckpointMap and bring forward every
	// ephemeral it lists. Apple's `newfs_apfs` writes a 2-entry CPM at
	// format time (SPACEMAN + REAPER), but after the kext mounts and
	// modifies the container, the CPM may grow to include FQ_IP / FQ_MAIN
	// (and on fusion devices: TIER2_FQ + FUSION_WBC). To preserve all of
	// these we copy each entry's source block forward at a fresh data
	// slot, just bumping its obj header xid. This way the kext's lazy-
	// created FQ trees survive our Commit unchanged.
	curCPMBlock, err := c.readBlock(c.sb.xpDescBase + uint64(c.sb.xpDescIndex))
	if err != nil {
		return fmt.Errorf("apfs: Commit: read current CheckpointMap: %w", err)
	}
	curEntries, err := parseCPMEntries(curCPMBlock)
	if err != nil {
		return fmt.Errorf("apfs: Commit: parse current CheckpointMap: %w", err)
	}
	if len(curEntries) == 0 {
		return fmt.Errorf("apfs: Commit: current CheckpointMap is empty")
	}
	const commitDescLen = uint32(2) // CPM + NX SB copy
	commitDataLen := uint32(len(curEntries))
	if commitDescLen > c.sb.xpDescBlocks {
		return fmt.Errorf("apfs: Commit: descriptor area too small (capacity=%d, need %d)",
			c.sb.xpDescBlocks, commitDescLen)
	}
	if commitDataLen > c.sb.xpDataBlocks {
		return fmt.Errorf("apfs: Commit: data area too small (capacity=%d, need %d)",
			c.sb.xpDataBlocks, commitDataLen)
	}
	// Ring-buffer wrap: the descriptor and data areas behave as ring
	// buffers. When the next checkpoint wouldn't fit linearly at
	// `xp_*_next`, wrap to slot 0 and start writing there. Per Apple's
	// File System Reference, individual checkpoints don't span the
	// wrap boundary (they're written linearly), so we wrap by jumping
	// `xp_*_next` to 0 if the new range would extend past the capacity.
	// Old slots are implicitly reclaimed: fsck / apfs.kext picks the
	// checkpoint with the highest xid, regardless of where it sits in
	// the ring.
	descIndex := c.sb.xpDescNext
	if descIndex+commitDescLen > c.sb.xpDescBlocks {
		descIndex = 0
	}
	dataIndex := c.sb.xpDataNext
	if dataIndex+commitDataLen > c.sb.xpDataBlocks {
		dataIndex = 0
	}
	descCheckpointMap := c.sb.xpDescBase + uint64(descIndex)
	descNXSBCopy := c.sb.xpDescBase + uint64(descIndex) + 1
	dataBase := c.sb.xpDataBase + uint64(dataIndex)

	// Step 3: copy each ephemeral block forward, bumping its xid, and
	// build the new CPM entry list with the new paddrs.
	newEntries := make([]cpmEntry, len(curEntries))
	for i, e := range curEntries {
		newPaddr := dataBase + uint64(i)
		src, err := c.readBlock(e.paddr)
		if err != nil {
			return fmt.Errorf("apfs: Commit: read ephemeral oid 0x%x at paddr %d: %w", e.oid, e.paddr, err)
		}
		binary.LittleEndian.PutUint64(src[16:24], newXID) // o_xid
		sealBlock(src)
		if _, err := c.w.WriteAt(src, int64(newPaddr*bs)); err != nil {
			return fmt.Errorf("apfs: Commit: write ephemeral oid 0x%x at paddr %d: %w", e.oid, newPaddr, err)
		}
		newEntries[i] = cpmEntry{
			objType:    e.objType,
			objSubtype: e.objSubtype,
			oid:        e.oid,
			paddr:      newPaddr,
		}
	}

	// Step 4: emit the new CheckpointMap at desc[descIndex].
	cpmBlock := make([]byte, bs)
	encodeCheckpointMapEntries(cpmBlock, descCheckpointMap, newXID, newEntries)
	sealBlock(cpmBlock)
	if _, err := c.w.WriteAt(cpmBlock, int64(descCheckpointMap*bs)); err != nil {
		return fmt.Errorf("apfs: Commit: write CheckpointMap at paddr %d: %w", descCheckpointMap, err)
	}

	// Step 5: build the new block-0 NX SB pointing at the new checkpoint
	// by READING the existing block-0 SB and mutating only the fields
	// that change in this commit. This preserves any non-decoded fields
	// Apple's `newfs_apfs` writes (nx_counters, nx_newest_mounted_version,
	// nx_features, fusion-related slots, etc.), so Commit works on
	// containers we did NOT format ourselves.
	sbBlock, err := c.readBlock(0)
	if err != nil {
		return fmt.Errorf("apfs: Commit: read NX SB at block 0: %w", err)
	}
	// Compute post-commit *_next with ring-buffer wrap so the on-disk
	// fields match the in-memory ones (xpDescNext / xpDataNext below).
	postDescNext := descIndex + commitDescLen
	if postDescNext >= c.sb.xpDescBlocks {
		postDescNext = 0
	}
	postDataNext := dataIndex + commitDataLen
	if postDataNext >= c.sb.xpDataBlocks {
		postDataNext = 0
	}
	updateNXSuperblockForCheckpoint(sbBlock, newXID,
		descIndex, commitDescLen, postDescNext,
		dataIndex, commitDataLen, postDataNext,
		newXID+1)
	// Persist the in-memory nx_next_oid cursor (bumped by leaf-split
	// allocations) at offset 88. fsck cross-checks every virtual oid
	// referenced by the OMAP against this hint, so it must reflect the
	// largest oid we've handed out.
	if c.allocOIDCursor > c.sb.nextOID {
		c.sb.nextOID = c.allocOIDCursor
	}
	if c.sb.nextOID != 0 {
		binary.LittleEndian.PutUint64(sbBlock[88:96], c.sb.nextOID)
	}
	sealBlock(sbBlock)
	// Write the desc-area copy first, then block 0. This mirrors
	// FormatContainer's "all metadata then sb" ordering and gives a
	// crash-safe (newer xid only becomes "current" once block 0 is
	// updated) commit fence.
	if _, err := c.w.WriteAt(sbBlock, int64(descNXSBCopy*bs)); err != nil {
		return fmt.Errorf("apfs: Commit: write NX SB copy at paddr %d: %w", descNXSBCopy, err)
	}
	if _, err := c.w.WriteAt(sbBlock, 0); err != nil {
		return fmt.Errorf("apfs: Commit: write NX SB at block 0: %w", err)
	}

	// Refresh the in-memory NX SB so subsequent operations see the new
	// checkpoint pointers.
	c.sb.xid = newXID
	c.sb.nextXID = newXID + 1
	c.sb.xpDescIndex = descIndex
	c.sb.xpDescLen = commitDescLen
	c.sb.xpDescNext = descIndex + commitDescLen
	if c.sb.xpDescNext >= c.sb.xpDescBlocks {
		c.sb.xpDescNext = 0 // wrap
	}
	c.sb.xpDataIndex = dataIndex
	c.sb.xpDataLen = commitDataLen
	c.sb.xpDataNext = dataIndex + commitDataLen
	if c.sb.xpDataNext >= c.sb.xpDataBlocks {
		c.sb.xpDataNext = 0 // wrap
	}
	// Step 6: refresh APSB.apfs_next_obj_id from the highest oid found
	// in any FS-tree leaf inode entry. fsck_apfs's "apfs_next_obj_id is
	// not valid (expected N, actual M)" error fires when a CreateFile
	// allocated an oid > apfs_next_obj_id but the APSB wasn't updated.
	if err := c.refreshAPSBNextObjID(bs); err != nil {
		return fmt.Errorf("apfs: Commit: refresh APSB: %w", err)
	}
	return nil
}

// refreshAPSBNextObjID walks every volume's FS-tree to compute the
// largest in-use inode oid and rewrites APSB.apfs_next_obj_id to
// (max + 1). Called from Commit after CreateFile so apfs.kext + fsck
// see a consistent next-oid hint.
//
// The APSB is rewritten in place: we read the existing block, mutate
// the 8-byte field at offset 0xB0, recompute Fletcher64, and WriteAt
// back. The volume OMAP entry's xid stays at xid=1 — this matches
// "the APSB was last touched at xid=1 and minor in-place edits don't
// bump that xid" which fsck accepts because every per-block xid we
// store is ≤ the checkpoint xid.
func (c *Container) refreshAPSBNextObjID(bs uint64) error {
	for _, apsbOID := range c.sb.fsOIDs {
		apsbPaddr, err := c.omapLookup(c.containerOmap, apsbOID, ^uint64(0))
		if err != nil {
			return err
		}
		apsbBlock, err := c.readBlock(apsbPaddr)
		if err != nil {
			return err
		}
		apsb, err := readAPSB(apsbBlock)
		if err != nil {
			return err
		}
		// Open this volume long enough to scan the FS-tree.
		v := &Volume{
			c:        c,
			apsb:     apsb,
			xidLimit: ^uint64(0),
		}
		if apsb.omapOID != 0 {
			volOmapBlock, err := c.readBlock(apsb.omapOID)
			if err != nil {
				return err
			}
			vo, err := readOmapPhys(volOmapBlock)
			if err != nil {
				return err
			}
			v.volOmap = vo
		}
		if v.volOmap != nil && apsb.rootTreeOID != 0 {
			rootBlock, err := c.omapLookup(v.volOmap, apsb.rootTreeOID, ^uint64(0))
			if err != nil {
				return err
			}
			raw, err := c.readBlock(rootBlock)
			if err != nil {
				return err
			}
			node, err := readBTreeNode(raw)
			if err != nil {
				return err
			}
			info, err := readRootBTreeInfo(raw)
			if err != nil {
				return err
			}
			v.rootNode = node
			v.rootInfo = info
		}
		highest := uint64(0x10) // APFS_MIN_USER_INO_NUM
		var numFiles, numDirs, numSymlinks, numOther uint64
		if v.rootNode != nil {
			_ = v.traverseFSTree(func(k, val []byte) error {
				oid, typ, jerr := jKeyHeader(k)
				if jerr != nil {
					return nil
				}
				// Sibling-id allocations share the apfs_next_obj_id
				// pool with inode oids — fsck rejects an apfs_next_obj_id
				// that's lower than every sibling_id we ever handed out.
				// J_SIBLING_LINK keys carry sibling_id at bytes 8..16;
				// J_SIBLING_MAP keys carry sibling_id in the j_key_t oid.
				switch typ {
				case jTypeSibLink:
					if len(k) >= 16 {
						sibID := binary.LittleEndian.Uint64(k[8:16])
						if sibID > highest {
							highest = sibID
						}
					}
				case jTypeSibMap:
					if oid > highest {
						highest = oid
					}
				case jTypeFileExt:
					// An xattr stream (e.g. a com.apple.ResourceFork holding
					// a compressed file's chunked payload) is keyed by a fresh
					// object id drawn from the apfs_next_obj_id pool, just like
					// an inode. Its only FS-tree footprint is a J_FILE_EXTENT
					// under that id, so account for it here or fsck rejects an
					// apfs_next_obj_id lower than an id we handed out.
					if oid > highest {
						highest = oid
					}
				}
				if typ != jTypeInode {
					return nil
				}
				if oid > highest {
					highest = oid
				}
				// Classify by mode bits at val[80:82]. fsck_apfs's
				// apfs_num_* counters track the live FS contents.
				if len(val) >= 82 {
					mode := binary.LittleEndian.Uint16(val[80:82])
					switch mode & 0xF000 {
					case 0x8000: // S_IFREG
						numFiles++
					case 0x4000: // S_IFDIR
						// Apple's fsck excludes the synthetic top-level
						// directories from apfs_num_directories — only
						// user-created directories count.
						if oid != apfsRootDirParent && oid != apfsRootDirInoNum && oid != apfsPrivDirInoNum {
							numDirs++
						}
					case 0xA000: // S_IFLNK
						numSymlinks++
					default:
						numOther++
					}
				}
				return nil
			})
		}
		next := highest + 1
		writeBuf := make([]byte, len(apsbBlock))
		copy(writeBuf, apsbBlock)
		binary.LittleEndian.PutUint64(writeBuf[0xB0:0xB8], next)
		binary.LittleEndian.PutUint64(writeBuf[0xB8:0xC0], numFiles)
		binary.LittleEndian.PutUint64(writeBuf[0xC0:0xC8], numDirs)
		binary.LittleEndian.PutUint64(writeBuf[0xC8:0xD0], numSymlinks)
		binary.LittleEndian.PutUint64(writeBuf[0xD0:0xD8], numOther)
		sealBlock(writeBuf)
		if _, err := c.w.WriteAt(writeBuf, int64(apsbPaddr*bs)); err != nil {
			return err
		}
	}
	return nil
}

// cpmEntry mirrors `apfs_checkpoint_mapping`: the obj-type word
// (storage class | object type), the obj-subtype, the ephemeral oid,
// and its on-disk paddr in the data area.
type cpmEntry struct {
	objType    uint32
	objSubtype uint32
	oid        uint64
	paddr      uint64
}

// parseCPMEntries decodes a CheckpointMapPhys block into its entries.
// checkpoint_map_phys layout (apfs.h):
//
//	+0    obj_phys_t (32 bytes)
//	+32   uint32 cpm_flags
//	+36   uint32 cpm_count
//	+40   checkpoint_mapping_t cpm_map[cpm_count]   (40 bytes each)
//
// Each checkpoint_mapping_t:
//
//	+0   uint32 cpm_type        (storage class | object type)
//	+4   uint32 cpm_subtype
//	+8   uint32 cpm_size
//	+12  uint32 cpm_pad
//	+16  oid_t  cpm_fs_oid
//	+24  oid_t  cpm_oid
//	+32  oid_t  cpm_paddr
func parseCPMEntries(cpm []byte) ([]cpmEntry, error) {
	if len(cpm) < objPhysSize+8 {
		return nil, fmt.Errorf("CheckpointMap block too short (%d bytes)", len(cpm))
	}
	off := objPhysSize
	count := binary.LittleEndian.Uint32(cpm[off+4 : off+8])
	base := off + 8
	const entrySize = 40
	if base+int(count)*entrySize > len(cpm) {
		return nil, fmt.Errorf("CheckpointMap count %d exceeds block size", count)
	}
	out := make([]cpmEntry, count)
	for i := uint32(0); i < count; i++ {
		entry := base + int(i)*entrySize
		out[i] = cpmEntry{
			objType:    binary.LittleEndian.Uint32(cpm[entry : entry+4]),
			objSubtype: binary.LittleEndian.Uint32(cpm[entry+4 : entry+8]),
			oid:        binary.LittleEndian.Uint64(cpm[entry+24 : entry+32]),
			paddr:      binary.LittleEndian.Uint64(cpm[entry+32 : entry+40]),
		}
	}
	return out, nil
}

// encodeCheckpointMapEntries writes a CheckpointMapPhys carrying the
// supplied entries in order, using each entry's recorded objType /
// objSubtype / oid / paddr verbatim. Used by Commit to emit the new
// per-checkpoint CPM after bringing every ephemeral forward.
func encodeCheckpointMapEntries(block []byte, ownPaddr, xid uint64, entries []cpmEntry) {
	const cpmFlagLast uint32 = 0x00000001
	encodeObjHeader(block, ownPaddr, xid, objTypeCheckpointMap, 0, objStoragePhysical)
	off := objPhysSize
	binary.LittleEndian.PutUint32(block[off:off+4], cpmFlagLast)
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	base := off + 8
	for i, e := range entries {
		entry := base + i*40
		binary.LittleEndian.PutUint32(block[entry:entry+4], e.objType)
		binary.LittleEndian.PutUint32(block[entry+4:entry+8], e.objSubtype)
		binary.LittleEndian.PutUint32(block[entry+8:entry+12], 4096) // cpm_size
		binary.LittleEndian.PutUint32(block[entry+12:entry+16], 0)   // cpm_pad
		binary.LittleEndian.PutUint64(block[entry+16:entry+24], 0)   // cpm_fs_oid
		binary.LittleEndian.PutUint64(block[entry+24:entry+32], e.oid)
		binary.LittleEndian.PutUint64(block[entry+32:entry+40], e.paddr)
	}
}

// updateNXSuperblockForCheckpoint mutates the supplied NX SB block,
// rewriting only the fields that change between checkpoints — the obj
// header's xid, the xp_desc / xp_data window indices/lengths/next slots,
// and nx_next_xid. Every other field (UUID, omap_oid, spaceman_oid,
// reaper_oid, fs_oid array, max_file_systems, ephemeral_info,
// nx_counters, nx_newest_mounted_version, fusion slots, etc.) is left
// alone so this works on containers that Apple — not our FormatContainer
// — produced. The cksum is intentionally NOT recomputed here; the caller
// runs sealBlock after this returns.
func updateNXSuperblockForCheckpoint(
	block []byte,
	xid uint64,
	descIndex, descLen, descNext uint32,
	dataIndex, dataLen, dataNext uint32,
	nextXID uint64,
) {
	// obj_phys.o_xid at offset 16.
	binary.LittleEndian.PutUint64(block[16:24], xid)
	// nx_next_xid at offset 96.
	binary.LittleEndian.PutUint64(block[96:104], nextXID)
	// xp_desc_next, xp_data_next at offsets 128 and 132.
	binary.LittleEndian.PutUint32(block[128:132], descNext)
	binary.LittleEndian.PutUint32(block[132:136], dataNext)
	// xp_desc_index/len, xp_data_index/len at offsets 136..151.
	binary.LittleEndian.PutUint32(block[136:140], descIndex)
	binary.LittleEndian.PutUint32(block[140:144], descLen)
	binary.LittleEndian.PutUint32(block[144:148], dataIndex)
	binary.LittleEndian.PutUint32(block[148:152], dataLen)
}

