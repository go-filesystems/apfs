package filesystem_apfs

// special_files.go adds writers for the four POSIX special-file types
// APFS represents alongside regular files / directories / symlinks:
// FIFOs, UNIX-domain sockets, block devices, and character devices.
//
// On-disk shape: an inode with the appropriate `mode` bits (S_IFIFO /
// S_IFSOCK / S_IFBLK / S_IFCHR), a parent dentry with the matching
// `drec_type`, and (for device nodes only) an INO_EXT_TYPE_RDEV xfield
// carrying the encoded device number. No file_extent, no dstream_id,
// no payload blocks: special files have no content.

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// POSIX file-type bits (mode high nibble).
const (
	modeFIFO  uint16 = 0o010000 // S_IFIFO
	modeCHR   uint16 = 0o020000 // S_IFCHR
	modeBLK   uint16 = 0o060000 // S_IFBLK
	modeSOCK  uint16 = 0o140000 // S_IFSOCK
)

// APFS drec types — `dir_rec_flags` low byte (apfs_raw.h).
const (
	drecTypeFIFO uint16 = 1  // DT_FIFO
	drecTypeCHR  uint16 = 2  // DT_CHR
	drecTypeBLK  uint16 = 6  // DT_BLK
	drecTypeSOCK uint16 = 12 // DT_SOCK
)

// inoExtTypeRDEV is the xfield carrying a device number for block /
// character device inodes (apfs_raw.h: APFS_INODE_EXT_TYPE_RDEV = 13).
const inoExtTypeRDEV byte = 13

// CreateFifo creates a named pipe under (parentOID, name) with the
// given permission bits. Returns the new FIFO's inode oid. FIFOs have
// no content blocks; the inode + drec are sufficient.
func (v *Volume) CreateFifo(parentOID uint64, name string, perm uint16) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.createSpecialInode(parentOID, name, modeFIFO|perm&0o7777, drecTypeFIFO, 0, 0)
}

// CreateSocket creates a UNIX-domain socket node. Same shape as a FIFO
// but with `mode = S_IFSOCK` and drec type DT_SOCK.
func (v *Volume) CreateSocket(parentOID uint64, name string, perm uint16) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.createSpecialInode(parentOID, name, modeSOCK|perm&0o7777, drecTypeSOCK, 0, 0)
}

// CreateBlockDevice creates a block-device node under (parentOID, name).
// `rdev` is the encoded device number (major / minor pair packed via
// the platform's `mkdev` macro — the kernel decodes it into st_rdev on
// stat(2)). The inode carries an INO_EXT_TYPE_RDEV xfield.
func (v *Volume) CreateBlockDevice(parentOID uint64, name string, perm uint16, rdev uint32) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.createSpecialInode(parentOID, name, modeBLK|perm&0o7777, drecTypeBLK, inoExtTypeRDEV, rdev)
}

// CreateCharDevice creates a character-device node — same as
// CreateBlockDevice but with `mode = S_IFCHR` and drec type DT_CHR.
func (v *Volume) CreateCharDevice(parentOID uint64, name string, perm uint16, rdev uint32) (uint64, error) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	return v.createSpecialInode(parentOID, name, modeCHR|perm&0o7777, drecTypeCHR, inoExtTypeRDEV, rdev)
}

// createSpecialInode is the shared backbone for FIFO / socket / block /
// char device creation. xfieldType=0 means "no xfield" (FIFO + socket);
// xfieldType=inoExtTypeRDEV (13) carries the rdev number for device
// nodes.
func (v *Volume) createSpecialInode(parentOID uint64, name string, mode, drecType uint16, xfieldType byte, rdev uint32) (uint64, error) {
	if v.c.w == nil {
		return 0, ErrReadOnly
	}
	if v.xidLimit != ^uint64(0) {
		return 0, fmt.Errorf("apfs: createSpecialInode on a snapshot view is not supported")
	}
	if err := v.checkSnapshotGuard(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("apfs: createSpecialInode: empty name")
	}
	bs := v.physicalBlockSize()
	rootPaddr, err := v.c.omapLookup(v.volOmap, v.apsb.rootTreeOID, v.xidLimit)
	if err != nil {
		return 0, err
	}
	newOID, err := v.nextInodeOID()
	if err != nil {
		return 0, err
	}
	rebindToRoot := parentOID == apfsRootDirParent || parentOID == apfsRootDirInoNum
	if rebindToRoot {
		parentOID = apfsRootDirInoNum
	}
	inodeKey := encodeInodeKey(newOID)
	inodeVal := encodeSpecialInodeValue(newOID, parentOID, mode, xfieldType, rdev)
	drKey := encodeDrecKey(parentOID, name)
	drVal := encodeDrecValue(newOID, drecType)
	newRecords := []fsLeafKV{
		{key: inodeKey, val: inodeVal},
		{key: drKey, val: drVal},
	}
	leafXID := v.rootNode.hdr.xid
	if leafXID == 0 {
		leafXID = defaultFormatXID
	}

	if v.rootNode.IsLeaf() {
		existing, err := readAllLeafEntries(v.rootNode, v.rootInfo)
		if err != nil {
			return 0, err
		}
		all := make([]fsLeafKV, 0, len(existing)+len(newRecords)+2)
		all = append(all, existing...)
		for _, ne := range newRecords {
			all = upsertEntry(all, ne.key, ne.val)
		}
		if rebindToRoot {
			all = upsertRootDir(all)
		} else {
			all, err = patchParentNchildrenInList(all, parentOID)
			if err != nil {
				return 0, fmt.Errorf("apfs: createSpecialInode: patch parent: %w", err)
			}
		}
		if leafFitsCheck(all, int(bs), true) {
			newLeaf, err := emitFSTreeLeafExplicit(all, int(bs), v.apsb.rootTreeOID, leafXID)
			if err != nil {
				return 0, err
			}
			if _, err := v.c.w.WriteAt(newLeaf, int64(rootPaddr*bs)); err != nil {
				return 0, err
			}
			if err := v.reloadRoot(rootPaddr); err != nil {
				return 0, err
			}
			return newOID, nil
		}
		if err := v.splitRootLeafAndWrite(all, rootPaddr, leafXID); err != nil {
			return 0, err
		}
		return newOID, nil
	}
	for _, rec := range newRecords {
		leafPaddr, leafOID, _, err := v.descendToLeafForKey(rec.key)
		if err != nil {
			return 0, err
		}
		if err := v.modifyLeafAtPaddrAndInsert(leafPaddr, leafOID, leafXID, []fsLeafKV{rec}, rootPaddr); err != nil {
			return 0, err
		}
	}
	if rebindToRoot {
		if err := v.refreshNonRootParentNchildren(apfsRootDirInoNum, leafXID, rootPaddr, true); err != nil {
			return 0, err
		}
	} else {
		if err := v.refreshNonRootParentNchildren(parentOID, leafXID, rootPaddr, false); err != nil {
			return 0, err
		}
	}
	if !v.rootNode.IsLeaf() {
		if err := v.refreshRoot(rootPaddr); err != nil {
			return 0, err
		}
	}
	return newOID, nil
}

// encodeSpecialInodeValue serialises a J_INODE_VAL for a FIFO / socket
// / block / char device. No INO_EXT_TYPE_DSTREAM (no content), no
// INO_EXT_TYPE_NAME. For device nodes (xfieldType = inoExtTypeRDEV)
// we emit a single 4-byte rdev xfield — total inode val size is
// 92 + 4 (xf header) + 4 (xf entry) + 8 (padded rdev to 8-byte align)
// = 108 bytes. For FIFOs / sockets (xfieldType = 0) we emit just the
// empty xf_blob header (count=0) — total 96 bytes.
func encodeSpecialInodeValue(oid, parentID uint64, mode uint16, xfieldType byte, rdev uint32) []byte {
	const baseLen = 92
	const xfHeader = 4 // count + used_data_len
	if xfieldType == 0 {
		val := make([]byte, baseLen+xfHeader)
		fillInodeBase(val, oid, parentID, mode)
		// Empty xf_blob: count=0, used_data_len=0.
		binary.LittleEndian.PutUint16(val[baseLen:baseLen+2], 0)
		binary.LittleEndian.PutUint16(val[baseLen+2:baseLen+4], 0)
		return val
	}
	// One xfield (RDEV: 4 bytes data, padded to 8 for alignment).
	const xfEntry = 4
	const rdevDataLen = 4
	const rdevPaddedLen = 8 // align to 8-byte boundary
	val := make([]byte, baseLen+xfHeader+xfEntry+rdevPaddedLen)
	fillInodeBase(val, oid, parentID, mode)
	xf := val[baseLen:]
	binary.LittleEndian.PutUint16(xf[0:2], 1)              // count = 1
	binary.LittleEndian.PutUint16(xf[2:4], rdevPaddedLen)  // used_data_len
	xf[4] = xfieldType                                      // type = INO_EXT_TYPE_RDEV
	xf[5] = 0                                               // flags
	binary.LittleEndian.PutUint16(xf[6:8], rdevDataLen)    // size = 4
	binary.LittleEndian.PutUint32(xf[xfHeader+xfEntry:xfHeader+xfEntry+4], rdev)
	return val
}

// fillInodeBase populates the 92-byte apfs_inode_val base (timestamps,
// flags, owner, group, mode). Shared between encodeSpecialInodeValue
// and the existing encoders.
func fillInodeBase(val []byte, oid, parentID uint64, mode uint16) {
	binary.LittleEndian.PutUint64(val[0:8], parentID)
	binary.LittleEndian.PutUint64(val[8:16], oid) // private_id
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(val[16:24], now)
	binary.LittleEndian.PutUint64(val[24:32], now)
	binary.LittleEndian.PutUint64(val[32:40], now)
	binary.LittleEndian.PutUint64(val[40:48], now)
	binary.LittleEndian.PutUint64(val[48:56], 0x8000) // INODE_HAS_FINDER_INFO
	binary.LittleEndian.PutUint32(val[56:60], 1)      // nlink = 1
	binary.LittleEndian.PutUint32(val[60:64], 6)      // APFS_PROTECTION_CLASS_F
	binary.LittleEndian.PutUint32(val[72:76], uint32(os.Geteuid()))
	binary.LittleEndian.PutUint32(val[76:80], uint32(os.Getegid()))
	binary.LittleEndian.PutUint16(val[80:82], mode)
}
