package filesystem_apfs

// obj.go parses the lowest layers of an APFS container: the
// obj_phys_t header, the NX superblock, the object map (omap_phys_t),
// and the per-volume APSB superblock.
//
// Reference: "Apple File System Reference" (Apple Inc., 2023-09-15) and the
// open-source xnu apfs.h headers. Field names follow the Apple convention so
// the code remains greppable against the spec.

import (
	"encoding/binary"
	"fmt"
)

// Object types as stored in the low 16 bits of obj_phys_t.o_type. Only the
// types we actually traverse are listed here.
const (
	objTypeNXSuperblock uint16 = 0x0001
	objTypeBTree        uint16 = 0x0002
	objTypeBTreeNode    uint16 = 0x0003
	objTypeSpaceman     uint16 = 0x0005
	objTypeAPFSVolume   uint16 = 0x000D
	objTypeOMAP         uint16 = 0x000B
	objTypeFSTree       uint16 = 0x000E // subtype value for the volume FS-tree
	objTypeBlockRefTree uint16 = 0x000F // subtype value for the volume extent-ref tree
	objTypeSnapMetaTree uint16 = 0x0010 // subtype value for the volume snap-meta tree
)

// Magics on disk are stored little-endian; the readable forms below are what
// you see when treating the four bytes as ASCII.
const (
	nxMagicASCII   = "NXSB"
	apsbMagicASCII = "APSB"
	btreeMagicLen  = 0 // B-tree nodes have no magic, they rely on obj header
)

// objPhysSize is the on-disk size of every APFS object header.
const objPhysSize = 32

// objPhys is the 32-byte object header that prefixes every APFS object.
//
//	uint64 o_cksum   (Fletcher64 of the rest of the block, computed by Apple
//	                  but NOT verified by this package; APFS allows zero on
//	                  ephemeral objects)
//	uint64 o_oid     (object ID)
//	uint64 o_xid     (transaction ID)
//	uint16 o_type
//	uint16 o_flags   (high bits of the type word)
//	uint32 o_subtype
type objPhys struct {
	cksum   uint64
	oid     uint64
	xid     uint64
	typ     uint16
	flags   uint16
	subtype uint32
}

// readObjPhys decodes a 32-byte obj_phys_t header from the start of buf.
func readObjPhys(buf []byte) (objPhys, error) {
	if len(buf) < objPhysSize {
		return objPhys{}, fmt.Errorf("apfs: obj_phys: short buffer (%d bytes)", len(buf))
	}
	return objPhys{
		cksum:   binary.LittleEndian.Uint64(buf[0:8]),
		oid:     binary.LittleEndian.Uint64(buf[8:16]),
		xid:     binary.LittleEndian.Uint64(buf[16:24]),
		typ:     binary.LittleEndian.Uint16(buf[24:26]),
		flags:   binary.LittleEndian.Uint16(buf[26:28]),
		subtype: binary.LittleEndian.Uint32(buf[28:32]),
	}, nil
}

// nxSuperblockNative captures the fields of the NX (container) superblock
// this package needs to traverse the container. Other fields exist on disk
// but are not decoded.
//
// The xp_*_index / xp_*_len / xp_*_next fields locate the most recent
// checkpoint inside the descriptor / data ring buffers; Commit (D-7)
// needs them to compute the next checkpoint's slots.
type nxSuperblockNative struct {
	blockSize    uint32
	blockCount   uint64
	xid          uint64 // o_xid of block 0 (= xid of the current checkpoint)
	nextOID      uint64 // nx_next_oid (next virtual oid for new top-level / tree nodes)
	nextXID      uint64 // nx_next_xid (must exceed every used xid)
	xpDescBlocks uint32
	xpDataBlocks uint32
	xpDescBase   uint64
	xpDataBase   uint64
	xpDescIndex  uint32 // current checkpoint starts at desc[xpDescIndex]
	xpDescLen    uint32 // current checkpoint occupies xpDescLen slots
	xpDescNext   uint32 // first free slot after current checkpoint
	xpDataIndex  uint32
	xpDataLen    uint32
	xpDataNext   uint32
	uuid         [16]byte
	omapOID      uint64   // container object map (oid)
	spacemanOID  uint64   // ephemeral spaceman OID (lookup via current CheckpointMap)
	reaperOID    uint64   // ephemeral reaper OID
	fsOIDs       []uint64 // per-volume APSB oids (up to 100, zeros pruned)
}

// readNXSuperblock decodes the NX superblock from a 4 KiB block. Apple's
// spec lays the structure out at well-known offsets; we only read what we
// need. Offsets follow the spec precisely.
func readNXSuperblock(block []byte) (*nxSuperblockNative, error) {
	if len(block) < 1024 {
		return nil, fmt.Errorf("apfs: NX SB: block too short (%d bytes)", len(block))
	}
	hdr, err := readObjPhys(block[:objPhysSize])
	if err != nil {
		return nil, fmt.Errorf("apfs: NX SB: %w", err)
	}
	if (hdr.typ & 0x00FF) != objTypeNXSuperblock {
		return nil, fmt.Errorf("apfs: NX SB: wrong object type 0x%04x", hdr.typ)
	}
	if string(block[32:36]) != nxMagicASCII {
		return nil, fmt.Errorf("apfs: NX SB: magic mismatch")
	}
	sb := &nxSuperblockNative{
		blockSize:    binary.LittleEndian.Uint32(block[36:40]),
		blockCount:   binary.LittleEndian.Uint64(block[40:48]),
		xid:          hdr.xid,
		nextOID:      binary.LittleEndian.Uint64(block[88:96]),
		nextXID:      binary.LittleEndian.Uint64(block[96:104]),
		xpDescBlocks: binary.LittleEndian.Uint32(block[104:108]),
		xpDataBlocks: binary.LittleEndian.Uint32(block[108:112]),
		xpDescBase:   binary.LittleEndian.Uint64(block[112:120]),
		xpDataBase:   binary.LittleEndian.Uint64(block[120:128]),
		xpDescNext:   binary.LittleEndian.Uint32(block[128:132]),
		xpDataNext:   binary.LittleEndian.Uint32(block[132:136]),
		xpDescIndex:  binary.LittleEndian.Uint32(block[136:140]),
		xpDescLen:    binary.LittleEndian.Uint32(block[140:144]),
		xpDataIndex:  binary.LittleEndian.Uint32(block[144:148]),
		xpDataLen:    binary.LittleEndian.Uint32(block[148:152]),
		spacemanOID:  binary.LittleEndian.Uint64(block[152:160]),
		omapOID:      binary.LittleEndian.Uint64(block[160:168]),
		reaperOID:    binary.LittleEndian.Uint64(block[168:176]),
	}
	copy(sb.uuid[:], block[72:88])
	// fs_oid array starts at byte 184 in the on-disk layout (after reaper /
	// other oids). It contains 100 uint64 entries; entries equal to 0 mark
	// the end of the populated portion.
	const fsOIDOffset = 184
	const maxFsOIDs = 100
	if fsOIDOffset+maxFsOIDs*8 > len(block) {
		return nil, fmt.Errorf("apfs: NX SB: block too small to hold fs_oid array")
	}
	for i := 0; i < maxFsOIDs; i++ {
		off := fsOIDOffset + i*8
		oid := binary.LittleEndian.Uint64(block[off : off+8])
		if oid == 0 {
			break
		}
		sb.fsOIDs = append(sb.fsOIDs, oid)
	}
	return sb, nil
}

// omapPhys decodes the relevant fields of an omap_phys_t (object type 0x000B).
type omapPhys struct {
	flags    uint32
	snapCnt  uint32
	treeType uint32
	snapType uint32
	treeOID  uint64 // root B-tree of this object map
	snapOID  uint64
	mostRecentXID uint64
}

// readOmapPhys decodes an omap_phys_t from the start of a block.
func readOmapPhys(block []byte) (*omapPhys, error) {
	if len(block) < objPhysSize+40 {
		return nil, fmt.Errorf("apfs: omap_phys: block too short")
	}
	hdr, err := readObjPhys(block[:objPhysSize])
	if err != nil {
		return nil, err
	}
	if (hdr.typ & 0x00FF) != objTypeOMAP {
		return nil, fmt.Errorf("apfs: omap_phys: wrong object type 0x%04x", hdr.typ)
	}
	off := objPhysSize
	return &omapPhys{
		flags:         binary.LittleEndian.Uint32(block[off : off+4]),
		snapCnt:       binary.LittleEndian.Uint32(block[off+4 : off+8]),
		treeType:      binary.LittleEndian.Uint32(block[off+8 : off+12]),
		snapType:      binary.LittleEndian.Uint32(block[off+12 : off+16]),
		treeOID:       binary.LittleEndian.Uint64(block[off+16 : off+24]),
		snapOID:       binary.LittleEndian.Uint64(block[off+24 : off+32]),
		mostRecentXID: binary.LittleEndian.Uint64(block[off+32 : off+40]),
	}, nil
}

// apsbSuperblock captures the volume-level fields we need. APSB stands for
// "APFS Superblock"; one APSB exists per volume in a container.
//
// snapMetaTreeType / extentRefTreeType carry the FULL apfs_*_tree_type
// word (storage class | object type) so callers can tell whether the
// associated oid is a virtual oid (resolve through the volume OMAP) or
// a physical block address. mkapfs writes both as
// `APFS_OBJ_PHYSICAL | APFS_OBJECT_TYPE_BTREE = 0x40000002`; older
// in-tree tests synthesise VIRTUAL trees and use the OMAP path.
type apsbSuperblock struct {
	rootTreeOID       uint64 // FS-tree root oid (virtual; resolved through the volume omap)
	extentRefOID      uint64
	snapMetaOID       uint64
	omapOID           uint64 // per-volume omap (different from container omap)
	rootTreeType      uint32 // apfs_root_tree_type (storage class | type)
	extentRefTreeType uint32 // apfs_extentref_tree_type
	snapMetaTreeType  uint32 // apfs_snap_meta_tree_type
	numSnapshots      uint32 // apfs_num_snapshots (APSB +0xD4)
	volumeName        string
	uuid              [16]byte
}

// snapMetaIsPhysical reports whether the snap-meta tree is stored
// PHYSICAL (oid is the block address) vs VIRTUAL (oid resolved through
// the volume OMAP). Apple's apfs.h tree-type encoding puts the storage
// class in the high bits of the type word.
func (a *apsbSuperblock) snapMetaIsPhysical() bool {
	return a.snapMetaTreeType&0xC0000000 == 0x40000000
}

// readAPSB decodes an APFS volume superblock from a 4 KiB block.
func readAPSB(block []byte) (*apsbSuperblock, error) {
	if len(block) < 1024 {
		return nil, fmt.Errorf("apfs: APSB: block too short")
	}
	hdr, err := readObjPhys(block[:objPhysSize])
	if err != nil {
		return nil, err
	}
	if (hdr.typ & 0x00FF) != objTypeAPFSVolume {
		return nil, fmt.Errorf("apfs: APSB: wrong object type 0x%04x", hdr.typ)
	}
	if string(block[32:36]) != apsbMagicASCII {
		return nil, fmt.Errorf("apfs: APSB: magic mismatch")
	}
	// Per apfs_superblock (linux-apfs_raw.h):
	//   +0x80  apfs_omap_oid
	//   +0x88  apfs_root_tree_oid
	//   +0x90  apfs_extentref_tree_oid
	//   +0x98  apfs_snap_meta_tree_oid
	sb := &apsbSuperblock{
		omapOID:           binary.LittleEndian.Uint64(block[0x80:0x88]),
		rootTreeOID:       binary.LittleEndian.Uint64(block[0x88:0x90]),
		extentRefOID:      binary.LittleEndian.Uint64(block[0x90:0x98]),
		snapMetaOID:       binary.LittleEndian.Uint64(block[0x98:0xA0]),
		rootTreeType:      binary.LittleEndian.Uint32(block[0x74:0x78]),
		extentRefTreeType: binary.LittleEndian.Uint32(block[0x78:0x7C]),
		snapMetaTreeType:  binary.LittleEndian.Uint32(block[0x7C:0x80]),
		numSnapshots:      binary.LittleEndian.Uint32(block[0xD4:0xD8]),
	}
	// Volume name lives at offset 0x2C0 (apfs_volname_t, 256 bytes,
	// NUL-terminated).
	const volNameOff = 0x2C0
	const volNameLen = 256
	if volNameOff+volNameLen <= len(block) {
		raw := block[volNameOff : volNameOff+volNameLen]
		if i := indexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		sb.volumeName = string(raw)
	}
	// volume UUID at offset 240 (apfs_vol_uuid).
	const volUUIDOff = 240
	if volUUIDOff+16 <= len(block) {
		copy(sb.uuid[:], block[volUUIDOff:volUUIDOff+16])
	}
	return sb, nil
}

// indexByte mirrors bytes.IndexByte but avoids the import.
func indexByte(s []byte, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
