package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

// memReadAt is a tiny ReadAt-only backing buffer for the synthetic image.
type memReadAt struct{ buf []byte }

func (m *memReadAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) >= len(m.buf) {
		return 0, io.EOF
	}
	n := copy(p, m.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// containerImage assembles a minimal valid APFS container in memory:
//
//	block 0:  NX superblock (omap @ block 1, fs_oid=[100])
//	block 1:  container OMAP (tree @ block 2)
//	block 2:  container OMAP B-tree root+leaf, one entry oid=100 → block 3
//	block 3:  APSB (omap @ block 4, root_tree_oid=200)
//	block 4:  volume OMAP (tree @ block 5)
//	block 5:  volume OMAP B-tree root+leaf, one entry oid=200 → block 6
//	block 6:  FS-tree root+leaf with three records: inode(101), drec(child=101), file_extent(101)
//	block 7:  file payload (the bytes ReadFile should return)
type containerImage struct {
	blocks [][]byte
}

func newContainerImage() *containerImage {
	img := &containerImage{blocks: make([][]byte, 8)}
	for i := range img.blocks {
		img.blocks[i] = make([]byte, 4096)
	}
	return img
}

func (i *containerImage) bytes() []byte {
	out := make([]byte, 0, 8*4096)
	for _, b := range i.blocks {
		out = append(out, b...)
	}
	return out
}

// writeObjHdr writes a minimal obj_phys_t into block. cksum is left zero
// (this package does not validate it, mirroring real APFS containers when
// the parser does not check checksums).
func writeObjHdr(block []byte, oid, xid uint64, typ uint16, subtype uint32) {
	binary.LittleEndian.PutUint64(block[0:8], 0) // cksum
	binary.LittleEndian.PutUint64(block[8:16], oid)
	binary.LittleEndian.PutUint64(block[16:24], xid)
	binary.LittleEndian.PutUint16(block[24:26], typ)
	binary.LittleEndian.PutUint16(block[26:28], 0)
	binary.LittleEndian.PutUint32(block[28:32], subtype)
}

func writeNXSB(block []byte, omapOID uint64, fsOIDs []uint64) {
	writeObjHdr(block, 1, 1, objTypeNXSuperblock, 0)
	copy(block[32:36], "NXSB")
	binary.LittleEndian.PutUint32(block[36:40], 4096) // block_size
	binary.LittleEndian.PutUint64(block[40:48], 1024) // block_count
	binary.LittleEndian.PutUint64(block[160:168], omapOID)
	for i, oid := range fsOIDs {
		binary.LittleEndian.PutUint64(block[184+i*8:], oid)
	}
}

func writeOMAP(block []byte, treeOID uint64) {
	writeObjHdr(block, 0, 1, objTypeOMAP, 0)
	off := objPhysSize
	binary.LittleEndian.PutUint32(block[off:off+4], 0)        // flags
	binary.LittleEndian.PutUint32(block[off+4:off+8], 0)      // snap_count
	binary.LittleEndian.PutUint32(block[off+8:off+12], 0x10)  // tree_type (BTree)
	binary.LittleEndian.PutUint32(block[off+12:off+16], 0x10) // snap tree type
	binary.LittleEndian.PutUint64(block[off+16:off+24], treeOID)
	binary.LittleEndian.PutUint64(block[off+24:off+32], 0) // snap oid
	binary.LittleEndian.PutUint64(block[off+32:off+40], 1) // most recent xid
}

// writeOmapBTreeLeaf builds a fixed-shape root-AND-leaf B-tree node holding
// the supplied (oid → physBlock) entries. Both keys and values are 16 bytes.
func writeOmapBTreeLeaf(block []byte, entries []struct{ oid, paddr uint64 }) {
	writeObjHdr(block, 0, 1, objTypeBTree, uint32(objTypeOMAP))
	off := objPhysSize
	flags := btnFlagRoot | btnFlagLeaf | btnFlagFixedKVSize
	binary.LittleEndian.PutUint16(block[off:off+2], flags)
	binary.LittleEndian.PutUint16(block[off+2:off+4], 0) // level=0
	binary.LittleEndian.PutUint32(block[off+4:off+8], uint32(len(entries)))
	// table_space starts at offset 0 within btn_data; one TOC entry = 4 bytes.
	tocLen := uint16(len(entries) * 4)
	binary.LittleEndian.PutUint16(block[off+8:off+10], 0) // tableSpace.off
	binary.LittleEndian.PutUint16(block[off+10:off+12], tocLen)
	// free_space, key_free_list, val_free_list — leave as zero, the parser
	// does not require them in this iteration.
	dataStart := off + btreeNodeHeaderSize
	tocOff := dataStart
	keyArea := dataStart + int(tocLen)
	// values grow from the end of the node toward keys; the last 40 bytes
	// of the node hold the btreeInfo trailer for root nodes.
	valBaseEnd := len(block) - btreeInfoSize
	for i, e := range entries {
		// TOC entry: key offset (from key-area start) and value offset.
		// Per Apple's apfs.h, toc.val is the distance from val_end to
		// the START of the value (so values grow backward from val_end).
		// First value: val=sizeof(value)=16; second: val=2*16; etc.
		keyOff := uint16(i * 16)
		valOff := uint16((i + 1) * 16)
		binary.LittleEndian.PutUint16(block[tocOff+i*4:tocOff+i*4+2], keyOff)
		binary.LittleEndian.PutUint16(block[tocOff+i*4+2:tocOff+i*4+4], valOff)
		// key bytes: oid + xid(=1)
		k := block[keyArea+i*16 : keyArea+i*16+16]
		binary.LittleEndian.PutUint64(k[0:8], e.oid)
		binary.LittleEndian.PutUint64(k[8:16], 1)
		// value bytes: flags(0) + size(4096) + paddr
		v := block[valBaseEnd-(i+1)*16 : valBaseEnd-i*16]
		binary.LittleEndian.PutUint32(v[0:4], 0)
		binary.LittleEndian.PutUint32(v[4:8], 4096)
		binary.LittleEndian.PutUint64(v[8:16], e.paddr)
	}
	// btreeInfo trailer
	bi := block[len(block)-btreeInfoSize:]
	binary.LittleEndian.PutUint32(bi[0:4], 0x4)        // flags: BTREE_FIXED_KV_SIZE
	binary.LittleEndian.PutUint32(bi[4:8], 4096)       // node_size
	binary.LittleEndian.PutUint32(bi[8:12], 16)        // key_size
	binary.LittleEndian.PutUint32(bi[12:16], 16)       // val_size
	binary.LittleEndian.PutUint32(bi[16:20], 16)       // longest_key
	binary.LittleEndian.PutUint32(bi[20:24], 16)       // longest_val
	binary.LittleEndian.PutUint64(bi[24:32], uint64(len(entries)))
	binary.LittleEndian.PutUint64(bi[32:40], 1)
}

func writeAPSB(block []byte, oid, omapOID, rootTreeOID uint64, name string) {
	writeObjHdr(block, oid, 1, objTypeAPFSVolume, 0)
	copy(block[0x20:0x24], "APSB")
	// Match Apple's apfs_superblock layout (linux-apfs_raw.h):
	//   +0x80  apfs_omap_oid
	//   +0x88  apfs_root_tree_oid
	//   +0x90  apfs_extentref_tree_oid
	//   +0x98  apfs_snap_meta_tree_oid
	//   +0x2C0 apfs_volname
	binary.LittleEndian.PutUint64(block[0x80:0x88], omapOID)
	binary.LittleEndian.PutUint64(block[0x88:0x90], rootTreeOID)
	binary.LittleEndian.PutUint64(block[0x90:0x98], 0)
	binary.LittleEndian.PutUint64(block[0x98:0xA0], 0)
	copy(block[0x2C0:0x2C0+len(name)], name)
}

// writeFSTreeLeaf builds a variable-shape root-AND-leaf B-tree holding three
// records for inode 101: J_INODE_VAL, J_DIR_REC (parent has a child named
// "hello.txt"), and J_FILE_EXTENT (one extent covering 4096 bytes at block 7).
func writeFSTreeLeaf(block []byte, inodeID, parentID, physBlock uint64, payloadSize uint64, fileName string) {
	// Delegate to writeFSTreeLeafCustom so the same sort/encoding rules
	// apply (entries are sorted by compareFSKey, the layout exactly
	// matches what the parser expects, the btreeInfo trailer is set up
	// uniformly).
	writeFSTreeLeafCustom(block, []fsLeafEntry{
		{key: jKey(inodeID, jTypeInode), val: buildInodeValue(parentID, payloadSize, 0o100644)},
		{key: drecKey(parentID, fileName), val: buildDrecValue(inodeID)},
		{key: fileExtKey(inodeID, 0), val: buildFileExtentValue(payloadSize, physBlock)},
	})
}

// buildInodeValue creates a minimal J_INODE_VAL with one xfield (J_DSTREAM).
func buildInodeValue(parent, size uint64, mode uint16) []byte {
	const baseLen = 92
	const xHdr = 4   // count + used
	const dsLen = 40 // J_DSTREAM is 40 bytes per apfs_dstream_t
	val := make([]byte, baseLen+4+(1*4)+dsLen)
	binary.LittleEndian.PutUint64(val[0:8], parent)
	binary.LittleEndian.PutUint16(val[80:82], mode)
	xf := val[baseLen:]
	binary.LittleEndian.PutUint16(xf[0:2], 1)             // count
	binary.LittleEndian.PutUint16(xf[2:4], uint16(dsLen)) // used data length
	xf[4] = 0x08                                          // INO_EXT_TYPE_DSTREAM
	xf[5] = 0                                             // flags
	binary.LittleEndian.PutUint16(xf[6:8], uint16(dsLen)) // size
	dsArea := xf[8:]
	binary.LittleEndian.PutUint64(dsArea[0:8], size)   // size
	binary.LittleEndian.PutUint64(dsArea[8:16], size)  // alloced_size
	binary.LittleEndian.PutUint64(dsArea[16:24], 0)    // default_crypto_id
	binary.LittleEndian.PutUint64(dsArea[24:32], size) // total_bytes_written
	binary.LittleEndian.PutUint64(dsArea[32:40], 0)    // total_bytes_read
	_ = xHdr
	return val
}

func buildDrecValue(fileID uint64) []byte {
	v := make([]byte, 18)
	binary.LittleEndian.PutUint64(v[0:8], fileID)
	binary.LittleEndian.PutUint64(v[8:16], 0)
	binary.LittleEndian.PutUint16(v[16:18], 0)
	return v
}

func buildFileExtentValue(length, phys uint64) []byte {
	v := make([]byte, 24)
	binary.LittleEndian.PutUint64(v[0:8], length&((uint64(1)<<56)-1))
	binary.LittleEndian.PutUint64(v[8:16], phys)
	binary.LittleEndian.PutUint64(v[16:24], 0)
	return v
}

func TestOpenAndRead(t *testing.T) {
	img := newContainerImage()
	writeNXSB(img.blocks[0], 1, []uint64{100})
	writeOMAP(img.blocks[1], 2)
	writeOmapBTreeLeaf(img.blocks[2], []struct{ oid, paddr uint64 }{
		{oid: 100, paddr: 3},  // APSB
		{oid: 200, paddr: 6},  // FS-tree root (virtual oid)
	})
	writeAPSB(img.blocks[3], 100, 4, 200, "TestVol")
	writeOMAP(img.blocks[4], 5)
	writeOmapBTreeLeaf(img.blocks[5], []struct{ oid, paddr uint64 }{
		{oid: 200, paddr: 6},
	})
	const fileName = "hello.txt"
	const payload = "hello from native APFS"
	writeFSTreeLeaf(img.blocks[6], 101, 1, 7, uint64(len(payload)), fileName)
	// payload block
	copy(img.blocks[7], []byte(payload))

	r := &memReadAt{buf: img.bytes()}
	c, err := OpenContainerFromBackend(r)
	if err != nil {
		t.Fatalf("OpenContainerFromBackend: %v", err)
	}
	defer c.Close()

	vols := c.Volumes()
	if len(vols) != 1 || vols[0].OID != 100 {
		t.Fatalf("Volumes() = %+v, want one volume with OID=100", vols)
	}

	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if v.Name() != "TestVol" {
		t.Fatalf("Name = %q, want TestVol", v.Name())
	}

	inodes, err := v.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	if len(inodes) != 1 {
		t.Fatalf("ListInodes returned %d inodes, want 1: %+v", len(inodes), inodes)
	}
	got := inodes[0]
	if got.ID != 101 || got.Name != fileName || got.Size != uint64(len(payload)) {
		t.Fatalf("inode mismatch: id=%d name=%q size=%d", got.ID, got.Name, got.Size)
	}

	data, err := v.ReadFile(got)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(data, []byte(payload)) {
		t.Fatalf("ReadFile = %q, want %q", data, payload)
	}
}

func TestDetectRejectsNonAPFS(t *testing.T) {
	r := &memReadAt{buf: make([]byte, 4096)}
	if _, err := OpenContainerFromBackend(r); err == nil {
		t.Fatal("expected error opening empty buffer as APFS")
	}
}

// ensure helper builders compile cleanly.
var _ = fmt.Sprintf
