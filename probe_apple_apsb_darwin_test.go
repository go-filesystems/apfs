//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	apfsfde "github.com/go-fde/apfs"
)

// TestProbe_AppleEncryptedAPSBDecrypt extracts the VEK from the Apple
// reference encrypted DMG using the known probe passphrase, decrypts
// the volume APSB, and dumps a few key fields. Used to byte-diff
// Apple's encrypted APSB layout against what FormatContainerEncrypted
// produces — pinpointing why the kext's spaceman query (-69808) fails
// on our output but succeeds on Apple's.
func TestProbe_AppleEncryptedAPSBDecrypt(t *testing.T) {
	const refPath = "/tmp/appleref/ref.dmg"
	const apfsPartByteOff = 20480 // Apple's hdiutil create puts APFS at LBA 40
	const blockSize = 4096
	const passphrase = "apfsfde-probe-password"

	if _, err := os.Stat(refPath); err != nil {
		t.Skipf("needs %s: %v", refPath, err)
	}
	f, err := os.Open(refPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Read NX SB and pull container UUID.
	nxSB := make([]byte, blockSize)
	f.ReadAt(nxSB, apfsPartByteOff)
	if string(nxSB[32:36]) != "NXSB" {
		t.Fatalf("NXSB magic missing")
	}
	var containerUUID [16]byte
	copy(containerUUID[:], nxSB[72:88])
	containerKBPaddr := binary.LittleEndian.Uint64(nxSB[1296:1304])
	t.Logf("ref container UUID = %x, kb_paddr = %d", containerUUID, containerKBPaddr)

	// Decrypt container keybag → walk to volume kb → recover VEK.
	containerKBCipher := make([]byte, blockSize)
	f.ReadAt(containerKBCipher, apfsPartByteOff+int64(containerKBPaddr)*blockSize)
	containerKBPlain, err := apfsfde.DecryptContainerKeybag(containerKBCipher, containerUUID, containerKBPaddr)
	if err != nil {
		t.Fatal(err)
	}
	volumeKBPaddr, volumeUUID, vekBlobBytes := walkContainerKB(t, containerKBPlain)
	t.Logf("ref volume UUID = %x, kb_paddr = %d", volumeUUID, volumeKBPaddr)

	volumeKBCipher := make([]byte, blockSize)
	f.ReadAt(volumeKBCipher, apfsPartByteOff+int64(volumeKBPaddr)*blockSize)
	volumeKBPlain, err := apfsfde.DecryptVolumeKeybag(volumeKBCipher, volumeUUID, volumeKBPaddr)
	if err != nil {
		t.Fatal(err)
	}
	kekBlobBytes := walkVolumeKB(t, volumeKBPlain)
	vek := unlockVEKFromBlobs(t, []byte(passphrase), kekBlobBytes, vekBlobBytes)
	t.Logf("recovered VEK from reference (len=%d)", len(vek))

	// Find the APSB paddr from the container OMAP.
	// Container OMAP is at nx_omap_oid (NX SB +160).
	containerOmapPaddr := binary.LittleEndian.Uint64(nxSB[160:168])
	t.Logf("ref container OMAP paddr = %d", containerOmapPaddr)

	containerOmap := make([]byte, blockSize)
	f.ReadAt(containerOmap, apfsPartByteOff+int64(containerOmapPaddr)*blockSize)
	// apfs_omap_phys: om_tree_oid at +48 (NOT +56 — that's om_snapshot_tree_oid).
	omapTreeOid := binary.LittleEndian.Uint64(containerOmap[48:56])
	t.Logf("ref container OMAP tree paddr = %d", omapTreeOid)

	omapTree := make([]byte, blockSize)
	f.ReadAt(omapTree, apfsPartByteOff+int64(omapTreeOid)*blockSize)
	t.Logf("first 128 bytes of OMAP tree:\n%s", hex.Dump(omapTree[:128]))

	// Parse the single OMAP leaf entry to extract APSB OID and paddr.
	// FIXED_KV layout: TOC entries are 4 bytes (key_off, val_off).
	// Key area starts at byte 56 + table_space.len; val area ends at
	// byte 4096 - 40 (btreeInfo trailer).
	tableSpaceLen := binary.LittleEndian.Uint16(omapTree[42:44])
	keyAreaStart := 56 + int(tableSpaceLen)
	valAreaEnd := blockSize - 40
	keyOff := binary.LittleEndian.Uint16(omapTree[56:58])
	valOff := binary.LittleEndian.Uint16(omapTree[58:60])
	keyPos := keyAreaStart + int(keyOff)
	valPos := valAreaEnd - int(valOff) - 16
	apsbOID := binary.LittleEndian.Uint64(omapTree[keyPos : keyPos+8])
	apsbXID := binary.LittleEndian.Uint64(omapTree[keyPos+8 : keyPos+16])
	apsbPaddr := binary.LittleEndian.Uint64(omapTree[valPos+8 : valPos+16])
	t.Logf("ref OMAP entry: oid=%d xid=%d → paddr=%d", apsbOID, apsbXID, apsbPaddr)

	// Try paddr 136 BOTH as plaintext (would be the case if Apple does
	// NOT VEK-encrypt the APSB) and decrypted with VEK.
	apsbCipher := make([]byte, blockSize)
	f.ReadAt(apsbCipher, apfsPartByteOff+int64(apsbPaddr)*blockSize)
	t.Logf("ref APSB raw bytes at paddr=%d:", apsbPaddr)
	t.Logf("  +0x20..+0x24: %s (raw)", string(apsbCipher[0x20:0x24]))
	t.Logf("  first 64 raw:\n%s", hex.Dump(apsbCipher[:64]))
	apsbDec, _ := apfsfde.DecryptVolumeBlock(apsbCipher, vek, apsbPaddr)
	t.Logf("ref APSB VEK-decrypted at paddr=%d:", apsbPaddr)
	t.Logf("  +0x20..+0x24: %s (decrypted)", string(apsbDec[0x20:0x24]))
	t.Logf("  first 64 decrypted:\n%s", hex.Dump(apsbDec[:64]))

	candidates := []uint64{apsbPaddr}
	for p := uint64(0); p < 200; p++ {
		candidates = append(candidates, p)
	}

	// Now build OUR output with the same flow and diff the APSBs
	// byte-by-byte.
	ourPath := filepath.Join(t.TempDir(), "ours-enc.apfs")
	if err := os.WriteFile(ourPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(ourPath, 1<<24, "OursDiff", []byte("diff-pass")); err != nil {
		t.Fatalf("FormatContainerEncrypted: %v", err)
	}
	ourFile, err := os.Open(ourPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ourFile.Close()

	// Our APSB is at formatAPSBBlock = 63.
	ourAPSB := make([]byte, blockSize)
	ourFile.ReadAt(ourAPSB, int64(formatAPSBBlock)*blockSize)
	if string(ourAPSB[0x20:0x24]) != "APSB" {
		t.Fatalf("our APSB magic missing at +0x20: %x", ourAPSB[:64])
	}
	t.Logf("OUR APSB first 256 bytes:\n%s", hex.Dump(ourAPSB[:256]))
	t.Logf("REF APSB first 256 bytes:\n%s", hex.Dump(apsbCipher[:256]))

	// Diff regions of interest. Skip cksum (0..7), oid (8..15), xid
	// (16..23) since those are random/per-instance. Skip uuid (0xF0..0x100).
	skip := func(off int) bool {
		switch {
		case off < 24:
			return true
		case off >= 0xF0 && off < 0x100:
			return true
		case off >= 0x100 && off < 0x108: // last_mod_time
			return true
		case off >= 0x110 && off < 0x130: // formatter_id
			return true
		case off >= 0x130 && off < 0x140: // formatter timestamps
			return true
		case off >= 0x2C0 && off < 0x300: // volume name (varies)
			return true
		}
		return false
	}
	diffs := 0
	for off := 0; off < 0x500; off++ {
		if skip(off) {
			continue
		}
		if ourAPSB[off] != apsbCipher[off] {
			diffs++
			if diffs <= 50 {
				t.Logf("DIFF +0x%X: ours=0x%02x ref=0x%02x", off, ourAPSB[off], apsbCipher[off])
			}
		}
	}
	t.Logf("total APSB byte diffs (excluding skip ranges): %d", diffs)

	// ── Spaceman byte-diff. ─────────────────────────────────────────
	// Find Apple's spaceman via the live NX SB:
	//   nx_spaceman_oid (offset 152) is an EPHEMERAL oid; resolve to a
	//   paddr by reading the CURRENT checkpoint mapping.
	refSpacemanOID := binary.LittleEndian.Uint64(nxSB[152:160])
	refXPDescBase := binary.LittleEndian.Uint64(nxSB[112:120])
	refXPDescIndex := binary.LittleEndian.Uint32(nxSB[136:140])
	refXPDescLen := binary.LittleEndian.Uint32(nxSB[140:144])
	t.Logf("ref nx_spaceman_oid=%d, xp_desc_base=%d, xp_desc_index=%d, xp_desc_len=%d",
		refSpacemanOID, refXPDescBase, refXPDescIndex, refXPDescLen)
	cpmPaddr := refXPDescBase + uint64(refXPDescIndex+refXPDescLen-1) - 1 // last NX SB copy is at +len-1; CPM is at +len-2
	// Apple convention from N-2 notes: CPM at desc[xp_desc_index+0], NX SB copy at desc[xp_desc_index+xp_desc_len-1].
	cpmPaddr = refXPDescBase + uint64(refXPDescIndex)
	t.Logf("ref CPM paddr = %d", cpmPaddr)

	cpm := make([]byte, blockSize)
	f.ReadAt(cpm, apfsPartByteOff+int64(cpmPaddr)*blockSize)
	// CPM layout: 32-byte obj_phys + uint32 cpm_flags + uint32 cpm_count + entries[].
	// Each entry is 40 bytes: type(4) + subtype(4) + size(4) + pad(4) + fs_oid(8) + oid(8) + paddr(8).
	cpmCount := binary.LittleEndian.Uint32(cpm[36:40])
	t.Logf("ref CPM count = %d", cpmCount)
	var refSpacemanPaddr uint64
	for i := uint32(0); i < cpmCount; i++ {
		entOff := 40 + int(i)*40
		entOID := binary.LittleEndian.Uint64(cpm[entOff+24 : entOff+32])
		entPaddr := binary.LittleEndian.Uint64(cpm[entOff+32 : entOff+40])
		entType := binary.LittleEndian.Uint32(cpm[entOff : entOff+4])
		t.Logf("  CPM entry[%d]: type=0x%x oid=%d paddr=%d", i, entType, entOID, entPaddr)
		if entOID == refSpacemanOID {
			refSpacemanPaddr = entPaddr
		}
	}
	if refSpacemanPaddr == 0 {
		t.Skip("could not resolve ref spaceman paddr")
	}
	refSpaceman := make([]byte, blockSize)
	f.ReadAt(refSpaceman, apfsPartByteOff+int64(refSpacemanPaddr)*blockSize)
	t.Logf("ref spaceman (paddr=%d) first 0x100 bytes:\n%s", refSpacemanPaddr, hex.Dump(refSpaceman[:0x100]))

	// Read OUR current spaceman the same way.
	ourNXSB := make([]byte, blockSize)
	ourFile.ReadAt(ourNXSB, 0)
	ourSpacemanOID := binary.LittleEndian.Uint64(ourNXSB[152:160])
	ourXPDescBase := binary.LittleEndian.Uint64(ourNXSB[112:120])
	ourXPDescIndex := binary.LittleEndian.Uint32(ourNXSB[136:140])
	ourCPMPaddr := ourXPDescBase + uint64(ourXPDescIndex)
	ourCPM := make([]byte, blockSize)
	ourFile.ReadAt(ourCPM, int64(ourCPMPaddr)*blockSize)
	ourCPMCount := binary.LittleEndian.Uint32(ourCPM[36:40])
	var ourSpacemanPaddr uint64
	for i := uint32(0); i < ourCPMCount; i++ {
		entOff := 40 + int(i)*40
		entOID := binary.LittleEndian.Uint64(ourCPM[entOff+24 : entOff+32])
		entPaddr := binary.LittleEndian.Uint64(ourCPM[entOff+32 : entOff+40])
		if entOID == ourSpacemanOID {
			ourSpacemanPaddr = entPaddr
		}
	}
	t.Logf("our spaceman paddr = %d", ourSpacemanPaddr)
	ourSpaceman := make([]byte, blockSize)
	ourFile.ReadAt(ourSpaceman, int64(ourSpacemanPaddr)*blockSize)
	t.Logf("our spaceman first 0x100 bytes:\n%s", hex.Dump(ourSpaceman[:0x100]))

	// Verify our CPM has the same shape as Apple's.
	t.Logf("our CPM count = %d", ourCPMCount)
	for i := uint32(0); i < ourCPMCount; i++ {
		entOff := 40 + int(i)*40
		entOID := binary.LittleEndian.Uint64(ourCPM[entOff+24 : entOff+32])
		entPaddr := binary.LittleEndian.Uint64(ourCPM[entOff+32 : entOff+40])
		entType := binary.LittleEndian.Uint32(ourCPM[entOff : entOff+4])
		t.Logf("  ours CPM entry[%d]: type=0x%x oid=%d paddr=%d", i, entType, entOID, entPaddr)
	}

	// Diff with skip ranges for per-instance fields.
	smSkip := func(off int) bool {
		switch {
		case off < 24: // cksum + oid
			return true
		case off >= 16 && off < 24: // xid
			return true
		}
		return false
	}
	smDiffs := 0
	for off := 0; off < blockSize; off++ {
		if smSkip(off) {
			continue
		}
		if ourSpaceman[off] != refSpaceman[off] {
			smDiffs++
			if smDiffs <= 80 {
				t.Logf("SM-DIFF +0x%X: ours=0x%02x ref=0x%02x", off, ourSpaceman[off], refSpaceman[off])
			}
		}
	}
	t.Logf("total spaceman byte diffs: %d", smDiffs)

	// Dump Apple's FQ tree blocks + integrity_meta — these are the
	// three ephemerals our writer is missing in the encrypted path.
	for label, paddr := range map[string]uint64{
		"SFQ_IP_BTREE   (oid 1027)": 43,
		"SFQ_MAIN_BTREE (oid 1029)": 44,
		"INTEGRITY_META (oid 1030)": 45,
	} {
		buf := make([]byte, blockSize)
		f.ReadAt(buf, apfsPartByteOff+int64(paddr)*blockSize)
		t.Logf("%s @ paddr=%d, first 0x80 bytes:\n%s", label, paddr, hex.Dump(buf[:0x80]))
	}
	for _, p := range candidates {
		buf := make([]byte, blockSize)
		f.ReadAt(buf, apfsPartByteOff+int64(p)*blockSize)
		dec, err := apfsfde.DecryptVolumeBlock(buf, vek, p)
		if err != nil {
			continue
		}
		if string(dec[0x20:0x24]) == "APSB" {
			t.Logf("FOUND APSB at paddr=%d", p)
			t.Logf("apfs_fs_flags  (+0x108): 0x%x", binary.LittleEndian.Uint64(dec[0x108:0x110]))
			t.Logf("apfs_features (+0x28): 0x%x", binary.LittleEndian.Uint64(dec[0x28:0x30]))
			t.Logf("apfs_incompat (+0x38): 0x%x", binary.LittleEndian.Uint64(dec[0x38:0x40]))
			t.Logf("apfs_meta_crypto (+0x60..+0x74):\n%s", hex.Dump(dec[0x60:0x74]))
			t.Logf("vol_uuid       (+0xF0): %x", dec[0xF0:0x100])
			t.Logf("apfs_root_tree_type (+0x74): 0x%x", binary.LittleEndian.Uint32(dec[0x74:0x78]))
			t.Logf("apfs_root_tree_oid  (+0x88): %d", binary.LittleEndian.Uint64(dec[0x88:0x90]))
			t.Logf("first 0x100 bytes of decrypted APSB:\n%s", hex.Dump(dec[:0x100]))
			t.Logf("APSB bytes 0x100..0x200:\n%s", hex.Dump(dec[0x100:0x200]))
			t.Logf("APSB bytes 0x400..0x4A0:\n%s", hex.Dump(dec[0x400:0x4A0]))
			break
		}
	}
	_ = bytes.Equal // silence unused import if we skip the loop
}
