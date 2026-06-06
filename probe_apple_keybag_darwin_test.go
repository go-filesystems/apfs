//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	apfsfde "github.com/go-fde/apfs"
	"golang.org/x/crypto/xts"
)

// TestProbe_AppleEncryptedKeybag captures the byte-level recipe Apple's
// apfs.kext / fsck_apfs use for an encrypted (FileVault) container's
// keybag. This is the source-of-truth for F-2 (our writer producing an
// hdiutil-mountable encrypted container).
//
// It cannot run unattended because `diskutil apfs encryptVolume`
// requires sudo + an interactive password prompt. The test is therefore
// gated on a pre-prepared reference DMG at the well-known path
// /tmp/appleref/ref.dmg, which the operator builds via the manual
// procedure documented in COMPAT_MANUAL.sh:
//
//   hdiutil create -size 16m -fs APFS -volname EncProbe \
//       /tmp/appleref/ref.dmg
//   hdiutil attach /tmp/appleref/ref.dmg
//   sudo diskutil apfs encryptVolume /Volumes/EncProbe \
//       -user disk -passphrase apfsfde-probe-password
//   # wait for "FileVault: Yes (Unlocked)" in `diskutil apfs list`
//   hdiutil detach /Volumes/EncProbe -force
//
// When that file is present the test reads it without writing anything,
// dumps the NX SB + keylocker, and verifies the keybag decrypts to a
// well-formed apfs_kb_locker (object type "syek" / 0x6b657973).
//
// What the recipe is (validated against Apple's macOS 14+ apfs.kext on
// 2026-05-09):
//
//   • nx_keylocker is at NX SB offset 1296 (struct apfs_prange =
//     uint64 paddr + uint64 block_count). NOT at offset 64-72 (which is
//     nx_incompatible_features).
//   • nx_flags has bit 0x4 (NX_CRYPTO_SW) set on encrypted containers.
//   • nx_incompatible_features is 0x2 (VERSION2), NOT 0x1 (VERSION1).
//   • The container keybag block carries a real 32-byte obj_phys
//     header, then 16-byte apfs_kb_locker (version=2, nkeys, nbytes,
//     8-byte padding), then entries.
//   • obj_phys.type at offset +24 is 0x6b657973 ("syek" little-endian =
//     APFS_OBJECT_TYPE_MEDIA_KEYBAG).
//   • The container keybag is AES-XTS-128 encrypted at rest. Key =
//     container UUID concatenated with itself (16+16 = 32 bytes). The
//     XTS sector size is 512 bytes (NOT the 4096-byte block size); each
//     4096-byte block is decrypted as 8 sub-sectors with tweak
//     = paddr*8 + sector_index_within_block.
//   • Keybag entries are aligned to 16 bytes (NOT 8 — apfs-fuse's
//     next_entry rounds up size to 0x10). The 24-byte header
//     (uuid + tag + keylen + 4-byte pad) plus keylen bytes of data is
//     followed by zero-pad up to the next 16-byte boundary.
//   • Container keybag for a freshly-encrypted volume contains exactly
//     two entries, both keyed on the *volume* UUID:
//       tag=3 (KB_TAG_VOLUME_UNLOCK_RECORDS), keylen=16,
//             data = apfs_prange{paddr=volume_kb, block_count=1}
//       tag=2 (KB_TAG_VOLUME_KEY), keylen=124, data = wrapped VEK blob
//   • The volume keybag (referenced via tag=3 above) is encrypted with
//     the VEK (which we don't have here — proving that decryption is
//     end-to-end correct).
func TestProbe_AppleEncryptedKeybag(t *testing.T) {
	const refPath = "/tmp/appleref/ref.dmg"
	const apfsPartByteOff = 20480 // LBA 40 — Apple_APFS partition start
	const blockSize = 4096

	if _, err := os.Stat(refPath); err != nil {
		t.Skipf("F-2 probe needs Apple-encrypted reference DMG at %s "+
			"(see COMPAT_MANUAL.sh — `diskutil apfs encryptVolume` "+
			"requires sudo + interactive passphrase): %v", refPath, err)
	}

	f, err := os.Open(refPath)
	if err != nil {
		t.Fatalf("open ref dmg: %v", err)
	}
	defer f.Close()

	nx := make([]byte, blockSize)
	if _, err := f.ReadAt(nx, apfsPartByteOff); err != nil {
		t.Fatalf("read NX SB: %v", err)
	}
	if string(nx[32:36]) != "NXSB" {
		t.Fatalf("NX magic missing at byte %d: %x", apfsPartByteOff, nx[32:36])
	}

	uuid := nx[72:88]
	flags := binary.LittleEndian.Uint64(nx[1264:1272])
	incompat := binary.LittleEndian.Uint64(nx[64:72])
	klPaddr := binary.LittleEndian.Uint64(nx[1296:1304])
	klBlocks := binary.LittleEndian.Uint64(nx[1304:1312])
	t.Logf("nx_uuid=%x", uuid)
	t.Logf("nx_flags=0x%x  (expect bit 0x4 NX_CRYPTO_SW set)", flags)
	t.Logf("nx_incompat=0x%x  (expect 0x2 VERSION2)", incompat)
	t.Logf("nx_keylocker.paddr=%d  block_count=%d", klPaddr, klBlocks)

	if flags&0x4 == 0 {
		t.Fatalf("expected NX_CRYPTO_SW (0x4) in nx_flags; got 0x%x", flags)
	}
	if klPaddr == 0 || klBlocks == 0 {
		t.Fatal("nx_keylocker is empty — container is not encrypted")
	}

	klSize := int(klBlocks) * blockSize
	klCipher := make([]byte, klSize)
	if _, err := f.ReadAt(klCipher, apfsPartByteOff+int64(klPaddr)*blockSize); err != nil {
		t.Fatalf("read keylocker: %v", err)
	}

	// Decrypt: AES-XTS-128, key = uuid||uuid, sector = 512, base unit = paddr*8.
	c, err := xts.NewCipher(aes.NewCipher, append(append([]byte{}, uuid...), uuid...))
	if err != nil {
		t.Fatalf("xts.NewCipher: %v", err)
	}
	const xtsSector = 512
	klPlain := make([]byte, klSize)
	for off := 0; off < klSize; off += xtsSector {
		c.Decrypt(klPlain[off:off+xtsSector], klCipher[off:off+xtsSector],
			klPaddr*8+uint64(off/xtsSector))
	}

	// Cross-check: the public go-fde/apfs.DecryptContainerKeybag helper
	// must produce byte-identical plaintext from the same ciphertext. If
	// these diverge the helper has drifted from the on-the-wire recipe
	// and any future FormatContainerEncrypted writer using it will emit
	// containers Apple cannot mount.
	var uuidArr [16]byte
	copy(uuidArr[:], uuid)
	helperPlain, err := apfsfde.DecryptContainerKeybag(klCipher, uuidArr, klPaddr)
	if err != nil {
		t.Fatalf("apfsfde.DecryptContainerKeybag: %v", err)
	}
	if !bytes.Equal(helperPlain, klPlain) {
		t.Fatalf("apfsfde.DecryptContainerKeybag disagrees with inline xts probe (helper drifted from recipe)\nfirst 64 inline:\n%s\nfirst 64 helper:\n%s",
			hex.Dump(klPlain[:64]), hex.Dump(helperPlain[:64]))
	}

	// Validate obj_phys + apfs_kb_locker shape.
	objType := binary.LittleEndian.Uint32(klPlain[24:28])
	if objType != 0x6b657973 {
		t.Fatalf("obj_phys.type at +24: got 0x%x want 0x6b657973 (\"syek\")\n%s",
			objType, hex.Dump(klPlain[:64]))
	}
	ver := binary.LittleEndian.Uint16(klPlain[32:34])
	nkeys := binary.LittleEndian.Uint16(klPlain[34:36])
	nbytes := binary.LittleEndian.Uint32(klPlain[36:40])
	t.Logf("apfs_kb_locker: version=%d nkeys=%d nbytes=%d", ver, nkeys, nbytes)
	if ver != 2 {
		t.Errorf("kb_locker version %d != 2", ver)
	}
	if nkeys < 1 || nkeys > 8 {
		t.Errorf("kb_locker nkeys=%d not in [1, 8]", nkeys)
	}

	// Walk and log each entry so future regressions diff cleanly.
	off := 48
	for i := 0; i < int(nkeys); i++ {
		if off+24 > len(klPlain) {
			t.Fatalf("entry %d truncated", i)
		}
		eUUID := klPlain[off : off+16]
		tag := binary.LittleEndian.Uint16(klPlain[off+16 : off+18])
		keylen := binary.LittleEndian.Uint16(klPlain[off+18 : off+20])
		dataEnd := off + 24 + int(keylen)
		if dataEnd > len(klPlain) {
			t.Fatalf("entry %d data truncated", i)
		}
		t.Logf("entry[%d] uuid=%x tag=%d keylen=%d", i, eUUID, tag, keylen)
		entryData := klPlain[off+24 : dataEnd]
		t.Logf("  data:\n%s", hex.Dump(entryData))
		// tag=2 (KB_TAG_VOLUME_KEY) carries an ASN.1 DER-encoded blob,
		// not a raw AES-KW(KEK, VEK). Dump its structured shape so we
		// know what to build in FormatContainerEncrypted.
		if tag == 2 && len(entryData) > 0 && entryData[0] == 0x30 {
			t.Logf("  ASN.1 decode of tag=%d:", tag)
			dumpDER(t, entryData, "    ")
		}
		// Entries are 16-byte aligned (apfs-fuse next_entry: (size+15)&~15).
		next := dataEnd
		if next%16 != 0 {
			next += 16 - (next % 16)
		}
		off = next
	}
}

// dumpDER recursively pretty-prints a DER-encoded blob so we can see
// the structure of Apple's tag=2 (volume-key) keybag entry payload.
// This is intentionally a small ad-hoc decoder — we just want a
// human-readable view to drive reverse-engineering, not a production
// ASN.1 parser.
func dumpDER(t *testing.T, b []byte, indent string) {
	t.Helper()
	for off := 0; off < len(b); {
		if off+2 > len(b) {
			t.Logf("%struncated tag at +%d", indent, off)
			return
		}
		tag := b[off]
		ln := int(b[off+1])
		off += 2
		// Constructed (bit 5 set): recurse.
		constructed := tag&0x20 != 0
		// Class: 00=universal, 01=application, 10=context, 11=private.
		classNames := []string{"univ", "app", "ctx", "priv"}
		class := classNames[tag>>6]
		num := tag & 0x1F
		hdr := fmt.Sprintf("%s[%s%d] len=%d", indent, class, num, ln)
		if off+ln > len(b) {
			t.Logf("%s — truncated (have %d)", hdr, len(b)-off)
			return
		}
		if constructed {
			t.Logf("%s {", hdr)
			dumpDER(t, b[off:off+ln], indent+"  ")
			t.Logf("%s}", indent)
		} else {
			// Tiny values get inlined; longer ones are hex-dumped.
			if ln <= 16 {
				t.Logf("%s = %x", hdr, b[off:off+ln])
			} else {
				t.Logf("%s =\n%s", hdr,
					strings.TrimRight(indent+"  "+
						strings.ReplaceAll(hex.Dump(b[off:off+ln]), "\n", "\n"+indent+"  "),
						"\n  "+indent))
			}
		}
		off += ln
	}
}

// findAppleAPFSPartByteOffset would normally come from a GPT parser, but
// for this probe we hard-code 20480 (LBA 40), which is what hdiutil
// produces for `-fs APFS` images. The helper below just lets us assert
// the assumption holds for any reference DMG we drop in.
//
//nolint:unused // diagnostic helper for the manual probe
func assertHdiutilAPFSPartOffset(t *testing.T, dmg string, want int64) {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		dmg).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	containerDev := parseHdiutilAttachContainer(t, out)
	defer exec.Command("hdiutil", "detach", "-force", containerDev).Run()
	info, err := exec.Command("diskutil", "info", containerDev+"s1").CombinedOutput()
	if err != nil {
		t.Fatalf("diskutil info: %v\n%s", err, info)
	}
	for _, line := range strings.Split(string(info), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "Partition Offset:") {
			continue
		}
		var got int64
		fmt.Sscanf(strings.TrimSpace(line), "Partition Offset: %d", &got)
		if got != want {
			t.Fatalf("partition offset = %d, want %d (in %s)", got, want, filepath.Base(dmg))
		}
	}
}
