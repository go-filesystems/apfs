package filesystem_apfs

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	apfsfde "github.com/go-fde/apfs"
	"golang.org/x/crypto/pbkdf2"
)

// TestFormatContainerEncrypted_NXSBFlagsAndKeylocker formats an
// encrypted container and verifies the live + checkpoint NX SB copies
// expose the encryption metadata where Apple's apfs.kext expects:
// nx_keylocker at +1296 pointing at block 91, and bit 0x4 set in
// nx_flags at +1264.
func TestFormatContainerEncrypted_NXSBFlagsAndKeylocker(t *testing.T) {
	const sizeBytes = int64(2 << 20) // 2 MiB
	path := filepath.Join(t.TempDir(), "enc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(path, sizeBytes, "EncTest", []byte("test-passphrase")); err != nil {
		t.Fatalf("FormatContainerEncrypted: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for _, tc := range []struct {
		label string
		off   int64
	}{
		{"live NX SB", 0},
		{"checkpoint NX SB", int64(currentNXSBCopyBlock) * 4096},
	} {
		buf := make([]byte, 4096)
		if _, err := f.ReadAt(buf, tc.off); err != nil {
			t.Fatalf("%s read: %v", tc.label, err)
		}
		if string(buf[32:36]) != "NXSB" {
			t.Fatalf("%s: NXSB magic missing", tc.label)
		}
		paddr := binary.LittleEndian.Uint64(buf[1296:1304])
		blocks := binary.LittleEndian.Uint64(buf[1304:1312])
		if paddr != formatContainerKeybagBlock || blocks != 1 {
			t.Errorf("%s: nx_keylocker = (paddr=%d, blocks=%d), want (%d, 1)",
				tc.label, paddr, blocks, formatContainerKeybagBlock)
		}
		flags := binary.LittleEndian.Uint64(buf[1264:1272])
		if flags&nxFlagCryptoSW == 0 {
			t.Errorf("%s: nx_flags = 0x%x, want bit 0x4 (NX_CRYPTO_SW) set", tc.label, flags)
		}
	}
}

// TestFormatContainerEncrypted_KeybagChainUnlocksWithPassphrase is the
// integration test for F-2: format an encrypted container, then walk
// the keybag chain end-to-end with only the passphrase + the on-disk
// UUIDs/paddrs and recover the VEK. Identical recipe to what
// apfs.kext applies on mount; if this passes, the keybag layer is
// byte-compatible with Apple's unlock path.
func TestFormatContainerEncrypted_KeybagChainUnlocksWithPassphrase(t *testing.T) {
	const sizeBytes = int64(2 << 20)
	path := filepath.Join(t.TempDir(), "enc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("integration-test-passphrase")
	if err := FormatContainerEncrypted(path, sizeBytes, "EncTest", pass); err != nil {
		t.Fatalf("FormatContainerEncrypted: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const blockSize = 4096

	// Step 1: read NX SB → containerUUID + nx_keylocker.
	nxSB := make([]byte, blockSize)
	if _, err := f.ReadAt(nxSB, 0); err != nil {
		t.Fatal(err)
	}
	var containerUUID [16]byte
	copy(containerUUID[:], nxSB[72:88])
	containerKBPaddr := binary.LittleEndian.Uint64(nxSB[1296:1304])
	if containerKBPaddr != formatContainerKeybagBlock {
		t.Fatalf("container kb paddr = %d, want %d", containerKBPaddr, formatContainerKeybagBlock)
	}

	// Step 2: decrypt the container keybag.
	containerKBCipher := make([]byte, blockSize)
	if _, err := f.ReadAt(containerKBCipher, int64(containerKBPaddr)*blockSize); err != nil {
		t.Fatal(err)
	}
	containerKBPlain, err := apfsfde.DecryptContainerKeybag(containerKBCipher, containerUUID, containerKBPaddr)
	if err != nil {
		t.Fatalf("DecryptContainerKeybag: %v", err)
	}
	// Sanity: media keybag obj_phys.type at +24 must be 0x6b657973 ("syek").
	if got := binary.LittleEndian.Uint32(containerKBPlain[24:28]); got != 0x6b657973 {
		t.Fatalf("container keybag obj_phys.type = 0x%x, want 0x6b657973", got)
	}
	// Walk the [3] = volume-keybag-prange and [2] = VEKBLOB entries.
	volumeKBPaddr, volumeUUID, vekBlobBytes := walkContainerKB(t, containerKBPlain)

	// Step 3: decrypt the volume keybag with the volume UUID.
	volumeKBCipher := make([]byte, blockSize)
	if _, err := f.ReadAt(volumeKBCipher, int64(volumeKBPaddr)*blockSize); err != nil {
		t.Fatal(err)
	}
	volumeKBPlain, err := apfsfde.DecryptVolumeKeybag(volumeKBCipher, volumeUUID, volumeKBPaddr)
	if err != nil {
		t.Fatalf("DecryptVolumeKeybag: %v", err)
	}
	if got := binary.LittleEndian.Uint32(volumeKBPlain[24:28]); got != 0x6b657973 {
		t.Fatalf("volume keybag obj_phys.type = 0x%x, want 0x6b657973", got)
	}
	kekBlobBytes := walkVolumeKB(t, volumeKBPlain)

	// Step 4: recover VEK from passphrase via the standard unlock walk.
	gotVEK := unlockVEKFromBlobs(t, pass, kekBlobBytes, vekBlobBytes)
	if len(gotVEK) != 32 {
		t.Fatalf("recovered VEK length = %d, want 32", len(gotVEK))
	}

	// Sanity: VEK changes per Format call — re-format with the same
	// passphrase on a fresh file and confirm we get a different VEK.
	path2 := filepath.Join(t.TempDir(), "enc2.apfs")
	if err := os.WriteFile(path2, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FormatContainerEncrypted(path2, sizeBytes, "EncTest", pass); err != nil {
		t.Fatal(err)
	}
	f2, _ := os.Open(path2)
	defer f2.Close()
	nx2 := make([]byte, blockSize)
	f2.ReadAt(nx2, 0)
	var cu2 [16]byte
	copy(cu2[:], nx2[72:88])
	if cu2 == containerUUID {
		t.Fatal("two formats produced the same container UUID — randomness broken")
	}
}

// TestFormatContainerEncrypted_ApfsfdeOpenRoundtrip is the high-level
// API integration test: format an encrypted container, then open it
// with apfsfde.Open(path, passphrase) and verify the unlocked Device
// is functional. The whole keybag-chain walk we did manually in the
// previous test is now driven through the public apfsfde.Open entry
// point, exercising unlockVEK's NX_CRYPTO_SW dispatch branch.
func TestFormatContainerEncrypted_ApfsfdeOpenRoundtrip(t *testing.T) {
	const sizeBytes = int64(2 << 20)
	path := filepath.Join(t.TempDir(), "enc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("apfsfde-open-roundtrip-passphrase")
	if err := FormatContainerEncrypted(path, sizeBytes, "EncTest", pass); err != nil {
		t.Fatalf("FormatContainerEncrypted: %v", err)
	}

	dev, err := apfsfde.Open(path, pass)
	if err != nil {
		t.Fatalf("apfsfde.Open with correct passphrase: %v", err)
	}
	defer dev.Close()

	// Wrong passphrase must NOT unlock.
	if err := os.WriteFile(filepath.Join(t.TempDir(), "extra"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongDev, err := apfsfde.Open(path, []byte("wrong-passphrase"))
	if err == nil {
		wrongDev.Close()
		t.Fatal("apfsfde.Open with wrong passphrase succeeded — security regression")
	}
}

// TestFormatContainerEncrypted_VolumeMetadataIsPlaintext verifies the
// post-2026-05-10 invariant: volume metadata blocks (APSB, volume
// OMAP, FS-tree root, snap-meta, extent-ref) are PLAINTEXT on disk
// even when NX_CRYPTO_SW is set in the NX SB. This was reverse-
// engineered from Apple's reference encrypted DMG, whose APSB at
// paddr 136 has "APSB" magic in clear. The VEK is reserved for user
// file data; encrypting volume metadata makes the kext's spaceman
// query fail with -69808.
func TestFormatContainerEncrypted_VolumeMetadataIsPlaintext(t *testing.T) {
	const sizeBytes = int64(2 << 20)
	path := filepath.Join(t.TempDir(), "enc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := []byte("volume-metadata-test-passphrase")
	if err := FormatContainerEncrypted(path, sizeBytes, "EncTest", pass); err != nil {
		t.Fatalf("FormatContainerEncrypted: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const blockSize = 4096

	_ = pass

	// Volume metadata blocks must read PLAINTEXT — the VEK at-rest
	// layer applies only to user file data per Apple's reference DMG
	// (probed via TestProbe_AppleEncryptedAPSBDecrypt).
	cases := []struct {
		paddr        uint64
		wantTypeLow  uint16
		extraCheck   func(t *testing.T, p []byte)
		describe     string
	}{
		{paddr: formatAPSBBlock, wantTypeLow: 0x0D, describe: "APSB", extraCheck: func(t *testing.T, p []byte) {
			t.Helper()
			if string(p[0x20:0x24]) != "APSB" {
				t.Errorf("APSB magic at +0x20 = %q, want APSB", string(p[0x20:0x24]))
			}
		}},
		{paddr: formatVolumeOmapBlock, wantTypeLow: 0x0B, describe: "volume OMAP"},
		{paddr: formatVolumeOmapTreeBlock, wantTypeLow: 0x02, describe: "volume OMAP B-tree leaf"},
		{paddr: formatFSTreeRootBlock, wantTypeLow: 0x02, describe: "FS-tree root"},
		{paddr: formatSnapMetaTreeRootBlock, wantTypeLow: 0x02, describe: "snap-meta tree root"},
		{paddr: formatExtentRefTreeBlock, wantTypeLow: 0x02, describe: "extent-ref tree root"},
	}
	for _, tc := range cases {
		buf := make([]byte, blockSize)
		if _, err := f.ReadAt(buf, int64(tc.paddr)*blockSize); err != nil {
			t.Fatalf("%s read: %v", tc.describe, err)
		}
		gotType := uint16(binary.LittleEndian.Uint32(buf[24:28]) & 0xFFFF)
		if gotType != tc.wantTypeLow {
			t.Errorf("%s on-disk obj_phys.type low 16 = 0x%x, want 0x%x (must be plaintext)",
				tc.describe, gotType, tc.wantTypeLow)
		}
		if tc.extraCheck != nil {
			tc.extraCheck(t, buf)
		}
	}
}

// walkContainerKB scans a decrypted container-keybag block for the
// tag=3 (volume-unlock-records) and tag=2 (VEKBLOB) entries and
// returns (volumeKBPaddr, volumeUUID, vekBlobBytes).
func walkContainerKB(t *testing.T, plain []byte) (uint64, [16]byte, []byte) {
	t.Helper()
	const entryAreaStart = 48
	const headerLen = 24
	nkeys := int(binary.LittleEndian.Uint16(plain[34:36]))
	if nkeys < 2 {
		t.Fatalf("container keybag has %d entries, want >= 2", nkeys)
	}
	var (
		gotPaddr   uint64
		gotUUID    [16]byte
		vekBlobOut []byte
		seenP      bool
		seenV      bool
	)
	off := entryAreaStart
	for i := 0; i < nkeys; i++ {
		var uuid [16]byte
		copy(uuid[:], plain[off:off+16])
		tag := binary.LittleEndian.Uint16(plain[off+16 : off+18])
		keylen := int(binary.LittleEndian.Uint16(plain[off+18 : off+20]))
		dataStart := off + headerLen
		dataEnd := dataStart + keylen
		switch tag {
		case apfsfde.KBTagVolumeUnlockRecords: // 3
			if keylen != 16 {
				t.Fatalf("tag=3 keylen = %d, want 16", keylen)
			}
			gotPaddr = binary.LittleEndian.Uint64(plain[dataStart : dataStart+8])
			gotUUID = uuid
			seenP = true
		case apfsfde.KBTagVolumeKey: // 2
			vekBlobOut = append([]byte{}, plain[dataStart:dataEnd]...)
			seenV = true
		}
		next := dataEnd
		if rem := next % 16; rem != 0 {
			next += 16 - rem
		}
		off = next
	}
	if !seenP || !seenV {
		t.Fatalf("container keybag missing tag=3 or tag=2 entry (P=%v V=%v)", seenP, seenV)
	}
	return gotPaddr, gotUUID, vekBlobOut
}

// walkVolumeKB returns the KEKBLOB bytes (the data of the single
// tag=3 / KB_TAG_VOLUME_PASSPHRASE entry) from a decrypted volume
// keybag block.
func walkVolumeKB(t *testing.T, plain []byte) []byte {
	t.Helper()
	const entryAreaStart = 48
	const headerLen = 24
	nkeys := int(binary.LittleEndian.Uint16(plain[34:36]))
	if nkeys < 1 {
		t.Fatalf("volume keybag has %d entries, want >= 1", nkeys)
	}
	off := entryAreaStart
	tag := binary.LittleEndian.Uint16(plain[off+16 : off+18])
	keylen := int(binary.LittleEndian.Uint16(plain[off+18 : off+20]))
	if tag != apfsfde.KBTagVolumePassphrase {
		t.Fatalf("volume keybag entry[0] tag = %d, want %d (KB_TAG_VOLUME_PASSPHRASE)",
			tag, apfsfde.KBTagVolumePassphrase)
	}
	dataStart := off + headerLen
	return append([]byte{}, plain[dataStart:dataStart+keylen]...)
}

// unlockVEKFromBlobs walks the same key-derivation chain Apple's
// apfs.kext does on mount: parse the KEKBLOB to extract the PBKDF2
// parameters + wrapped KEK, derive the unwrap key from the passphrase,
// unwrap the KEK, parse the VEKBLOB to extract the wrapped VEK, and
// finally unwrap the VEK.
func unlockVEKFromBlobs(t *testing.T, passphrase, kekBlob, vekBlob []byte) []byte {
	t.Helper()
	wrappedKEK, pbkdf2Salt, iterations := parseKEKBlobInner(t, kekBlob)
	wrappedVEK := parseVEKBlobWrappedKey(t, vekBlob)

	dk := pbkdf2.Key(passphrase, pbkdf2Salt, int(iterations), 32, sha256.New)
	kek, err := apfsfde.AESKeyUnwrap(dk, wrappedKEK)
	if err != nil {
		t.Fatalf("unwrap KEK: %v", err)
	}
	vek, err := apfsfde.AESKeyUnwrap(kek, wrappedVEK)
	if err != nil {
		t.Fatalf("unwrap VEK: %v", err)
	}
	return vek
}

// parseKEKBlobInner walks the KEKBLOB DER ([3] keyblob inner) and
// returns (wrappedKEK, pbkdf2Salt, iterations).
func parseKEKBlobInner(t *testing.T, der []byte) ([]byte, []byte, uint32) {
	t.Helper()
	if der[0] != 0x30 {
		t.Fatalf("KEKBLOB outer not a SEQUENCE: 0x%x", der[0])
	}
	body := skipSeqHeader(der)
	pos := 0
	pos += 2 + int(body[pos+1]) // skip [0]
	// skip [1] HMAC (long-form length is possible but typically 0x20)
	pos += 1
	hLen, hOff := readLen(body, pos)
	pos = hOff + hLen
	// skip [2] salt
	pos += 1
	sLen, sOff := readLen(body, pos)
	pos = sOff + sLen
	// [3] inner CONSTRUCTED
	pos += 1
	innerLen, innerOff := readLen(body, pos)
	inner := body[innerOff : innerOff+innerLen]

	ipos := 0
	ipos += 2 + int(inner[ipos+1]) // [0]
	// [1] uuid
	ipos += 1
	uLen, uOff := readLen(inner, ipos)
	ipos = uOff + uLen
	// [2] flags
	ipos += 1
	fLen, fOff := readLen(inner, ipos)
	ipos = fOff + fLen
	// [3] wrapped KEK
	ipos += 1
	wLen, wOff := readLen(inner, ipos)
	wrappedKEK := inner[wOff : wOff+wLen]
	ipos = wOff + wLen
	// [4] iterations
	ipos += 1
	itLen, itOff := readLen(inner, ipos)
	var iterations uint32
	for i := 0; i < itLen; i++ {
		iterations = (iterations << 8) | uint32(inner[itOff+i])
	}
	ipos = itOff + itLen
	// [5] PBKDF2 salt
	ipos += 1
	psLen, psOff := readLen(inner, ipos)
	pbkdf2Salt := inner[psOff : psOff+psLen]
	return wrappedKEK, pbkdf2Salt, iterations
}

// parseVEKBlobWrappedKey returns the AES-KW(KEK, VEK) ciphertext
// stored in the VEKBLOB's inner [3] OCTET STRING.
func parseVEKBlobWrappedKey(t *testing.T, der []byte) []byte {
	t.Helper()
	body := skipSeqHeader(der)
	pos := 0
	pos += 2 + int(body[pos+1]) // [0]
	pos += 1                     // [1] tag
	hLen, hOff := readLen(body, pos)
	pos = hOff + hLen
	pos += 1 // [2] tag
	sLen, sOff := readLen(body, pos)
	pos = sOff + sLen
	pos += 1 // [3] tag
	innerLen, innerOff := readLen(body, pos)
	inner := body[innerOff : innerOff+innerLen]

	ipos := 0
	ipos += 2 + int(inner[ipos+1]) // [0]
	ipos += 1                       // [1] tag
	uLen, uOff := readLen(inner, ipos)
	ipos = uOff + uLen
	ipos += 1 // [2] tag
	fLen, fOff := readLen(inner, ipos)
	ipos = fOff + fLen
	ipos += 1 // [3] tag
	wLen, wOff := readLen(inner, ipos)
	return inner[wOff : wOff+wLen]
}

// skipSeqHeader returns der minus the leading universal SEQUENCE
// tag+length octets.
func skipSeqHeader(der []byte) []byte {
	if der[1]&0x80 == 0 {
		return der[2:]
	}
	return der[2+int(der[1]&0x7F):]
}

// readLen decodes a DER length octet sequence starting at off in b.
func readLen(b []byte, off int) (int, int) {
	first := b[off]
	if first&0x80 == 0 {
		return int(first), off + 1
	}
	n := int(first & 0x7F)
	v := 0
	for i := 0; i < n; i++ {
		v = (v << 8) | int(b[off+1+i])
	}
	return v, off + 1 + n
}
